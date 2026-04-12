"""
common.py — Shared Protocol Logic
===================================
Contains everything that host.py and client.py share:
  • Length-prefixed socket framing
  • Chat loop (send + receive threads)
  • Command dispatcher  (/exit /history /sendfile /help)
  • JSON message envelope construction & parsing

JSON wire envelope:
  {
    "type":      "message" | "file" | "file_done" | "system",
    "data":      "<base64 Fernet token>",   # for type==message
    "timestamp": "HH:MM:SS"
    ... (file-specific fields for type==file / file_done)
  }
"""

import json
import os
import struct
import sys
import threading
import base64
from datetime import datetime

import crypto
import history
import file_transfer

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
MAGENTA= "\033[95m"
RESET  = "\033[0m"

HELP_TEXT = f"""
{BOLD}Available commands:{RESET}
  {CYAN}/help{RESET}              Show this help
  {CYAN}/sendfile <path>{RESET}   Send a file to your peer
  {CYAN}/history{RESET}           Show local chat history
  {CYAN}/exit{RESET}              Close the connection and quit
  {DIM}  (anything else is sent as a chat message){RESET}
"""


# ── Low-level framing ─────────────────────────────────────────────────────────
# 4-byte big-endian length prefix ensures complete message delivery
# regardless of TCP segmentation.

def send_frame(sock, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock) -> bytes:
    """Block until a complete framed message arrives. Returns b'' on close."""
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            return b""
        hdr += chunk
    n = struct.unpack(">I", hdr)[0]
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# ── Message envelope helpers ──────────────────────────────────────────────────

def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def build_message_frame(aes_key: bytes, text: str) -> bytes:
    """
    Encrypt `text` and wrap it in a JSON envelope.

    Wire format:
      { "type": "message", "data": "<b64 fernet token>", "timestamp": "HH:MM:SS" }
    """
    token  = crypto.aes_encrypt(aes_key, text)
    b64    = base64.b64encode(token).decode("ascii")
    return json.dumps({"type": "message", "data": b64, "timestamp": _ts()}).encode()


def parse_frame(aes_key: bytes, raw: bytes) -> dict | None:
    """
    Decode a raw frame.
    For type=="message", adds a "plaintext" key with the decrypted content.
    Returns None if the frame cannot be parsed.
    """
    try:
        env = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if env.get("type") == "message":
        try:
            token = base64.b64decode(env["data"].encode("ascii"))
            env["plaintext"] = crypto.aes_decrypt(aes_key, token)
        except Exception as e:
            env["plaintext"] = f"[decryption error: {e}]"

    return env


# ── Key-exchange helpers ──────────────────────────────────────────────────────

def key_exchange_host(conn) -> tuple:
    """
    Host side of the RSA+AES handshake.

      Host  → Client : RSA public key (PEM)
      Client→ Host   : RSA public key (PEM)
      Host  → Client : AES key encrypted with Client's RSA public key

    Returns (private_key, aes_key).
    """
    priv, pub = crypto.generate_rsa_keypair()
    print(f"{DIM}[*] RSA-2048 key pair generated.{RESET}")

    send_frame(conn, crypto.serialize_public_key(pub))
    print(f"{DIM}[*] Sent our public key.{RESET}")

    peer_pem = recv_frame(conn)
    if not peer_pem:
        raise ConnectionError("Peer disconnected during handshake.")
    peer_pub = crypto.deserialize_public_key(peer_pem)
    print(f"{DIM}[*] Received peer's public key.{RESET}")

    aes_key = crypto.generate_aes_key()
    send_frame(conn, crypto.rsa_encrypt(peer_pub, aes_key))
    print(f"{GREEN}[✓] AES session key sent (RSA-encrypted).{RESET}")

    return priv, aes_key


def key_exchange_client(sock) -> tuple:
    """
    Client side of the RSA+AES handshake (mirror of host).

    Returns (private_key, aes_key).
    """
    priv, pub = crypto.generate_rsa_keypair()
    print(f"{DIM}[*] RSA-2048 key pair generated.{RESET}")

    peer_pem = recv_frame(sock)
    if not peer_pem:
        raise ConnectionError("Host disconnected during handshake.")
    peer_pub = crypto.deserialize_public_key(peer_pem)   # noqa: F841 (not needed by client)
    print(f"{DIM}[*] Received host's public key.{RESET}")

    send_frame(sock, crypto.serialize_public_key(pub))
    print(f"{DIM}[*] Sent our public key.{RESET}")

    enc_aes = recv_frame(sock)
    if not enc_aes:
        raise ConnectionError("Host disconnected before sending AES key.")
    aes_key = crypto.rsa_decrypt(priv, enc_aes)
    print(f"{GREEN}[✓] AES session key received and decrypted.{RESET}")

    return priv, aes_key


# ── Chat engine ───────────────────────────────────────────────────────────────

_stop = threading.Event()


def receive_loop(sock, aes_key: bytes) -> None:
    """
    Background thread: receive frames from peer, dispatch by type.
    Handles chat messages and incoming file transfers.
    """
    # Expose a file-transfer receive hook that can read more frames
    file_transfer._recv_frame = recv_frame   # share the same framing function

    while not _stop.is_set():
        try:
            raw = recv_frame(sock)
            if not raw:
                if not _stop.is_set():
                    print(f"\n{YELLOW}[!] Peer disconnected.{RESET}")
                    _stop.set()
                break

            env = parse_frame(aes_key, raw)
            if env is None:
                continue

            t = env.get("type")

            if t == "message":
                ts   = env.get("timestamp", _ts())
                text = env.get("plaintext", "")
                print(f"\r{CYAN}{BOLD}[{ts}] Friend:{RESET} {text}")
                print(f"{DIM}[{_ts()}] You:{RESET} ", end="", flush=True)
                history.log_message("friend", text)

            elif t == "file":
                # First chunk already parsed — hand off to file_transfer
                # which will read remaining chunks directly from the socket
                file_transfer.receive_file(sock, aes_key, env)
                print(f"{DIM}[{_ts()}] You:{RESET} ", end="", flush=True)

            elif t == "system":
                print(f"\n{YELLOW}  [system] {env.get('data', '')}{RESET}")
                _stop.set()
                break

        except Exception as e:
            if not _stop.is_set():
                print(f"\n{RED}[!] Receive error: {e}{RESET}")
                _stop.set()
            break


def send_loop(sock, aes_key: bytes) -> None:
    """
    Main thread: read stdin, parse commands, encrypt & send.
    """
    print(f"{DIM}Type a message or command. /help for help.{RESET}\n")

    while not _stop.is_set():
        try:
            print(f"{DIM}[{_ts()}] You:{RESET} ", end="", flush=True)
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            _stop.set()
            break

        if _stop.is_set():
            break
        if not line:
            continue

        # ── Command dispatcher ──────────────────────────────────────────────

        if line.lower() == "/exit":
            print(f"{YELLOW}[*] Closing connection…{RESET}")
            # Notify peer gracefully
            try:
                send_frame(sock, json.dumps(
                    {"type": "system", "data": "Peer has left the chat."}
                ).encode())
            except Exception:
                pass
            _stop.set()
            break

        elif line.lower() == "/history":
            history.show_history()
            continue

        elif line.lower() == "/help":
            print(HELP_TEXT)
            continue

        elif line.lower().startswith("/sendfile"):
            parts = line.split(maxsplit=1)
            if len(parts) < 2 or not parts[1].strip():
                print(f"  {RED}Usage: /sendfile <path/to/file>{RESET}")
                continue
            filepath = parts[1].strip()
            file_transfer.send_file(sock, aes_key, filepath)
            continue

        elif line.startswith("/"):
            print(f"  {RED}Unknown command '{line}'. Type /help for commands.{RESET}")
            continue

        # ── Regular chat message ────────────────────────────────────────────
        try:
            frame = build_message_frame(aes_key, line)
            send_frame(sock, frame)
            history.log_message("you", line)
        except Exception as e:
            print(f"  {RED}[!] Send error: {e}{RESET}")
            _stop.set()
            break


def run_chat(sock, aes_key: bytes) -> None:
    """
    Start the bidirectional chat session.
    Blocks until either peer disconnects or /exit is typed.
    """
    _stop.clear()
    recv_thread = threading.Thread(target=receive_loop, args=(sock, aes_key), daemon=True)
    recv_thread.start()
    send_loop(sock, aes_key)
    _stop.set()
    try:
        sock.close()
    except Exception:
        pass
    recv_thread.join(timeout=2)
    print(f"{DIM}[*] Session ended. Goodbye.{RESET}")

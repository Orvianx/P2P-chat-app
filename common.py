"""
common.py — Shared Protocol Logic (Chat + File Transfer + VoIP)
================================================================
Contains everything that host.py and client.py share:

  • Length-prefixed TCP framing
  • RSA+AES key-exchange helpers
  • JSON message envelope construction & parsing
  • Chat send/receive threads
  • Command dispatcher  (/exit /history /sendfile /help /call /accept /reject /hangup)
  • VoIP call signal routing

JSON wire types
---------------
  type = "message"       → encrypted chat message
  type = "file"          → file chunk
  type = "file_done"     → file transfer sentinel
  type = "system"        → peer-disconnect notification
  type = "call_request"  → initiate voice call
  type = "call_accept"   → accept voice call
  type = "call_reject"   → reject voice call
  type = "call_end"      → hang up
"""

import base64
import json
import os
import struct
import threading
from datetime import datetime

import crypto
import history
import file_transfer
from voice import VoIPEngine

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN   = "\033[92m"
CYAN    = "\033[96m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"

# ── Call-related TCP message types ────────────────────────────────────────────
_CALL_TYPES = {"call_request", "call_accept", "call_reject", "call_end"}

HELP_TEXT = f"""
{BOLD}Available commands:{RESET}
  {CYAN}/help{RESET}              Show this help
  {CYAN}/sendfile <path>{RESET}   Send an encrypted file to your peer
  {CYAN}/history{RESET}           Show local chat history
  {CYAN}/exit{RESET}              Close the connection and quit

  {MAGENTA}/call{RESET}              Initiate a voice call
  {MAGENTA}/accept{RESET}            Accept an incoming call
  {MAGENTA}/reject{RESET}            Reject an incoming call
  {MAGENTA}/hangup{RESET}            End the current call

  {DIM}(anything else is sent as a chat message){RESET}
"""


# ── Low-level TCP framing ─────────────────────────────────────────────────────

def send_frame(sock, data: bytes) -> None:
    """Send a length-prefixed frame over a TCP socket."""
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock) -> bytes:
    """
    Block until a complete length-prefixed frame arrives.
    Returns b'' on graceful close.
    """
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
    Encrypt a chat message and wrap it in a JSON envelope.

    Wire format:
      { "type": "message", "data": "<b64 Fernet token>", "timestamp": "HH:MM:SS" }
    """
    token = crypto.aes_encrypt(aes_key, text)
    b64   = base64.b64encode(token).decode("ascii")
    return json.dumps({"type": "message", "data": b64, "timestamp": _ts()}).encode()


def parse_frame(aes_key: bytes, raw: bytes) -> dict | None:
    """
    Decode a raw TCP frame.
    For type=="message", decrypts and adds a "plaintext" key.
    Returns None on parse failure.
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


# ── RSA + AES key-exchange helpers ────────────────────────────────────────────

def key_exchange_host(conn) -> tuple:
    """
    Host side:
      Host  → Client : RSA public key (PEM)
      Client→ Host   : RSA public key (PEM)
      Host  → Client : AES key  (RSA-encrypted)

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
    Client side (mirror of host).
    Returns (private_key, aes_key).
    """
    priv, pub = crypto.generate_rsa_keypair()
    print(f"{DIM}[*] RSA-2048 key pair generated.{RESET}")

    peer_pem = recv_frame(sock)
    if not peer_pem:
        raise ConnectionError("Host disconnected during handshake.")
    crypto.deserialize_public_key(peer_pem)          # validate but not needed later
    print(f"{DIM}[*] Received host's public key.{RESET}")

    send_frame(sock, crypto.serialize_public_key(pub))
    print(f"{DIM}[*] Sent our public key.{RESET}")

    enc_aes = recv_frame(sock)
    if not enc_aes:
        raise ConnectionError("Host disconnected before sending AES key.")
    aes_key = crypto.rsa_decrypt(priv, enc_aes)
    print(f"{GREEN}[✓] AES session key received and decrypted.{RESET}")
    return priv, aes_key


# ── Chat + VoIP engine ────────────────────────────────────────────────────────

_stop  = threading.Event()
_voip  = None    # VoIPEngine instance, set in run_chat()


def receive_loop(sock, aes_key: bytes) -> None:
    """
    Background thread: receive TCP frames and dispatch by type.

    Handles:
      message        → print + history
      file           → hand off to file_transfer
      system         → peer disconnect
      call_*         → hand off to VoIPEngine
    """
    file_transfer._recv_frame = recv_frame

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

            # ── Chat message ─────────────────────────────────────────────────
            if t == "message":
                ts   = env.get("timestamp", _ts())
                text = env.get("plaintext", "")
                print(f"\r{CYAN}{BOLD}[{ts}] Friend:{RESET} {text}")
                print(f"{DIM}[{_ts()}] You:{RESET} ", end="", flush=True)
                history.log_message("friend", text)

            # ── File transfer ─────────────────────────────────────────────────
            elif t == "file":
                file_transfer.receive_file(sock, aes_key, env)
                print(f"{DIM}[{_ts()}] You:{RESET} ", end="", flush=True)

            # ── Graceful disconnect ───────────────────────────────────────────
            elif t == "system":
                print(f"\n{YELLOW}  [system] {env.get('data', '')}{RESET}")
                _stop.set()
                break

            # ── VoIP call signals ─────────────────────────────────────────────
            elif t in _CALL_TYPES:
                if _voip is not None:
                    _voip.handle_signal(env)
                else:
                    print(f"{YELLOW}  [!] Received call signal but VoIP engine not ready.{RESET}")

        except Exception as e:
            if not _stop.is_set():
                print(f"\n{RED}[!] Receive error: {e}{RESET}")
                _stop.set()
            break


def send_loop(sock, aes_key: bytes) -> None:
    """
    Main thread: read stdin, parse commands, and act.

    Commands
    --------
      /exit              close connection
      /history           show history
      /help              show help
      /sendfile <path>   send file
      /call              start voice call
      /accept            accept incoming call
      /reject            reject incoming call
      /hangup            end active call
      <anything else>    send as chat message
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

        lo = line.lower()

        # ── /exit ────────────────────────────────────────────────────────────
        if lo == "/exit":
            print(f"{YELLOW}[*] Closing connection…{RESET}")
            if _voip and not _voip.is_idle:
                _voip.cmd_hangup()
            try:
                send_frame(sock, json.dumps(
                    {"type": "system", "data": "Peer has left the chat."}
                ).encode())
            except Exception:
                pass
            _stop.set()
            break

        # ── /history ─────────────────────────────────────────────────────────
        elif lo == "/history":
            history.show_history()

        # ── /help ────────────────────────────────────────────────────────────
        elif lo == "/help":
            print(HELP_TEXT)

        # ── /sendfile ────────────────────────────────────────────────────────
        elif lo.startswith("/sendfile"):
            parts = line.split(maxsplit=1)
            if len(parts) < 2 or not parts[1].strip():
                print(f"  {RED}Usage: /sendfile <path/to/file>{RESET}")
                continue
            file_transfer.send_file(sock, aes_key, parts[1].strip())

        # ── VoIP commands ─────────────────────────────────────────────────────
        elif lo == "/call":
            if _voip:
                _voip.cmd_call()
            else:
                print(f"{RED}  [!] VoIP engine not initialised.{RESET}")

        elif lo == "/accept":
            if _voip:
                _voip.cmd_accept()
            else:
                print(f"{RED}  [!] VoIP engine not initialised.{RESET}")

        elif lo == "/reject":
            if _voip:
                _voip.cmd_reject()
            else:
                print(f"{RED}  [!] VoIP engine not initialised.{RESET}")

        elif lo == "/hangup":
            if _voip:
                _voip.cmd_hangup()
            else:
                print(f"{RED}  [!] VoIP engine not initialised.{RESET}")

        # ── Unknown command ───────────────────────────────────────────────────
        elif line.startswith("/"):
            print(f"  {RED}Unknown command '{line}'. Type /help for commands.{RESET}")

        # ── Regular chat message ──────────────────────────────────────────────
        else:
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
    Start the full-featured bidirectional chat + VoIP session.
    Blocks until either peer disconnects or /exit is typed.
    """
    global _voip, _stop

    _stop = threading.Event()
    _voip = VoIPEngine(tcp_sock=sock, aes_key=aes_key, send_frame_fn=send_frame)

    recv_thread = threading.Thread(
        target=receive_loop, args=(sock, aes_key), daemon=True, name="tcp-recv"
    )
    recv_thread.start()
    send_loop(sock, aes_key)

    _stop.set()

    # Hang up cleanly if still in a call
    if _voip and not _voip.is_idle:
        _voip._end_call(local=True)

    try:
        sock.close()
    except Exception:
        pass

    recv_thread.join(timeout=2)
    print(f"{DIM}[*] Session ended. Goodbye.{RESET}")

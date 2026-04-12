"""
client.py — P2P Secure Chat: Client (Connector) Side
=====================================================
Workflow:
  1. Connect via TCP to the host IP:port.
  2. Perform mutual RSA public-key exchange.
  3. Receive the AES session key (encrypted), decrypt it with our RSA
     private key — now both sides share the same AES key.
  4. Start two threads:
       • receive_loop — decrypt and print incoming messages
       • send_loop    — read stdin, encrypt, and transmit
  5. On disconnect or Ctrl-C, shut down cleanly.

Run:
    python client.py <HOST_IP> [--port PORT]
"""

import socket
import struct
import sys
import threading
import argparse

import crypto

# ── ANSI colour helpers ────────────────────────────────────────────────────────
GREEN  = "\033[92m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

BANNER = f"""
{BOLD}{CYAN}╔══════════════════════════════════════════╗
║   🔒  P2P Secure Chat  —  CLIENT MODE    ║
║      RSA-2048  ·  AES-Fernet  ·  TCP     ║
╚══════════════════════════════════════════╝{RESET}
"""


# ── Framed socket I/O ──────────────────────────────────────────────────────────
# Identical framing logic as host.py — must match exactly.

def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send length-prefixed bytes over a TCP socket."""
    length = struct.pack(">I", len(data))
    sock.sendall(length + data)


def recv_frame(sock: socket.socket) -> bytes:
    """
    Receive a length-prefixed message.
    Returns b"" on graceful peer close.
    """
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return b""
        header += chunk

    length = struct.unpack(">I", header)[0]

    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return b""
        payload += chunk

    return payload


# ── Key Exchange ───────────────────────────────────────────────────────────────

def perform_key_exchange_client(sock: socket.socket):
    """
    Client-side handshake (mirror of the host side):

      Host  →  Client  : Host's RSA public key  (PEM)
      Client → Host    : Client's RSA public key (PEM)
      Host  →  Client  : AES session key, encrypted with Client's RSA pub key

    The client decrypts the AES key with its own private key.

    Returns:
        (private_key, aes_key)
    """
    print(f"{DIM}[*] Generating RSA-2048 key pair…{RESET}")
    private_key, public_key = crypto.generate_rsa_keypair()

    # 1. Receive host's public key first
    host_pem = recv_frame(sock)
    if not host_pem:
        raise ConnectionError("Host disconnected before sending public key.")
    _host_public_key = crypto.deserialize_public_key(host_pem)
    print(f"{DIM}[*] Received host's RSA public key.{RESET}")

    # 2. Send our public key so the host can encrypt the AES key for us
    our_pem = crypto.serialize_public_key(public_key)
    send_frame(sock, our_pem)
    print(f"{DIM}[*] Sent our RSA public key.{RESET}")

    # 3. Receive the AES session key (RSA-encrypted) and decrypt it
    encrypted_aes = recv_frame(sock)
    if not encrypted_aes:
        raise ConnectionError("Host disconnected before sending AES key.")
    aes_key = crypto.rsa_decrypt(private_key, encrypted_aes)
    print(f"{GREEN}[✓] AES session key received and decrypted.{RESET}")

    return private_key, aes_key


# ── Chat Threads ───────────────────────────────────────────────────────────────

stop_event = threading.Event()


def receive_loop(sock: socket.socket, aes_key: bytes) -> None:
    """
    Background thread: continuously receive and decrypt messages from peer.
    """
    while not stop_event.is_set():
        try:
            token = recv_frame(sock)
            if not token:
                print(f"\n{YELLOW}[!] Peer disconnected.{RESET}")
                stop_event.set()
                break
            message = crypto.aes_decrypt(aes_key, token)
            print(f"\r{CYAN}{BOLD}Friend:{RESET} {message}\n{DIM}You:{RESET} ", end="", flush=True)
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n{RED}[!] Receive error: {e}{RESET}")
                stop_event.set()
            break


def send_loop(sock: socket.socket, aes_key: bytes) -> None:
    """
    Main thread: read user input, encrypt, and send to peer.
    """
    print(f"{DIM}Type a message and press Enter. Ctrl-C to quit.{RESET}\n")
    while not stop_event.is_set():
        try:
            print(f"{DIM}You:{RESET} ", end="", flush=True)
            message = input()
            if stop_event.is_set():
                break
            if not message.strip():
                continue
            token = crypto.aes_encrypt(aes_key, message)
            send_frame(sock, token)
        except (EOFError, KeyboardInterrupt):
            print(f"\n{YELLOW}[*] Closing chat…{RESET}")
            stop_event.set()
            break
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n{RED}[!] Send error: {e}{RESET}")
                stop_event.set()
            break


# ── Entry Point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="P2P Secure Chat — Client mode (connects to a host peer)"
    )
    parser.add_argument("host_ip", help="IP address of the host peer")
    parser.add_argument(
        "--port", type=int, default=5000,
        help="TCP port the host is listening on (default: 5000)"
    )
    args = parser.parse_args()

    print(BANNER)
    print(f"{DIM}[*] Detecting your network addresses…{RESET}")
    local_ip  = crypto.get_local_ip()
    public_ip = crypto.get_public_ip()

    print(f"\n{BOLD}{'─'*46}")
    print(f"  📡  Your Network Info")
    print(f"{'─'*46}{RESET}")
    print(f"  {BOLD}Local  IP  (LAN){RESET}  →  {YELLOW}{local_ip}{RESET}")
    print(f"  {BOLD}Public IP  (WAN){RESET}  →  {YELLOW}{public_ip}{RESET}")
    print(f"{BOLD}{'─'*46}{RESET}\n")

    print(f"{BOLD}[*] Connecting to {YELLOW}{args.host_ip}:{args.port}{RESET}{BOLD}…{RESET}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)   # 15-second connect timeout

    try:
        sock.connect((args.host_ip, args.port))
    except socket.timeout:
        print(f"{RED}[✗] Connection timed out. Check the IP, port, and firewall/port-forward settings.{RESET}")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"{RED}[✗] Connection refused. Is the host running? Is port {args.port} open?{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[✗] Could not connect: {e}{RESET}")
        sys.exit(1)

    sock.settimeout(None)   # switch to blocking mode for the chat session
    print(f"{GREEN}[✓] Connected to {args.host_ip}:{args.port}{RESET}")

    try:
        _private_key, aes_key = perform_key_exchange_client(sock)
    except Exception as e:
        print(f"{RED}[✗] Key exchange failed: {e}{RESET}")
        sock.close()
        sys.exit(1)

    print(f"\n{BOLD}{GREEN}🔐 Secure channel established. Start chatting!{RESET}\n")
    print("─" * 46)

    recv_thread = threading.Thread(target=receive_loop, args=(sock, aes_key), daemon=True)
    recv_thread.start()

    send_loop(sock, aes_key)

    stop_event.set()
    sock.close()
    recv_thread.join(timeout=2)
    print(f"{DIM}[*] Connection closed. Goodbye.{RESET}")


if __name__ == "__main__":
    main()

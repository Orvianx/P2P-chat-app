"""
host.py — P2P Secure Chat: Host (Listener) Side
=================================================
Workflow:
  1. Bind a TCP socket and wait for exactly one peer connection.
  2. Perform mutual RSA public-key exchange.
  3. Generate a fresh AES (Fernet) session key and deliver it to the
     peer, encrypted under the peer's RSA public key.
  4. Start two threads:
       • receive_loop — decrypt and print incoming messages
       • send_loop    — read stdin, encrypt, and transmit
  5. On disconnect or Ctrl-C, shut down cleanly.

Run:
    python host.py [--port PORT]
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
║   🔒  P2P Secure Chat  —  HOST MODE      ║
║      RSA-2048  ·  AES-Fernet  ·  TCP     ║
╚══════════════════════════════════════════╝{RESET}
"""


# ── Framed socket I/O ──────────────────────────────────────────────────────────
# We prefix every message with a 4-byte big-endian length so the receiver
# knows exactly how many bytes to read (avoids TCP stream fragmentation bugs).

def send_frame(sock: socket.socket, data: bytes) -> None:
    """Send length-prefixed bytes over a TCP socket."""
    length = struct.pack(">I", len(data))   # 4-byte big-endian unsigned int
    sock.sendall(length + data)


def recv_frame(sock: socket.socket) -> bytes:
    """
    Receive a length-prefixed message.
    Blocks until the full payload arrives.
    Returns b"" on graceful close.
    """
    # 1. Read the 4-byte length header
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return b""
        header += chunk

    length = struct.unpack(">I", header)[0]

    # 2. Read exactly `length` bytes of payload
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            return b""
        payload += chunk

    return payload


# ── Key Exchange ───────────────────────────────────────────────────────────────

def perform_key_exchange_host(conn: socket.socket):
    """
    Host-side handshake:

      Host  →  Client  : Host's RSA public key  (PEM)
      Client → Host    : Client's RSA public key (PEM)
      Host  →  Client  : AES session key, encrypted with Client's RSA pub key

    After this function returns, both sides share the same AES key.

    Returns:
        (private_key, aes_key)
    """
    print(f"{DIM}[*] Generating RSA-2048 key pair…{RESET}")
    private_key, public_key = crypto.generate_rsa_keypair()

    # 1. Send our public key
    our_pem = crypto.serialize_public_key(public_key)
    send_frame(conn, our_pem)
    print(f"{DIM}[*] Sent our RSA public key.{RESET}")

    # 2. Receive peer's public key
    peer_pem = recv_frame(conn)
    if not peer_pem:
        raise ConnectionError("Peer disconnected during key exchange.")
    peer_public_key = crypto.deserialize_public_key(peer_pem)
    print(f"{DIM}[*] Received peer's RSA public key.{RESET}")

    # 3. Generate AES session key and send it encrypted
    aes_key = crypto.generate_aes_key()
    encrypted_aes = crypto.rsa_encrypt(peer_public_key, aes_key)
    send_frame(conn, encrypted_aes)
    print(f"{GREEN}[✓] AES session key exchanged securely.{RESET}")

    return private_key, aes_key


# ── Chat Threads ───────────────────────────────────────────────────────────────

stop_event = threading.Event()


def receive_loop(conn: socket.socket, aes_key: bytes) -> None:
    """
    Background thread: continuously receive and decrypt messages from peer.
    Sets stop_event when the connection closes.
    """
    while not stop_event.is_set():
        try:
            token = recv_frame(conn)
            if not token:
                print(f"\n{YELLOW}[!] Peer disconnected.{RESET}")
                stop_event.set()
                break
            message = crypto.aes_decrypt(aes_key, token)
            # Overwrite the current input line for cleaner UX
            print(f"\r{CYAN}{BOLD}Friend:{RESET} {message}\n{DIM}You:{RESET} ", end="", flush=True)
        except Exception as e:
            if not stop_event.is_set():
                print(f"\n{RED}[!] Receive error: {e}{RESET}")
                stop_event.set()
            break


def send_loop(conn: socket.socket, aes_key: bytes) -> None:
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
            send_frame(conn, token)
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
        description="P2P Secure Chat — Host mode (listens for a peer)"
    )
    parser.add_argument(
        "--port", type=int, default=5000,
        help="TCP port to listen on (default: 5000)"
    )
    args = parser.parse_args()

    print(BANNER)

    # Create listening socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", args.port))
    server_sock.listen(1)

    # ── Discover and display both IP addresses ────────────────────────────────
    print(f"{DIM}[*] Detecting network addresses…{RESET}")
    local_ip  = crypto.get_local_ip()
    public_ip = crypto.get_public_ip()   # may take up to ~5 s on first call

    print(f"\n{BOLD}{'─'*46}")
    print(f"  📡  Network Info")
    print(f"{'─'*46}{RESET}")
    print(f"  {BOLD}Local  IP  (LAN){RESET}  →  {YELLOW}{local_ip}{RESET}")
    print(f"  {BOLD}Public IP  (WAN){RESET}  →  {YELLOW}{public_ip}{RESET}")
    print(f"{BOLD}{'─'*46}{RESET}\n")

    if public_ip == "unavailable":
        print(f"{YELLOW}  [!] Could not reach the internet to detect your public IP.")
        print(f"      Use `curl ifconfig.me` manually if you need it.{RESET}\n")
    else:
        print(f"{DIM}  Give your peer the right address:")
        print(f"    • Same WiFi / LAN  →  {local_ip}:{args.port}")
        print(f"    • Over Internet    →  {public_ip}:{args.port}  (requires port forwarding on your router){RESET}\n")

    print(f"{BOLD}[*] Listening on port {YELLOW}{args.port}{RESET}{BOLD}  —  waiting for peer…{RESET}")

    try:
        conn, addr = server_sock.accept()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Aborted.{RESET}")
        server_sock.close()
        sys.exit(0)

    server_sock.close()   # stop accepting further connections (single-peer P2P)
    print(f"{GREEN}[✓] Peer connected from {addr[0]}:{addr[1]}{RESET}")

    try:
        _private_key, aes_key = perform_key_exchange_host(conn)
    except Exception as e:
        print(f"{RED}[✗] Key exchange failed: {e}{RESET}")
        conn.close()
        sys.exit(1)

    print(f"\n{BOLD}{GREEN}🔐 Secure channel established. Start chatting!{RESET}\n")
    print("─" * 46)

    # Launch receive thread; run send loop in the main thread
    recv_thread = threading.Thread(target=receive_loop, args=(conn, aes_key), daemon=True)
    recv_thread.start()

    send_loop(conn, aes_key)

    # Teardown
    stop_event.set()
    conn.close()
    recv_thread.join(timeout=2)
    print(f"{DIM}[*] Connection closed. Goodbye.{RESET}")


if __name__ == "__main__":
    main()

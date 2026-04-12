"""
host.py — P2P Secure Chat: Host (Listener)
==========================================
  1. Detect and display LAN + public IP addresses.
  2. Bind a TCP socket and wait for exactly one peer.
  3. RSA-2048 handshake → shared AES session key.
  4. Full-featured encrypted chat session:
       • Real-time messages  (encrypted JSON frames)
       • File transfer        (/sendfile)
       • Chat history         (/history)
       • Clean disconnect     (/exit or Ctrl-C)

Usage:
    python host.py [--port PORT]
    ./chat.sh --host [--port PORT]
"""

import socket
import sys
import argparse

import crypto
import common

# ── Colours ───────────────────────────────────────────────────────────────────
G = "\033[92m"; C = "\033[96m"; Y = "\033[93m"
B = "\033[1m";  D = "\033[2m";  R = "\033[0m"

BANNER = f"""
{B}{C}╔══════════════════════════════════════════════╗
║   🔒  P2P Secure Chat  ·  HOST MODE          ║
║   RSA-2048 handshake  ·  AES-Fernet session  ║
╚══════════════════════════════════════════════╝{R}
"""


def _show_network_info(port: int) -> None:
    print(f"{D}[*] Detecting network addresses…{R}")
    lan = crypto.get_local_ip()
    wan = crypto.get_public_ip()

    print(f"\n{B}{'─'*48}")
    print("  📡  Your Network Addresses")
    print(f"{'─'*48}{R}")
    print(f"  {B}Local  IP  (LAN / same WiFi){R}  →  {Y}{lan}{R}")
    print(f"  {B}Public IP  (WAN / internet){R}   →  {Y}{wan}{R}")
    print(f"{B}{'─'*48}{R}\n")

    if wan == "unavailable":
        print(f"{Y}  [!] Could not reach internet — public IP unknown.")
        print(f"      Run `curl ifconfig.me` manually if needed.{R}\n")
    else:
        print(f"{D}  Share with your peer:")
        print(f"    • Same network  →  python client.py {lan} --port {port}")
        print(f"    • Internet      →  python client.py {wan} --port {port}")
        print(f"      (Internet requires TCP port {port} forwarded on your router){R}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="P2P Secure Chat — Host mode")
    parser.add_argument("--port", type=int, default=5000,
                        help="TCP port to listen on (default: 5000)")
    args = parser.parse_args()

    print(BANNER)
    _show_network_info(args.port)

    # ── Create listening socket ───────────────────────────────────────────────
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("0.0.0.0", args.port))
    except OSError as e:
        print(f"{Y}[✗] Cannot bind to port {args.port}: {e}{R}")
        sys.exit(1)

    srv.listen(1)
    print(f"{B}[*] Listening on port {Y}{args.port}{R}{B} — waiting for peer…{R}\n")

    try:
        conn, addr = srv.accept()
    except KeyboardInterrupt:
        print(f"\n{Y}[*] Aborted.{R}")
        srv.close()
        sys.exit(0)

    srv.close()   # accept only one peer (pure P2P)
    print(f"{G}[✓] Peer connected from {addr[0]}:{addr[1]}{R}\n")

    # ── RSA + AES handshake ───────────────────────────────────────────────────
    try:
        _priv, aes_key = common.key_exchange_host(conn)
    except Exception as e:
        print(f"{Y}[✗] Handshake failed: {e}{R}")
        conn.close()
        sys.exit(1)

    print(f"\n{B}{G}🔐 Secure channel established. Start chatting!{R}\n")
    print("─" * 48)

    # ── Chat session ──────────────────────────────────────────────────────────
    common.run_chat(conn, aes_key)


if __name__ == "__main__":
    main()

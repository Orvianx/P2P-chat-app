"""
client.py — P2P Secure Chat: Client (Connector)
================================================
  1. Detect and display own LAN + public IP.
  2. Connect via TCP to the host peer.
  3. RSA-2048 handshake → shared AES session key.
  4. Full-featured encrypted chat session (identical to host after connect).

Usage:
    python client.py <HOST_IP> [--port PORT]
    ./chat.sh --connect <IP> [--port PORT]
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
║   🔒  P2P Secure Chat  ·  CLIENT MODE        ║
║   RSA-2048 handshake  ·  AES-Fernet session  ║
╚══════════════════════════════════════════════╝{R}
"""


def _show_own_network_info() -> None:
    print(f"{D}[*] Detecting your network addresses…{R}")
    lan = crypto.get_local_ip()
    wan = crypto.get_public_ip()
    print(f"\n{B}{'─'*48}")
    print("  📡  Your Network Addresses")
    print(f"{'─'*48}{R}")
    print(f"  {B}Local  IP (LAN){R}   →  {Y}{lan}{R}")
    print(f"  {B}Public IP (WAN){R}   →  {Y}{wan}{R}")
    print(f"{B}{'─'*48}{R}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="P2P Secure Chat — Client mode")
    parser.add_argument("host_ip", help="IP address of the host peer")
    parser.add_argument("--port", type=int, default=5000,
                        help="TCP port the host is listening on (default: 5000)")
    args = parser.parse_args()

    print(BANNER)
    _show_own_network_info()

    # ── Connect ───────────────────────────────────────────────────────────────
    print(f"{B}[*] Connecting to {Y}{args.host_ip}:{args.port}{R}{B}…{R}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)

    try:
        sock.connect((args.host_ip, args.port))
    except socket.timeout:
        print(f"{Y}[✗] Timed out. Check IP, port, and router port-forwarding.{R}")
        sys.exit(1)
    except ConnectionRefusedError:
        print(f"{Y}[✗] Refused. Is the host running on port {args.port}?{R}")
        sys.exit(1)
    except Exception as e:
        print(f"{Y}[✗] Connect error: {e}{R}")
        sys.exit(1)

    sock.settimeout(None)
    print(f"{G}[✓] Connected to {args.host_ip}:{args.port}{R}\n")

    # ── RSA + AES handshake ───────────────────────────────────────────────────
    try:
        _priv, aes_key = common.key_exchange_client(sock)
    except Exception as e:
        print(f"{Y}[✗] Handshake failed: {e}{R}")
        sock.close()
        sys.exit(1)

    print(f"\n{B}{G}🔐 Secure channel established. Start chatting!{R}\n")
    print("─" * 48)

    # ── Chat session ──────────────────────────────────────────────────────────
    common.run_chat(sock, aes_key)


if __name__ == "__main__":
    main()

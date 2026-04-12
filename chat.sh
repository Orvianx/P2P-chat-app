#!/usr/bin/env bash
# ============================================================
# chat.sh — SSH-style CLI wrapper for P2P Secure Chat
# ============================================================
# Usage:
#   ./chat.sh --host [--port PORT]
#   ./chat.sh --connect <IP> [--port PORT]
#
# Examples:
#   ./chat.sh --host
#   ./chat.sh --host --port 9000
#   ./chat.sh --connect 192.168.1.42
#   ./chat.sh --connect 203.0.113.7 --port 9000
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=5000
MODE=""
HOST_IP=""

# ── Colour helpers ─────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

usage() {
    echo -e "${BOLD}Usage:${RESET}"
    echo "  ./chat.sh --host [--port PORT]"
    echo "  ./chat.sh --connect <IP> [--port PORT]"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  --host            Start in host (listening) mode"
    echo "  --connect <IP>    Start in client mode, connect to <IP>"
    echo "  --port <PORT>     TCP port to use (default: 5000)"
    echo "  -h, --help        Show this help message"
    exit 1
}

# ── Check Python and cryptography package ─────────────────
check_deps() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[✗] python3 not found. Please install Python 3.8+.${RESET}"
        exit 1
    fi

    if ! python3 -c "from cryptography.fernet import Fernet" &>/dev/null; then
        echo -e "${YELLOW}[!] The 'cryptography' package is not installed.${RESET}"
        echo -e "    Install it with:  ${CYAN}pip install cryptography${RESET}"
        echo -e "    Or (Debian/Ubuntu with PEP 668):  ${CYAN}pip install cryptography --break-system-packages${RESET}"
        echo -e "    Or inside a venv:  ${CYAN}python3 -m venv .venv && source .venv/bin/activate && pip install cryptography${RESET}"
        exit 1
    fi
}

# ── Parse arguments ────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    usage
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            MODE="host"
            shift
            ;;
        --connect)
            MODE="client"
            if [[ -z "${2:-}" ]]; then
                echo -e "${RED}[✗] --connect requires an IP address argument.${RESET}"
                usage
            fi
            HOST_IP="$2"
            shift 2
            ;;
        --port)
            if [[ -z "${2:-}" ]]; then
                echo -e "${RED}[✗] --port requires a number.${RESET}"
                usage
            fi
            PORT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}[✗] Unknown argument: $1${RESET}"
            usage
            ;;
    esac
done

# ── Run ────────────────────────────────────────────────────
check_deps

cd "$SCRIPT_DIR"

case "$MODE" in
    host)
        exec python3 host.py --port "$PORT"
        ;;
    client)
        exec python3 client.py "$HOST_IP" --port "$PORT"
        ;;
    *)
        echo -e "${RED}[✗] No mode specified. Use --host or --connect <IP>.${RESET}"
        usage
        ;;
esac

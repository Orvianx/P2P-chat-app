#!/usr/bin/env bash
# ============================================================
#  chat.sh — SSH-style CLI wrapper for P2P Secure Chat
# ============================================================
#  Usage:
#    ./chat.sh --host [--port PORT]
#    ./chat.sh --connect <IP> [--port PORT]
#
#  Examples:
#    ./chat.sh --host
#    ./chat.sh --host --port 9000
#    ./chat.sh --connect 192.168.1.42
#    ./chat.sh --connect 203.0.113.7 --port 9000
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT=5000
MODE=""
HOST_IP=""

RED='\033[0;31m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BOLD='\033[1m';   RESET='\033[0m'

usage() {
    echo -e "${BOLD}P2P Secure Chat${RESET}"
    echo ""
    echo -e "${BOLD}Usage:${RESET}"
    echo "  ./chat.sh --host [--port PORT]"
    echo "  ./chat.sh --connect <IP> [--port PORT]"
    echo ""
    echo -e "${BOLD}Options:${RESET}"
    echo "  --host              Listen for a peer (host mode)"
    echo "  --connect <IP>      Connect to a host peer"
    echo "  --port <PORT>       TCP port (default: 5000)"
    echo "  -h, --help          Show this help"
    echo ""
    echo -e "${BOLD}In-chat commands:${RESET}"
    echo "  /sendfile <path>    Send a file"
    echo "  /history            Show chat history"
    echo "  /help               Show in-chat help"
    echo "  /exit               Disconnect"
    exit 1
}

check_deps() {
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}[✗] python3 not found. Install Python 3.10+.${RESET}"
        exit 1
    fi
    if ! python3 -c "from cryptography.fernet import Fernet" 2>/dev/null; then
        echo -e "${YELLOW}[!] The 'cryptography' package is missing.${RESET}"
        echo -e "    Install:  ${CYAN}pip install cryptography${RESET}"
        echo -e "    PEP 668:  ${CYAN}pip install cryptography --break-system-packages${RESET}"
        echo -e "    Venv:     ${CYAN}python3 -m venv .venv && source .venv/bin/activate && pip install cryptography${RESET}"
        exit 1
    fi
}

[[ $# -eq 0 ]] && usage

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)    MODE="host"; shift ;;
        --connect)
            MODE="client"
            [[ -z "${2:-}" ]] && { echo -e "${RED}--connect needs an IP.${RESET}"; usage; }
            HOST_IP="$2"; shift 2 ;;
        --port)
            [[ -z "${2:-}" ]] && { echo -e "${RED}--port needs a number.${RESET}"; usage; }
            PORT="$2"; shift 2 ;;
        -h|--help) usage ;;
        *) echo -e "${RED}Unknown option: $1${RESET}"; usage ;;
    esac
done

check_deps
cd "$SCRIPT_DIR"

case "$MODE" in
    host)   exec python3 host.py --port "$PORT" ;;
    client) exec python3 client.py "$HOST_IP" --port "$PORT" ;;
    *)      echo -e "${RED}Specify --host or --connect <IP>.${RESET}"; usage ;;
esac

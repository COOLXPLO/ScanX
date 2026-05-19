#!/usr/bin/env bash
# ─────────────────────────────────────────────
#  ScanX v2.0  —  Linux / macOS Launcher
#  by iamunknown77
# ─────────────────────────────────────────────
set -e

GREEN='\033[92m'
CYAN='\033[96m'
YELLOW='\033[93m'
RED='\033[91m'
DIM='\033[90m'
RESET='\033[0m'

echo -e "${GREEN}"
echo "  ███████╗ ██████╗ █████╗ ███╗   ██╗██╗  ██╗"
echo "  ██╔════╝██╔════╝██╔══██╗████╗  ██║╚██╗██╔╝"
echo "  ███████╗██║     ███████║██╔██╗ ██║ ╚███╔╝ "
echo "  ╚════██║██║     ██╔══██║██║╚██╗██║ ██╔██╗ "
echo "  ███████║╚██████╗██║  ██║██║ ╚████║██╔╝ ██╗"
echo "  ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝${RESET}"
echo -e "${CYAN}  Advanced Security Scanner v2.0  //  by iamunknown77${RESET}"
echo -e "${DIM}  ──────────────────────────────────────────────────${RESET}"
echo -e "${YELLOW}  ⚠  Use only on systems you own or have permission to test.${RESET}"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}  [✗] python3 not found. Install Python 3.9+ first.${RESET}"
    exit 1
fi

PY=$(python3 --version 2>&1)
echo -e "${DIM}  [+] $PY${RESET}"

# Install deps if needed
if ! python3 -c "import fastapi, uvicorn, aiohttp" &>/dev/null; then
    echo -e "${YELLOW}  [!] Installing dependencies...${RESET}"
    pip3 install -r requirements.txt --quiet
fi

echo -e "${GREEN}  [✓] Dependencies OK${RESET}"
echo -e "${CYAN}  [●] Starting ScanX backend on http://localhost:8000 ...${RESET}"
echo -e "${DIM}  [i] Open index.html in your browser  (or http://localhost:8000)${RESET}"
echo -e "${DIM}  [i] Press Ctrl+C to stop.${RESET}"
echo ""

# Try to auto-open browser (best-effort)
if command -v xdg-open &>/dev/null; then
    (sleep 2 && xdg-open "http://localhost:8000") &
elif command -v open &>/dev/null; then
    (sleep 2 && open "http://localhost:8000") &
fi

python3 scanner_backend.py

#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  LogSentinelAI — Security Agent  |  Linux / macOS launcher
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

DASHBOARD="https://log-sentinel-ai-h3bmh3hbh6e3c6bx.francecentral-01.azurewebsites.net"
API_KEY="sentinel-secret-key"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "  +--------------------------------------------------+"
echo "  |  LogSentinelAI  —  Security Agent  v1.2          |"
echo "  |  AI-Powered Intrusion Detection                   |"
echo "  +--------------------------------------------------+"
echo ""

# ── Detect OS ─────────────────────────────────────────────────────────────────
OS_NAME="$(uname -s)"
case "$OS_NAME" in
  Linux*)   OS_LABEL="Linux" ;;
  Darwin*)  OS_LABEL="macOS" ;;
  *)        OS_LABEL="$OS_NAME" ;;
esac
echo "  OS       : $OS_LABEL"

# ── Check Python 3 ───────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  echo ""
  echo "  [ERROR] Python 3 is not installed."
  echo ""
  if [ "$OS_LABEL" = "Linux" ]; then
    echo "  Install it with:"
    echo "    sudo apt update && sudo apt install python3 python3-pip   # Debian/Ubuntu"
    echo "    sudo yum install python3                                   # RHEL/CentOS"
    echo "    sudo pacman -S python                                      # Arch"
  elif [ "$OS_LABEL" = "macOS" ]; then
    echo "  Install it with:  brew install python3"
  fi
  echo ""
  exit 1
fi

PYVER="$(python3 --version 2>&1)"
echo "  Python   : $PYVER"

# ── Install / update dependencies ────────────────────────────────────────────
echo "  Deps     : checking..."
pip3 install requests psutil watchdog --quiet --disable-pip-version-check 2>/dev/null \
  || python3 -m pip install requests psutil watchdog --quiet --disable-pip-version-check
echo "  Deps     : ready"
echo ""

# ── Note for Linux: Security logs need root ───────────────────────────────────
if [ "$OS_LABEL" = "Linux" ] && [ "$(id -u)" -ne 0 ]; then
  echo "  NOTE: Some log files (/var/log/auth.log, /var/log/secure) require"
  echo "        root access.  Re-run with  sudo ./start.sh  for full coverage."
  echo ""
fi

echo "  Dashboard: $DASHBOARD"
echo ""
echo "  ┌──────────────────────────────────────────────────┐"
echo "  │  A pairing code will appear below.               │"
echo "  │  Sign in to your dashboard and click             │"
echo "  │  'Connect Machine', then enter the code.         │"
echo "  │                                                  │"
echo "  │  Press  Ctrl+C  to stop the agent.               │"
echo "  └──────────────────────────────────────────────────┘"
echo ""

# ── Run agent ─────────────────────────────────────────────────────────────────
exec python3 "$SCRIPT_DIR/agent.py" \
  --server "$DASHBOARD" \
  --key    "$API_KEY" \
  "$@"

#!/bin/bash
# FlowOsint v3.0 — Linux / macOS launcher

# Always run from the script's own directory
cd "$(dirname "$0")"

# ── Check Python ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo ""
    echo " [ERROR] Python 3 is not installed."
    echo " Install it with your package manager:"
    echo "   Ubuntu/Debian:  sudo apt install python3 python3-venv python3-pip"
    echo "   macOS:          brew install python"
    echo ""
    exit 1
fi

# Check version is 3.10+
PY_VER=$(python3 -c "import sys; print(sys.version_info >= (3,10))")
if [ "$PY_VER" != "True" ]; then
    echo ""
    echo " [ERROR] Python 3.10 or newer is required."
    echo " Your version: $(python3 --version)"
    echo ""
    exit 1
fi

# ── Create virtual environment if it doesn't exist ───────────────────────────
if [ ! -f "venv/bin/activate" ]; then
    echo ""
    echo " [*] First run detected - setting up virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo " [ERROR] Failed to create virtual environment."
        echo " Try: sudo apt install python3-venv"
        exit 1
    fi
    echo " [+] Virtual environment created."
fi

# ── Activate virtual environment ─────────────────────────────────────────────
source venv/bin/activate

# ── Install / update dependencies ────────────────────────────────────────────
echo ""
echo " [*] Checking dependencies..."
pip install -r requirements.txt -q --disable-pip-version-check
if [ $? -ne 0 ]; then
    echo ""
    echo " [ERROR] Dependency installation failed."
    echo " Try running manually: pip install -r requirements.txt"
    echo ""
    exit 1
fi
echo " [+] Dependencies OK."
echo ""

# ── Launch FlowOsint ─────────────────────────────────────────────────────────
python flowoosint.py

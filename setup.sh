#!/usr/bin/env bash
# ==============================================================================
# DevGuard Setup & Automated Verification Script
# GDG Jakarta Gemini Prompt Maxxing Submission
# ==============================================================================

set -e

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}             DEVGUARD: ADVERSARIAL CODE REVIEW HARNESS                ${NC}"
echo -e "${BLUE}======================================================================${NC}"
echo ""

# 1. Cek Python3
echo -e "[*] Memeriksa environment sistem..."
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python 3 tidak ditemukan. Silakan pasang python3 terlebih dahulu.${NC}"
    exit 1
fi

PY_VERSION=$(python3 --version)
echo -e "    ${GREEN}✓${NC} Terdeteksi: $PY_VERSION"

# 2. Setup Virtual Environment (.venv)
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo -e "[*] Membuat virtual environment Python di ./$VENV_DIR..."
    python3 -m venv "$VENV_DIR"
fi

echo -e "[*] Mengaktifkan virtual environment..."
source "$VENV_DIR/bin/activate"

# 3. Pasang Dependensi
echo -e "[*] Memasang dependensi dari requirements.txt..."
pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet
echo -e "    ${GREEN}✓${NC} google-genai berhasil dipasang/diperbarui."

# 4. Jalankan Tes Verifikasi Empiris SQLite
echo ""
echo -e "${BLUE}[*] Menjalankan test harness empiris lokal (devguard_verify.py)...${NC}"
echo "----------------------------------------------------------------------"
python3 devguard_verify.py
echo "----------------------------------------------------------------------"

# 5. Pengecekan GEMINI_API_KEY untuk Live Adversarial Review
echo ""
if [ -z "$GEMINI_API_KEY" ]; then
    echo -e "${YELLOW}[!] Catatan: Environment variable GEMINI_API_KEY belum terdeteksi.${NC}"
    echo -e "    Untuk menjalankan audit adversarial berbasis AI langsung, jalankan:"
    echo -e "    export GEMINI_API_KEY='kunci_gemini_anda'"
    echo -e "    python3 run_devguard.py"
else
    echo -e "${GREEN}✓ GEMINI_API_KEY terdeteksi.${NC} Ingin menjalankan live audit sekarang? (y/n)"
    read -r -t 10 response || response="y"
    if [[ "$response" =~ ^[Yy]$ ]]; then
        python3 run_devguard.py
    fi
fi

echo ""
echo -e "${GREEN}[✓] Setup dan verifikasi DevGuard selesai dengan sukses!${NC}"
echo -e "${BLUE}======================================================================${NC}"

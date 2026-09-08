#!/bin/bash
# Instalacni skript pro MikroTik ISP Manager (mk_manager)

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "================================================================="
echo "    Instalace MikroTik ISP Manager (mk_manager)"
echo "================================================================="

# Pomocne urceni prav (root vs sudo)
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
fi

# 1. Kontrola a instalace Pythonu 3
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 nenalezen, pokousim se nainstalovat..."
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -y && $SUDO apt-get install -y python3 python3-venv
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm python
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y python3
    fi
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] CHYBA: python3 neni nainstalovan a nepodarilo se jej nainstalovat."
    exit 1
fi

# 2. Kontrola a instalace python3-venv / ensurepip
if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
    echo "[!] Chybi modul venv / ensurepip, pokousim se doinstalovat..."
    PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "")
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -y
        $SUDO apt-get install -y python3-venv 2>/dev/null || $SUDO apt-get install -y "python${PY_VER}-venv" 2>/dev/null || true
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm python
    fi
fi

if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
    echo "[!] CHYBA: Chybi modul python3-venv / ensurepip."
    echo "    Na Debianu/Ubuntu spustte rucne: apt update && apt install -y python3-venv"
    exit 1
fi

# 3. Vytvoreni virtualniho prostredi
if [ ! -f "venv/bin/pip" ]; then
    rm -rf venv
    echo "[+] Vytvarim virtualni prostredi Python (venv)..."
    python3 -m venv venv
else
    echo "[+] Virtualni prostredi (venv) jiz existuje."
fi

# 4. Instalace balicku
echo "[+] Instaluji zavislosti z requirements.txt..."
venv/bin/pip install --upgrade pip --quiet
venv/bin/pip install -r requirements.txt --quiet

# 5. Inicializace adresare data
mkdir -p data

# 6. Kontrola konfigurace
if [ ! -f "config.yaml" ]; then
    echo "[+] Vytvarim vychozi config.yaml z config.example.yaml..."
    cp config.example.yaml config.yaml
    echo "[!] DULEZITE: Upravte prosim soubor config.yaml pred spustenim skenu!"
    echo "    Spustte napr.: vim config.yaml"
else
    echo "[+] Soubor config.yaml jiz existuje."
fi

# 7. Nastaveni prav
chmod +x mk_manager main.py install.sh setup_env.sh 2>/dev/null || true

echo "================================================================="
echo " Instalace uspesne dokoncena!"
echo " Spusteni: ./mk_manager status nebo ./mk_manager scan"
echo "================================================================="

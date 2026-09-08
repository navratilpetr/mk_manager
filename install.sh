#!/bin/bash
# Instalacni skript pro MikroTik ISP Manager (mk_manager)

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Barvy
if [ -t 1 ]; then
    C_RESET='\033[0m'
    C_BOLD='\033[1m'
    C_GREEN='\033[32m'
    C_YELLOW='\033[33m'
    C_CYAN='\033[36m'
    C_RED='\033[31m'
    C_GRAY='\033[90m'
else
    C_RESET=''
    C_BOLD=''
    C_GREEN=''
    C_YELLOW=''
    C_CYAN=''
    C_RED=''
    C_GRAY=''
fi

msg_ok()   { printf " ${C_GREEN}[  OK  ]${C_RESET} %b\n" "$1"; }
msg_info() { printf " ${C_CYAN}[ INFO ]${C_RESET} %b\n" "$1"; }
msg_warn() { printf " ${C_YELLOW}[POZOR ]${C_RESET} %b\n" "$1"; }
msg_err()  { printf " ${C_RED}[CHYBA ]${C_RESET} %b\n" "$1"; }
msg_step() { printf "\n${C_BOLD}%b${C_RESET}\n" "$1"; }

echo ""
echo -e "${C_BOLD}${C_CYAN}=================================================================${C_RESET}"
echo -e "${C_BOLD}          MikroTik ISP Manager (mk_manager) - Instalace          ${C_RESET}"
echo -e "${C_BOLD}${C_CYAN}=================================================================${C_RESET}"

# Pomocne urceni prav (root vs sudo)
if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
elif command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
else
    SUDO=""
fi

# 1. Kontrola a instalace Pythonu 3
msg_step "[1/5] Kontrola Pythonu 3..."
if ! command -v python3 >/dev/null 2>&1; then
    msg_info "Instaluji python3 ze systemovych repozitaru..."
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -qq >/dev/null 2>&1
        $SUDO apt-get install -y -qq python3 python3-venv >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm python >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then
        $SUDO dnf install -y -q python3 >/dev/null 2>&1 || true
    fi
fi

if ! command -v python3 >/dev/null 2>&1; then
    msg_err "Python 3 se nepodarilo nainstalovat. Nainstalujte jej rucne."
    exit 1
fi
PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "")
msg_ok "Nalezen Python ${PY_VER} ($(command -v python3))"

# 2. Kontrola python3-venv / ensurepip
msg_step "[2/5] Kontrola podpory virtualniho prostredi (venv)..."
if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
    msg_info "Doinstalovavam balicek python3-venv..."
    if command -v apt-get >/dev/null 2>&1; then
        $SUDO apt-get update -qq >/dev/null 2>&1
        $SUDO apt-get install -y -qq python3-venv >/dev/null 2>&1 || $SUDO apt-get install -y -qq "python${PY_VER}-venv" >/dev/null 2>&1 || true
    elif command -v pacman >/dev/null 2>&1; then
        $SUDO pacman -Sy --noconfirm python >/dev/null 2>&1 || true
    fi
fi

if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
    msg_err "Chybi modul python3-venv / ensurepip. Spustte: apt install -y python3-venv"
    exit 1
fi
msg_ok "Podpora venv (ensurepip) je dostupna"

# 3. Vytvoreni virtualniho prostredi venv
msg_step "[3/5] Priprava virtualniho prostredi (venv)..."
if [ ! -f "venv/bin/pip" ]; then
    rm -rf venv
    python3 -m venv venv
    msg_ok "Virtualni prostredi venv/ vytvoreno"
else
    msg_ok "Pouzito stavajici prostredi venv/"
fi

# 4. Instalace balicku z requirements.txt
msg_step "[4/5] Instalace Python knihoven (requirements.txt)..."
venv/bin/pip install --upgrade pip --quiet
venv/bin/pip install -r requirements.txt --quiet
msg_ok "Vsechny knihovny byly uspesne nainstalovany"

# 5. Inicializace dat a konfigurace
msg_step "[5/5] Priprava konfigurace a prav..."
mkdir -p data
chmod +x mk_manager main.py install.sh 2>/dev/null || true

NEW_CONFIG=0
if [ ! -f "config.yaml" ]; then
    cp config.example.yaml config.yaml
    NEW_CONFIG=1
    msg_ok "Vytvoren vychozi config.yaml (z config.example.yaml)"
else
    msg_ok "Konfigurace config.yaml jiz existuje"
fi

# Zaverecne shrnuti
echo ""
echo -e "${C_BOLD}${C_GREEN}=================================================================${C_RESET}"
echo -e "${C_BOLD}        Instalace MikroTik ISP Manageru probehla uspesne!        ${C_RESET}"
echo -e "${C_BOLD}${C_GREEN}=================================================================${C_RESET}"
echo ""
echo -e "${C_BOLD}Dalsi kroky k pouziti:${C_RESET}"
if [ $NEW_CONFIG -eq 1 ]; then
    echo -e "  ${C_YELLOW}1. Nastavte rozsahy siti a prihlasovaci udaje v konfiguraci:${C_RESET}"
    echo -e "     ${C_CYAN}vim config.yaml${C_RESET}"
    echo ""
    echo -e "  2. Spustte uvodni audit a sken site:"
else
    echo -e "  1. Spustte uvodni audit a sken site:"
fi
echo -e "     ${C_CYAN}./mk_manager scan${C_RESET}"
echo ""
echo -e "  $([ $NEW_CONFIG -eq 1 ] && echo 3 || echo 2). Zobrazte prehled stavu zarizeni:"
echo -e "     ${C_CYAN}./mk_manager status${C_RESET}"
echo ""
echo -e "${C_GRAY}Tip: Napovedu ke vsem prikazum ziskate pomoci: ./mk_manager --help${C_RESET}"
echo ""

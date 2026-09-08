#!/bin/bash
# Instalacni skript pro MikroTik ISP Manager (mk_manager)

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "================================================================="
echo "    Instalace MikroTik ISP Manager (mk_manager)"
echo "================================================================="

# 1. Kontrola Pythonu
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] CHYBA: python3 neni nainstalovan."
    echo "    Na Debianu/Ubuntu: apt update && apt install -y python3 python3-venv"
    echo "    Na Arch Linuxu:   pacman -S python"
    exit 1
fi

# 2. Kontrola python3-venv
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "[!] CHYBA: Chybi modul python3-venv."
    echo "    Na Debianu/Ubuntu spustte: apt update && apt install -y python3-venv"
    exit 1
fi

# 3. Vytvoreni virtualniho prostredi
if [ ! -d "venv" ]; then
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

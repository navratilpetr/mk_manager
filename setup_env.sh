#!/bin/bash
# Inicializace izolovaneho Python venv bez sudo

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "=== Inicializace virtualniho prostredi mk_manager ==="

# Kontrola dostupnosti modulu venv / ensurepip (na Debianu 12 vyzaduje balicek python3-venv)
if ! python3 -m venv --help >/dev/null 2>&1; then
    echo "[!] Chybi modul python3-venv. Na Debianu 12 spustte:"
    echo "    apt update && apt install -y python3-venv"
    exit 1
fi

# Vytvoreni venv pokud neexistuje
if [ ! -d "venv" ]; then
    echo "[+] Vytvarim venv..."
    if ! python3 -m venv venv; then
        echo "[!] Selhalo vytvoreni venv. Na Debianu 12 doinstalujte:"
        echo "    apt update && apt install -y python3-venv"
        exit 1
    fi
fi

# Instalace zavislosti
echo "[+] Instaluji / aktualizuji zavislosti z requirements.txt..."
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt

# Vytvoreni datoveho adresare
mkdir -p data

# Nastaveni prav spusteni
chmod +x main.py mk_manager setup_env.sh 2>/dev/null || true

echo "=== Inicializace uspesne dokoncena ==="
echo "Dostupne prikazy CLI:"
echo "  ./main.py status"
echo "  ./main.py scan"
echo "  ./main.py topology"
echo "  ./main.py audit"
echo "  ./main.py update --dry-run"
echo ""
echo "Nebo pouzitim wrapperu:"
echo "  ./mk_manager status"

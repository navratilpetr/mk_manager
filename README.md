# MikroTik ISP Manager (`mk_manager`)

[![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)](https://github.com/navratilpetr/mk_manager)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![RouterOS](https://img.shields.io/badge/RouterOS-v5%20%7C%20v6%20%7C%20v7-green.svg)](https://mikrotik.com)

**MikroTik ISP Manager** je nastroj navrzeny pro spravce siti a poskytovatele internetu (ISP). Umoznuje hromadny audit, automatickou detekci sitove topologie a bezpecny fazovany update RouterOS napric rozsahlymi sitemi (stovky az tisice zarizeni) bez rizika odriznuti vzdalenych lokalit.

---

## Hlavni prednosti a funkce

- **Inteligentni planovani vln (Leaf-to-Spine):**
  - Analyzuje topologii site (vychozi brany, traceroute a MNDP sousedy).
  - Rozdeli sit do vrstev/vln: od koncovych klientskych jednotek a AP (Vlna 1) az po centralni brany a Core routery (nejvyssi vlna).
  - Aktualizace probiha striktne od listu k jadru – nikdy se neaktualizuje paterni router drive nez zarizeni za nim.
- **Rychlost a paralelni zpracovani:**
  - V ramci kazde vlny probiha update paralelne pomoci fondu vlaken (vychozi: 10 zarizeni soubezne, konfigurovatelne).
  - Sit s 800+ zarizenimi lze bezpecne zaktualizovat za nekolik hodin misto nekolika dni.
- **Univerzalni podpora RouterOS (v5, v6, v7):**
  - Automaticka podpora legacy SSH sifer a klicu (vcetne `ssh-dss` u velmi starych instalaci).
  - Specialni fallback pro legacy verze (napr. ROS 6.20, kde neexistuje prikaz `install`): primy download balicku pres `/tool fetch` a neinteraktivni skriptovy reboot.
- **Automaticka oprava DNS pred aktualizaci:**
  - Pokud router nema nastaven zadny DNS server (caste u L2 zarizeni v management VLAN), nastroj docasne doplni zalozni DNS z konfigurace, aby router dokazal stahnout balicky z repozitare MikroTiku.
- **Kontrola bezpecnosti a kompromitace:**
  - Detekuje indikatory napadeni: `device-mode flagged=yes`, pritomnost utocnickeho uctu `ops` nebo zname exploity v logu.
- **Automaticky upgrade RouterBOOT:**
  - Po uspesnem nabehnuti nove verze zkontroluje a aktualizuje firmware RouterBOARDu (`/system routerboard upgrade`).
- **Prehledny Rich CLI vystup & CSV Export:**
  - Barevne vystupy, prubezne ukazatele stavu (progress bar), numericke razeni podle IP a export kompletniho auditu do `data/audit.csv`.

---

## Struktura projektu

```
mk_manager/
├── install.sh           # Automaticky instalator (kontrola Pythonu, venv, balicku)
├── mk_manager           # Spusteci bash wrapper
├── main.py              # Hlavni ridici CLI skript
├── config.yaml          # Vasi privatni konfigurace (ignoruje se gitem)
├── config.example.yaml  # Ukazkova sablona konfigurace
├── config.py            # Parser konfigurace a rotujici logger
├── database.py          # SQLite databaze (WAL rezim pro soubezny pristup)
├── auth.py              # SSH klient, sifrovaci algoritmy a audit bezpecnosti
├── scanner.py           # 3fazovy skener (Ping sweep -> Port probe -> SSH auth)
├── topology.py          # Sber sousedu a vypocet DAG vln (Leaf -> Spine)
├── updater.py           # Paralelni updater s recovery smyckou
├── requirements.txt     # Zavislosti (paramiko, netaddr, rich, PyYAML, cryptography)
├── LICENSE              # MIT Licence
└── README.md            # Tato dokumentace
```

---

## Instalace a zprovozneni

### 1. Klonovani repozitare
```bash
git clone https://github.com/navratilpetr/mk_manager.git
cd mk_manager
```

### 2. Spusteni instalatoru
Instalator overi pritomnost Pythonu 3, vytvori izolovane virtualni prostredi `venv`, nainstaluje potrebne knihovny a pripravi `config.yaml`:
```bash
chmod +x install.sh
./install.sh
```

*(Poznamka pro Debian/Ubuntu: Pokud chybi podpora pro venv, instalator vas vyzve k doinstalovani balicku: `apt install -y python3-venv`).*

### 3. Nastaveni konfigurace
Otevrete `config.yaml` ve svem oblibenem editoru a zadejte management rozsahy a pristupy:
```bash
vim config.yaml
```

Priklad nastaveni `config.yaml`:
```yaml
networks:
  - "10.10.13.0/24"
  - "192.168.100.0/24"

credentials:
  users:
    - "admin"
    - "ispadmin"
  passwords:
    - "MojeTajneHeslo1"
    - "MojeTajneHeslo2"

updater:
  workers: 10                  # Pocet soubeznych aktualizaci v ramci jedne vlny
  max_attempts: 3              # Maximalni pocet pokusu pri upgradu
  min_disk_free_mb: 0.8        # Minimalni volne misto na disku (vhodne i pro 16MB flash)
  allow_major_upgrade: false   # Prechod z v6 na v7 je prisne zakazan

dns:
  servers:
    - "1.1.1.1"
    - "8.8.8.8"
```

---

## Pouziti (Doporuceny pracovni postup)

CLI muzete spoustet pres wrapper `./mk_manager` nebo primo `./main.py`:

### Krok 1: Skennovani a audit site
```bash
./mk_manager scan
```
- Provede rychly ping sweep zadanych subnetu.
- Otestuje dostupnost portu (SSH, Winbox, API).
- Prihlasi se pres SSH, overi stav pameti, disku, DNS, pritomnost uctu a zjisti aktualni i doporucenou verzi.

### Krok 2: Vypocet topologie a vln
```bash
./mk_manager topology
```
- Vycte informace o sousedech, vychozich branach a wireless registracich.
- Vypocita zavislosti a rozdeli sit do vln (Vlna 1 = koncove body, nejvyssi vlna = jadro).

### Krok 3: Kontrola stavu
```bash
./mk_manager status
```
- Zobrazi prehled zarizeni, statistiky verzi, varovani pred kompromitovanymi routery a tabulku zarizeni cekajicich na update.

### Krok 4: Fazovany update

**Testovaci simulace (dry-run bez restartu):**
```bash
./mk_manager update --dry-run
```

**Aktualizace konkretni vlny (napr. Vlna 1):**
```bash
./mk_manager update --wave 1
```

**Aktualizace cele site (postupne vlna po vlne):**
```bash
./mk_manager update
```

**Zmena poctu soubeznych vlaken:**
```bash
./mk_manager update --workers 5
```

**Cileny update vybranych IP:**
```bash
./mk_manager update --ip 10.10.13.2
./mk_manager update --ip 10.10.13.5,10.10.13.9,10.10.13.10
```

### Automaticky kompletni pruchod (Scan -> Topology -> Update)
```bash
./mk_manager run-all
```

### Aktualizace nastroje z GitHubu
Nastroj obsahuje vestaveny prikaz pro aktualizaci zdrojoveho kodu:
```bash
./mk_manager self-update
```

---

## Bezpecnostni pravidla a principy

1. **Ochrana stability site (Leaf-to-Spine):**
   Paterni switch nebo router se nikdy nezacne aktualizovat a restartovat, dokud nejsou plne dokoncena a online vsechna zarizeni za nim.
2. **Ochrana pred znefunkcnenim konfigurace (Major upgrade lock):**
   Prechod z RouterOS v6 na RouterOS v7 prinasi zasadni zmeny v routovani a konfiguraci. Prechod mezi hlavnimi verzemi v6 -> v7 je ve vychozim stavu **blokovan**.
3. **Kontrola uloziste:**
   Pred zahajenim stahovani balicku skript overuje volne misto na flash disku, aby nedoslo k zaplneni flash pameti a naslednemu bootloopu.
4. **Recovery smycka po rebootu:**
   Skript aktivne monitoruje prubeh restartu routeru a nabehnuti sitovych sluzeb az po dobu 600 sekund. Pote overi novou verzi a provede upgrade RouterBOOTu.

---

## Poděkování a vývoj (Built with AI Assistance)

Tento projekt byl vytvořen, refaktorován a optimalizován za aktivního přispění pokročilých nástrojů umělé inteligence:
- **Google DeepMind Antigravity** – agentní vývojové prostředí, návrh architektury a ladění kompatibility.
- **Gemini** – generování kódu, asistence při reverzním inženýrství legacy chování RouterOS a tvorba dokumentace.

Děkujeme AI týmům v Google za špičkové nástroje, které umožnily vytvořit a otestovat tento robustní síťový manažer.

---

## Licence

Projekt je licencovan pod otevrenou licenci **MIT**. Vice informaci naleznete v souboru [LICENSE](LICENSE).

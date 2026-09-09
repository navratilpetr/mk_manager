# Changelog

Všechny významné změny v projektu **MikroTik ISP Manager (`mk_manager`)** jsou zaznamenávány v tomto souboru.

Formát vychází ze zásad [Keep a Changelog](https://keepachangelog.com/cs/1.0.0/) a projekt dodržuje [Sémantické verzování](https://semver.org/lang/cs/).

---

## [1.0.1] - 2026-09-09

### Přidáno
- **Samostatná tabulka ručního zásahu:** V příkazu `./mk_manager status` se nově zobrazuje jasná tabulka routerů, které vyžadují manuální pozornost (`SKIPPED` nebo `FAILED_UPGRADE`) s přesným důvodem selhání.
- **Automatická kontrola verzí:** Nástroj při zobrazení stavu na pozadí ověřuje dostupnost novější verze z GitHub repozitáře a doporučí spuštění `./mk_manager self-update`.
- **Příkaz `version`:** Možnost zobrazit verzi pomocí `./mk_manager version`.
- **Verze aplikace ve statusu:** V souhrnné tabulce stavu sítě je nově uveden řádek s verzí použitého `mk_manageru`.
- **Přehlednější výstup statusu:** Tabulka zařízení vyžadujících aktualizaci byla přesunuta na konec výpisu před celkový souhrn sítě pro okamžitou viditelnost bez nutnosti rolovat.

### Opraveno a vylepšeno
- **Inteligentní fallback pro AP bez ICMP pingu:** Pokud na routeru selže test `ping 8.8.8.8` (časté u AP a prvků v management VLAN, kde firewall zahazuje odchozí ICMP), updater router automaticky nepřeskakuje. Místo toho otestuje přímé spojení na update server MikroTiku přes TCP (`check-for-updates once`). Pokud spojení funguje, update normálně proběhne.
- **Rozlišení pokusů o exploit od reálné kompromitace:** Neúspěšné pokusy o přihlášení v logu (`login failure for user -2`) již nespouštějí falešný poplach o kompromitaci. Jsou vyčleněny do samostatného žlutého bezpečnostního upozornění s informací, že útok byl odražen a router běží na opravené verzi. Červené varování je vyhrazeno pouze pro potvrzený průnik (`device-mode: flagged`, útočnický účet `ops`).
- **Stabilita SSH spojení:** Zapnut aktivní TCP Keepalive (5 s) na transportní vrstvě Paramiko pro včasnou detekci pádu spojení při rebootu bez TCP FIN/RST.
- **Odstranění zablokování v topologii:** Odstraněn nekonečně běžící příkaz `traceroute` z mapování topologie a přidán striktní kanálový timeout na čtení dat ze soketu.
- **Tichý výstup updatu:** Potlačen šum vláken do konzole, přidáno počítadlo `[X/Y]` se souhrnem na jednom řádku a kalkulačka odhadu času při 50+ zařízeních.
- **Okamžitá odezva při startu vlny:** Ihned po zahájení vlny se vypíše seznam prvních souběžně zpracovávaných routerů a spustí se animovaný indikátor průběhu (spinner), takže uživatel nemusí čekat 2 minuty v tichu na dokončení prvního rebootu.
- **Automatická deduplikace zařízení s více IP adresami:** Zavedena robustní deduplikace routerů s více IP adresami (typicky OmniTIK se sektory/VLAN), které byly dříve vloženy duplicitně a v jedné vlně se aktualizovaly souběžně (což vedlo k selhání jednoho ze spojení během rebootu). Deduplikace probíhá podle unikátního sériového čísla (`serial_number`), fyzických MAC adres a pole `all_ips` (nikoliv podle `identity`, kde mohou mít různé klientské jednotky stejné jméno). Přidán thread-lock v `Database` proti race condition a automatická očista `cleanup_duplicate_devices()`.
- **Instalátor:** Vylepšena detekce `python3-venv` a automatická instalace systémových balíčků.

---

## [1.0.0] - 2026-09-08

### Přidáno
- **3fázový síťový skener:** ICMP Ping Sweep -> TCP Port Probe -> SSH Auth & Audit.
- **Automatická detekce topologie (Leaf-to-Spine):** Výpočet orientovaného acyklického grafu (DAG) z default gateway, ARP vazeb, MNDP a bezdrátových registrací pro bezpečný update od klientů k jádru.
- **Paralelní fazovaný updater:** Souběžné aktualizace v rámci vln s recovery smyčkou a automatickým RouterBOOT upgradem.
- **Podpora RouterOS v5, v6 a v7:** Zpětná kompatibilita s legacy šiframi (`ssh-rsa`, `ssh-dss`) a fallback pro stahování balíčků přes `/tool fetch`.
- **Bezpečnostní audit:** Detekce napadení routerů (MikroTrick, `flagged: yes`, neznámé účty).
- **SQLite databáze s WAL:** Souběžný a rychlý přístup k datům s automatickým CSV exportem.
- **Automatický instalátor `install.sh` a příkaz `self-update`.**

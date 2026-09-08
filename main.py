#!/usr/bin/env python3
# Hlavni ridici skript MikroTik ISP Manager s CLI rozhranim (argparse + rich)
import os
import sys
from pathlib import Path

# Automaticky self-reexec do lokalniho venv pokud neni aktivovano
base_dir = Path(__file__).resolve().parent
venv_python = base_dir / "venv" / "bin" / "python"

if sys.prefix == sys.base_prefix and venv_python.exists():
    if Path(sys.executable).resolve() != venv_python.resolve():
        os.execv(str(venv_python), [str(venv_python)] + sys.argv)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
except ImportError:
    print("CHYBA: Chybi potrebne knihovny (rich atd.).", file=sys.stderr)
    print("Spustte nejprve inicializaci prostredi: ./setup_env.sh", file=sys.stderr)
    sys.exit(1)

import argparse

from config import Config, setup_logger, APP_VERSION
from database import Database
from scanner import Scanner
from topology import TopologyManager
from updater import Updater

console = Console()


def ip_sort_key(d: dict):
    import ipaddress
    try:
        return ipaddress.ip_address(d.get("ip", "0.0.0.0"))
    except Exception:
        return ipaddress.ip_address("0.0.0.0")


def print_banner() -> None:
    banner_text = (
        f"[bold cyan]MikroTik ISP Manager[/bold cyan] [bold yellow]v{APP_VERSION}[/bold yellow] - "
        "[green]Audit, Topologie a Fazovany Update[/green]\n"
        "[dim]Sprava RouterOS v5, v6 a v7 v ISP siti[/dim]"
    )
    console.print(Panel(banner_text, border_style="cyan"))


def cmd_scan(config: Config, db: Database, args: argparse.Namespace) -> None:
    print_banner()
    scanner = Scanner(config, db)
    updater = Updater(config, db)

    # 1. Zjisteni cilovych verzi z internetu
    console.print("[bold yellow]Ziskavani aktualnich verzi RouterOS z MikroTik update kanalu...[/bold yellow]")
    latest_v6, latest_v7 = updater.get_latest_versions()
    console.print(f"Cilove stabilni verze: [cyan]ROS v6: {latest_v6}[/cyan] | [cyan]ROS v7: {latest_v7}[/cyan]\n")

    # 2. Generovani IP adres
    target_ips = scanner.generate_target_ips()
    if not target_ips:
        console.print("[red]Nebyly nalezeny zadne IP adresy ze zadanych rozsahu v config.yaml[/red]")
        return
    console.print(f"Celkem IP adres k provereni: [bold]{len(target_ips)}[/bold]")

    # 3. Faze 1: ICMP Ping Sweep
    active_hosts = scanner.phase1_ping_sweep(target_ips)
    if not active_hosts:
        console.print("[yellow]Zadny z testovanych hostu neodpovida na ICMP ping.[/yellow]")
        return

    # 4. Faze 2: Port Check
    candidates = scanner.phase2_port_check(active_hosts)
    if not candidates:
        console.print("[yellow]Na zadnem aktivnim zarizeni nebyly nalezeny MikroTik porty.[/yellow]")
        return

    # 5. Faze 3: Auth & Audit
    audited = scanner.phase3_auth_and_audit(candidates, latest_v6, latest_v7)

    # 6. Automaticky export do CSV
    csv_path = db.export_audit_csv()
    console.print(f"\n[bold green]Audit dokoncen.[/bold green] Uspesne auditovano: {len(audited)} routeru.")
    console.print(f"Report ulozen do: [cyan]{csv_path}[/cyan]")


def cmd_topology(config: Config, db: Database, args: argparse.Namespace) -> None:
    print_banner()
    topo = TopologyManager(config, db)
    if not getattr(args, "no_collect", False):
        console.print("[bold yellow]Vyctani informaci o sousedech (/ip neighbor, wireless, gateway, traceroute)...[/bold yellow]")
        topo.collect_neighbors()
    console.print("[bold yellow]Vypocet aktualizacnich vln (Leaf -> Spine)...[/bold yellow]")
    topo.calculate_waves()
    topo.display_waves_summary()
    csv_path = db.export_audit_csv()
    console.print(f"Aktualizovany report s vlnami ulozen do: [cyan]{csv_path}[/cyan]")


def cmd_audit(config: Config, db: Database, args: argparse.Namespace) -> None:
    print_banner()
    updater = Updater(config, db)
    latest_v6, latest_v7 = updater.get_latest_versions()
    db.refresh_target_versions(latest_v6, latest_v7)
    devices = db.get_all_devices()
    if not devices:
        console.print("[yellow]V databazi nejsou evidovana zadna zarizeni. Spustte nejprve 'scan'.[/yellow]")
        return

    table = Table(title=f"[bold green]Audit MikroTik zarizeni ({len(devices)} routeru) | Cil: v6={latest_v6}, v7={latest_v7}[/bold green]")
    table.add_column("ID", justify="right", style="dim")
    table.add_column("IP", style="bold cyan")
    table.add_column("Identity", style="magenta")
    table.add_column("Model", style="blue")
    table.add_column("Arch", style="dim")
    table.add_column("Verze", justify="center")
    table.add_column("Cil", justify="center")
    table.add_column("Update?", justify="center")
    table.add_column("Net", justify="center")
    table.add_column("DNS", justify="center")
    table.add_column("HDD volno", justify="right")
    table.add_column("Vlna", justify="center", style="bold")
    table.add_column("Status", justify="center")

    for d in sorted(devices, key=ip_sort_key):
        needs_upd = d.get("needs_update")
        upd_str = "[bold red]ANO[/bold red]" if needs_upd else "[green]NE[/green]"

        has_net = d.get("has_internet")
        net_str = "[green]OK[/green]" if has_net else "[bold red]FAIL[/bold red]"

        has_dns = d.get("has_dns")
        dns_str = "[green]OK[/green]" if has_dns or has_dns is None else "[yellow]CHYBI[/yellow]"

        free_mb = round(d.get("free_hdd_bytes", 0) / (1024 * 1024), 1)
        hdd_str = f"{free_mb} MB"
        if free_mb < config.min_disk_free_mb:
            hdd_str = f"[bold red]{hdd_str}[/bold red]"

        status = d.get("status", "")
        status_color = "green" if status == "UPDATED" else ("red" if "FAIL" in status else "cyan")

        table.add_row(
            str(d.get("id")),
            d.get("ip", ""),
            d.get("identity") or "-",
            d.get("model") or "-",
            d.get("architecture") or "-",
            d.get("current_version") or "-",
            d.get("target_version") or "-",
            upd_str,
            net_str,
            dns_str,
            hdd_str,
            str(d.get("wave", 0)),
            f"[{status_color}]{status}[/{status_color}]",
        )

    console.print(table)
    csv_path = db.export_audit_csv()
    console.print(f"\nKompletni data vyexportovana do: [cyan]{csv_path}[/cyan]")


def cmd_update(config: Config, db: Database, args: argparse.Namespace) -> None:
    print_banner()
    updater = Updater(config, db)

    if args.dry_run:
        console.print("[bold yellow]*** REZIM SIMULACE (DRY-RUN) AKTIVOVAN ***[/bold yellow]\n")

    if args.ip:
        # Cileny update jednoho nebo vice zarizeni (oddelene carkou)
        raw_ips = [ip.strip() for ip in args.ip.split(",") if ip.strip()]
        devs_to_update = []
        for ip in raw_ips:
            dev = db.get_device_by_ip(ip)
            if not dev:
                console.print(f"[red]Zarizeni s IP {ip} nebylo nalezeno v databazi.[/red]")
            else:
                devs_to_update.append(dev)

        if not devs_to_update:
            return

        if len(devs_to_update) == 1:
            dev = devs_to_update[0]
            res = updater.upgrade_single_device(dev, dry_run=args.dry_run)
            status, detail = res if isinstance(res, tuple) else (str(res), "")
            color = "green" if status in ("UPDATED", "DRY_RUN_OK") else ("yellow" if status == "SKIPPED" else "red")
            console.print(f"Vysledek aktualizace pro {dev['ip']}: [{color}]{status}[/{color}] - {detail}")
        else:
            max_workers = args.workers if args.workers is not None else config.updater_workers
            effective_workers = min(max_workers, len(devs_to_update))
            console.print(f"[bold cyan]Spusteni aktualizace pro {len(devs_to_update)} vybranych zarizeni (soubezne: {effective_workers}):[/bold cyan]")
            from concurrent.futures import ThreadPoolExecutor, as_completed
            with ThreadPoolExecutor(max_workers=effective_workers) as executor:
                futures = {
                    executor.submit(updater.upgrade_single_device, dev, args.dry_run): dev
                    for dev in devs_to_update
                }
                completed_count = 0
                for fut in as_completed(futures):
                    dev = futures[fut]
                    completed_count += 1
                    try:
                        res = fut.result()
                    except Exception as e:
                        res = ("FAILED_UPGRADE", f"EXCEPTION: {e}")
                    status, detail = res if isinstance(res, tuple) else (str(res), "")
                    color = "green" if status in ("UPDATED", "DRY_RUN_OK") else ("yellow" if status == "SKIPPED" else "red")
                    tag = "  OK  " if status in ("UPDATED", "DRY_RUN_OK") else (" SKIP " if status == "SKIPPED" else "CHYBA ")
                    ident = (dev.get("identity") or dev.get("model") or "MikroTik")[:25]
                    console.print(f"  [{completed_count}/{len(devs_to_update)}] [{color}][{tag}][/{color}] {dev['ip']} ({ident}): {detail or status}")
    else:
        # Fazovany update podle vln
        updater.run_update_waves(target_wave=args.wave, dry_run=args.dry_run, workers=args.workers)

    csv_path = db.export_audit_csv()
    console.print(f"\nAktualizovany audit exportovan do: [cyan]{csv_path}[/cyan]")


def cmd_status(config: Config, db: Database, args: argparse.Namespace) -> None:
    print_banner()
    db.cleanup_stale_records()
    updater = Updater(config, db)
    latest_v6, latest_v7 = updater.get_latest_versions()
    db.refresh_target_versions(latest_v6, latest_v7)
    stats = db.get_statistics()

    total = stats.get("total", 0)
    if total == 0:
        console.print("[yellow]V databazi zatim nejsou zadna data. Pouzijte prikaz 'scan'.[/yellow]")
        return

    # 1. Tabulka zarizeni vyzadujicich aktualizaci
    outdated = [d for d in db.get_all_devices() if d.get("needs_update") and d.get("status") not in ("UPDATED",)]
    if outdated:
        out_table = Table(title=f"[bold red]Zarizeni vyzadujici aktualizaci ({len(outdated)})[/bold red]")
        out_table.add_column("IP", style="cyan", no_wrap=True)
        out_table.add_column("Identity", style="bold magenta")
        out_table.add_column("Model", style="blue")
        out_table.add_column("Verze aktualni", justify="center", style="red")
        out_table.add_column("Verze cilova", justify="center", style="green")
        out_table.add_column("Internet", justify="center")
        out_table.add_column("DNS", justify="center")
        out_table.add_column("Vlna", justify="center")
        out_table.add_column("Status", justify="center")

        for d in sorted(outdated, key=ip_sort_key):
            has_net = d.get("has_internet")
            net_str = "[green]OK[/green]" if has_net else "[bold red]FAIL[/bold red]"
            has_dns = d.get("has_dns")
            dns_str = "[green]OK[/green]" if has_dns or has_dns is None else "[yellow]CHYBI[/yellow]"
            status = d.get("status", "")
            s_color = "red" if "FAIL" in status else "yellow"
            out_table.add_row(
                d.get("ip", ""),
                d.get("identity") or "-",
                d.get("model") or "-",
                d.get("current_version") or "-",
                d.get("target_version") or "-",
                net_str,
                dns_str,
                str(d.get("wave", 0)),
                f"[{s_color}]{status}[/{s_color}]",
            )
        console.print(out_table)

    # 2. Tabulka aktualnich zarizeni (v poradku, nevyzaduji update)
    uptodate = [d for d in db.get_all_devices() if not d.get("needs_update") and d.get("status") in ("AUDITED", "UPDATED")]
    if uptodate:
        up_table = Table(title=f"[bold green]Aktualni zarizeni v poradku ({len(uptodate)})[/bold green]")
        up_table.add_column("IP", style="cyan", no_wrap=True)
        up_table.add_column("Identity", style="bold magenta")
        up_table.add_column("Model", style="blue")
        up_table.add_column("Verze", justify="center", style="bold green")
        up_table.add_column("Internet", justify="center")
        up_table.add_column("DNS", justify="center")
        up_table.add_column("Vlna", justify="center")
        up_table.add_column("Status", justify="center", style="green")

        for d in sorted(uptodate, key=ip_sort_key):
            has_net = d.get("has_internet")
            net_str = "[green]OK[/green]" if has_net else "[bold red]FAIL[/bold red]"
            has_dns = d.get("has_dns")
            dns_str = "[green]OK[/green]" if has_dns or has_dns is None else "[yellow]CHYBI[/yellow]"
            up_table.add_row(
                d.get("ip", ""),
                d.get("identity") or "-",
                d.get("model") or "-",
                d.get("current_version") or "-",
                net_str,
                dns_str,
                str(d.get("wave", 0)),
                d.get("status", "AUDITED"),
            )
        console.print(up_table)

    # 3. Tabulka zarizeni s chybou auth
    auth_failed = [d for d in db.get_all_devices() if d.get("status") == "AUTH_FAILED"]
    if auth_failed:
        af_table = Table(title=f"[bold yellow]Zarizeni s chybou prihlaseni ({len(auth_failed)})[/bold yellow]")
        af_table.add_column("IP", style="cyan", no_wrap=True)
        af_table.add_column("Duvod", style="dim")
        for d in sorted(auth_failed, key=ip_sort_key):
            af_table.add_row(d.get("ip", ""), d.get("last_error") or "AUTH_FAILED")
        console.print(af_table)

    # 4. Tabulka rozdeleni podle verzi
    v_table = Table(title="[bold cyan]Rozdeleni podle verzi RouterOS[/bold cyan]")
    v_table.add_column("Verze", style="magenta")
    v_table.add_column("Pocet", justify="right", style="bold")
    for ver_name, count in sorted(stats.get("versions", {}).items()):
        v_table.add_row(ver_name, str(count))
    console.print(v_table)

    # 5. Urgentni tabulka kompromitovanych routeru (pokud existuji)
    flagged_devs = [d for d in db.get_all_devices() if d.get("is_flagged")]
    if flagged_devs:
        fl_table = Table(title=f"[bold white on red] KRITICKE VAROVANI: Kompromitovana zarizeni ({len(flagged_devs)}) [/bold white on red]")
        fl_table.add_column("IP", style="bold cyan")
        fl_table.add_column("Identity", style="bold magenta")
        fl_table.add_column("Model", style="blue")
        fl_table.add_column("Verze", justify="center")
        fl_table.add_column("Duvod detekce (IoC)", style="bold red")
        for d in sorted(flagged_devs, key=ip_sort_key):
            fl_table.add_row(
                d.get("ip", ""),
                d.get("identity") or "-",
                d.get("model") or "-",
                d.get("current_version") or "-",
                d.get("flagged_reason") or "device-mode flagged=yes",
            )
        console.print(fl_table)

    # 6. Celkovy souhrnny prehled stavu site (na samotnem konci pro maximalni viditelnost)
    table = Table(title=f"[bold green]Celkovy prehled stavu site ISP (Cil: ROS v6={latest_v6} | ROS v7={latest_v7})[/bold green]")
    table.add_column("Metrika", style="cyan")
    table.add_column("Hodnota", justify="right", style="bold")

    table.add_row("Celkem evidovanych routeru", str(total))
    flagged_cnt = stats.get("flagged", 0)
    flag_str = f"[bold white on red] {flagged_cnt} (POZOR: MikroTrick/flagged) [/bold white on red]" if flagged_cnt > 0 else "[green]0 (V poradku)[/green]"
    table.add_row("Podezreni na kompromitaci (flagged/ops)", flag_str)
    table.add_row("Vyzaduje aktualizaci (zranitelne/stare)", f"[bold red]{stats.get('needs_update', 0)}[/bold red]")
    table.add_row("Uspesne aktualizovano (UPDATED)", f"[bold green]{stats.get('updated', 0)}[/bold green]")
    table.add_row("Selhala aktualizace (FAILED_UPGRADE)", f"[red]{stats.get('failed', 0)}[/red]")
    table.add_row("Preskoceno (chybi net / disk)", f"[yellow]{stats.get('skipped', 0)}[/yellow]")
    table.add_row("Overeny pristup k internetu", f"[green]{stats.get('has_internet', 0)}[/green]")
    table.add_row("Bez pristupu k internetu", f"[red]{stats.get('no_internet', 0)}[/red]")

    missing_dns = len([d for d in db.get_all_devices() if d.get("has_dns") is False])
    if missing_dns > 0:
        table.add_row("Chybejici DNS (doplni se pri updatu)", f"[bold yellow]{missing_dns}[/bold yellow]")

    console.print(table)


def cmd_run_all(config: Config, db: Database, args: argparse.Namespace) -> None:
    print_banner()
    console.print("[bold cyan]=== KROK 1: Skenovani a Audit ===[/bold cyan]")
    cmd_scan(config, db, args)
    console.print("\n[bold cyan]=== KROK 2: Mapovani Topologie a Vln ===[/bold cyan]")
    cmd_topology(config, db, args)
    console.print("\n[bold cyan]=== KROK 3: Fazovany Update ===[/bold cyan]")
    cmd_update(config, db, args)


def cmd_self_update(config: Config, db: Database, args: argparse.Namespace) -> None:
    print_banner()
    import subprocess
    console.print("[bold cyan]Aktualizace nastroje z GitHub repozitare...[/bold cyan]")
    base_dir = Path(__file__).resolve().parent
    try:
        res = subprocess.run(["git", "pull"], cwd=base_dir, capture_output=True, text=True)
        if res.returncode != 0:
            console.print(f"[bold red]Chyba pri 'git pull':[/bold red]\n{res.stderr.strip()}")
            return
        console.print(f"[green]{res.stdout.strip()}[/green]")

        venv_pip = base_dir / "venv" / "bin" / "pip"
        req_file = base_dir / "requirements.txt"
        if venv_pip.exists() and req_file.exists():
            console.print("[dim]Overeni a instalace pripadnych novych zavislosti...[/dim]")
            subprocess.run([str(venv_pip), "install", "-r", str(req_file), "--quiet"], cwd=base_dir)

        console.print("[bold green]Aktualizace probehla uspesne![/bold green]")
    except Exception as e:
        console.print(f"[bold red]Chyba pri aktualizaci: {e}[/bold red]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MikroTik ISP Manager - Hromadny audit, mapovani topologie a bezpecny fazovany update"
    )
    parser.add_argument(
        "--config",
        "-c",
        default="config.yaml",
        help="Cesta ke konfiguracnimu souboru (vychozi: config.yaml)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Dostupne prikazy")

    # scan
    subparsers.add_parser("scan", help="3fazovy sken: ICMP ping -> Port check -> SSH Auth/Audit")

    # topology
    topo_parser = subparsers.add_parser("topology", help="Sber sousedu a vypocet vln (Leaf -> Spine)")
    topo_parser.add_argument("--no-collect", action="store_true", help="Preskocit sber sousedu a pouze prepocitat vlny z dat v DB")

    # audit
    subparsers.add_parser("audit", help="Zobrazeni prehledne tabulky auditu a export do data/audit.csv")

    # update
    upd_parser = subparsers.add_parser("update", help="Spusteni bezpecneho fazovaneho updatu po vlnach")
    upd_parser.add_argument("--wave", "-w", type=int, default=None, help="Cislo konkretni vlny k aktualizaci")
    upd_parser.add_argument("--ip", type=str, default=None, help="IP konkretniho zarizeni (lze zadat i vice IP oddelenych carkou)")
    upd_parser.add_argument("--workers", type=int, default=None, help="Pocet soubeznych vlaken pro update (vychozi z config.yaml: 10)")
    upd_parser.add_argument("--dry-run", action="store_true", help="Simulace bez provedeni rebootu a instalace")

    # status
    subparsers.add_parser("status", help="Statisticky prehled stavu routeru a verzi v siti")

    # run-all
    all_parser = subparsers.add_parser("run-all", help="Kompletni pruchod: scan -> topology -> update")
    all_parser.add_argument("--workers", type=int, default=None, help="Pocet soubeznych vlaken pro update (vychozi z config.yaml: 10)")
    all_parser.add_argument("--dry-run", action="store_true", help="Simulace pro update fazi")

    # self-update
    subparsers.add_parser("self-update", help="Aktualizace nastroje z GitHub repozitare (git pull + venv pip)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Inicializace konfigurace a loggeru
    cfg = Config(args.config)
    setup_logger(cfg)

    # Validace konfigurace
    cfg_warnings = cfg.validate_config()
    for w in cfg_warnings:
        console.print(f"[bold yellow][VAROVANI KONFIGURACE][/bold yellow] {w}")
    if cfg_warnings:
        console.print("")

    db = Database(cfg.db_path)

    # Automaticky uklid databaze: odstraneni routeru, jejichz rozsah byl odebran z config.yaml
    removed = db.cleanup_networks(cfg.networks)
    if removed > 0:
        console.print(f"[yellow]Uklid DB: Odstraneno {removed} routeru, jejichz sit byla odebrana z {args.config}.[/yellow]\n")

    commands = {
        "scan": cmd_scan,
        "topology": cmd_topology,
        "audit": cmd_audit,
        "update": cmd_update,
        "status": cmd_status,
        "run-all": cmd_run_all,
        "self-update": cmd_self_update,
    }

    cmd_fn = commands.get(args.command)
    if cmd_fn:
        cmd_fn(cfg, db, args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

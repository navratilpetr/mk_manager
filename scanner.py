# Modul pro 3fazovy skener MikroTik routeru
import socket
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Set, Tuple, Optional
from netaddr import IPNetwork
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console

from config import Config
from database import Database
from auth import try_authenticate, audit_device

logger = logging.getLogger("mk_manager.scanner")
console = Console()


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    # Rychly ICMP ping test bez nutnosti raw socketu
    try:
        timeout_int = max(1, int(timeout))
        res = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout_int), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return False


def check_tcp_port(ip: str, port: int, timeout: float = 1.5) -> bool:
    # Rychly TCP test otevreneho portu
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


class Scanner:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db

    def generate_target_ips(self) -> List[str]:
        # Generovani unikatnich IP adres ze zadanych rozsahu s kontrolou bezpecne velikosti
        all_ips: Set[str] = set()
        for cidr in self.config.networks:
            try:
                network = IPNetwork(cidr)
                # Bezpecnostni kontrola: odmitnuti siti vetsich nez /16
                if network.prefixlen < 16:
                    msg = (
                        f"Rozsah '{cidr}' ma masku /{network.prefixlen} (cca {network.size:,} adres). "
                        f"Z bezpecnostnich duvodu jsou povoleny maximalne rozsahy /16 a mensi (/16 az /32). "
                        f"Tento rozsah byl preskocen, aby nedoslo k zahlceni pameti RAM."
                    )
                    logger.error(msg)
                    console.print(f"[bold red]VAROVANI: {msg}[/bold red]")
                    continue

                for ip in network.iter_hosts():
                    all_ips.add(str(ip))
            except Exception as e:
                logger.error(f"Chyba pri zpracovani rozsahu {cidr}: {e}")
        return sorted(list(all_ips))

    def phase1_ping_sweep(self, ip_list: List[str]) -> List[str]:
        # Faze 1: Paralelni ICMP ping sweep s davkovym zpracovanim (chunking)
        active_hosts: List[str] = []
        total = len(ip_list)
        logger.info(f"Zahajeni Faze 1: ICMP ping sweep na {total} adres")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Faze 1: ICMP Ping Sweep...", total=total)

            # Zpracovani po davkach (max 2000 adres najednou pro setreni pameti)
            chunk_size = 2000
            for i in range(0, total, chunk_size):
                chunk = ip_list[i:i + chunk_size]
                with ThreadPoolExecutor(max_workers=self.config.ping_threads) as executor:
                    futures = {executor.submit(ping_host, ip, self.config.ping_timeout): ip for ip in chunk}
                    for fut in as_completed(futures):
                        ip = futures[fut]
                        try:
                            if fut.result():
                                active_hosts.append(ip)
                        except Exception as e:
                            logger.debug(f"Chyba pingu pro {ip}: {e}")
                        finally:
                            progress.advance(task)

        logger.info(f"Faze 1 dokoncena: nalezeno {len(active_hosts)} aktivnich hostu")
        return active_hosts

    def phase2_port_check(self, active_hosts: List[str]) -> List[Dict[str, Any]]:
        # Faze 2: Kontrola otevrenych portu (SSH, Winbox, API)
        ssh_port = self.config.port_ssh
        winbox_port = self.config.port_winbox
        ssh_ports = self.config.ports_ssh
        winbox_ports = self.config.ports_winbox
        api_port = self.config.port_api
        results: List[Dict[str, Any]] = []

        total = len(active_hosts)
        logger.info(f"Zahajeni Faze 2: Kontrola TCP portu pro {total} zarizeni")

        def check_device_ports(ip: str) -> Dict[str, Any]:
            # Hledani otevreneho SSH portu (podpora 22 i alternativnich portu)
            found_ssh_port = None
            for p in ssh_ports:
                if check_tcp_port(ip, p, self.config.port_timeout):
                    found_ssh_port = p
                    break

            # Kontrola Winbox portu (podpora 8291, 33333 atd.)
            has_winbox = any(check_tcp_port(ip, p, self.config.port_timeout) for p in winbox_ports)
            has_api = check_tcp_port(ip, api_port, self.config.port_timeout)

            return {
                "ip": ip,
                "ssh": found_ssh_port is not None,
                "winbox": has_winbox,
                "api": has_api,
                "ssh_port": found_ssh_port if found_ssh_port else self.config.port_ssh,
            }

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[green]Faze 2: Kontrola TCP portu...", total=total)

            with ThreadPoolExecutor(max_workers=self.config.port_threads) as executor:
                futures = {executor.submit(check_device_ports, ip): ip for ip in active_hosts}
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        # Zarizeni je kandidatem na MikroTik POUZE pokud ma otevreny Winbox (8291, 33333) nebo API
                        if res["winbox"] or res["api"]:
                            results.append(res)
                    except Exception as e:
                        logger.debug(f"Chyba pri testu portu: {e}")
                    finally:
                        progress.advance(task)

        logger.info(f"Faze 2 dokoncena: {len(results)} zarizeni s MikroTik sluzbami (Winbox/API)")
        return results

    def phase3_auth_and_audit(
        self,
        candidate_devices: List[Dict[str, Any]],
        latest_v6: str,
        latest_v7: str
    ) -> List[Dict[str, Any]]:
        # Faze 3: Autentizace pres SSH a audit zarizeni
        # Striktni overeni: zarizeni musi mit otevreny Winbox nebo API A ZAROVEN SSH port
        ssh_candidates = [d for d in candidate_devices if (d.get("winbox") or d.get("api")) and d.get("ssh")]
        total = len(ssh_candidates)
        logger.info(f"Zahajeni Faze 3: SSH overovani a audit pro {total} kandidatu")
        audited_devices: List[Dict[str, Any]] = []

        def worker(dev: Dict[str, Any]) -> Optional[Dict[str, Any]]:
            ip = dev["ip"]
            port = dev.get("ssh_port", self.config.port_ssh)

            client, user, pwd, auth_err = try_authenticate(
                ip=ip,
                port=port,
                users=self.config.users,
                passwords=self.config.passwords,
                timeout=self.config.ssh_timeout
            )

            if not client:
                # Ulozeni zarizeni s neuspesnou autentizaci a presnym duvodem
                fail_data = {
                    "ip": ip,
                    "ssh_port": port,
                    "status": "AUTH_FAILED",
                    "last_error": auth_err or "Zadne funkcni heslo z matice",
                }
                self.db.upsert_device(fail_data)
                return None

            try:
                # Audit parametru
                audit_data = audit_device(client, ip, port, user, pwd)
                if not audit_data:
                    # Zarizeni neodpovedelo na prikazy RouterOS, nejedna se o MikroTik
                    return None

                # Centralni urceni target_version a needs_update
                curr_ver = audit_data.get("current_version", "")
                target_ver, needs_upd = evaluate_versions(curr_ver, latest_v6, latest_v7)
                audit_data["target_version"] = target_ver
                audit_data["needs_update"] = needs_upd

                # Ulozeni a deduplikace do SQLite
                self.db.upsert_device(audit_data)
                return audit_data
            except Exception as e:
                logger.error(f"Kriticka chyba pri auditu {ip}: {e}")
                return None
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("({task.completed}/{task.total})"),
            TimeRemainingColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[yellow]Faze 3: SSH Auth & Audit...", total=total)

            with ThreadPoolExecutor(max_workers=self.config.auth_threads) as executor:
                futures = {executor.submit(worker, dev): dev for dev in ssh_candidates}
                for fut in as_completed(futures):
                    try:
                        res = fut.result()
                        if res:
                            audited_devices.append(res)
                    except Exception as e:
                        logger.error(f"Chyba workeru Faze 3: {e}")
                    finally:
                        progress.advance(task)

        logger.info(f"Faze 3 dokoncena: uspesne zkontrolovano {len(audited_devices)} routeru")
        return audited_devices


def parse_version_tuple(version_str: str) -> Tuple[int, ...]:
    # Pomocna funkce pro bezpecne porovnavani cisel verzi (napr. 6.49.10 -> (6, 49, 10))
    parts = []
    clean = version_str.split()[0] if version_str else ""
    for seg in clean.split("."):
        try:
            parts.append(int(seg))
        except ValueError:
            # Pripadne rc/beta odstranit nebo aproximovat
            digits = "".join(filter(str.isdigit, seg))
            parts.append(int(digits) if digits else 0)
    return tuple(parts)


def evaluate_versions(current_ver: str, latest_v6: str, latest_v7: str) -> Tuple[str, bool]:
    # Pravidla aktualizace podle zadani:
    # v5 -> posledni v6
    # v6 -> posledni v6 (prechod na v7 prisne zakazan)
    # v7 -> posledni v7
    if not current_ver:
        return latest_v6, True

    curr_tuple = parse_version_tuple(current_ver)
    major = curr_tuple[0] if curr_tuple else 0

    if major <= 5:
        # ROS v5 vzdy vyzaduje update na posledni v6
        return latest_v6, True
    elif major == 6:
        # ROS v6 se aktualizuje pouze na posledni v6
        latest_tuple = parse_version_tuple(latest_v6)
        needs_upd = curr_tuple < latest_tuple
        return latest_v6, needs_upd
    elif major >= 7:
        # ROS v7 se aktualizuje na posledni v7
        latest_tuple = parse_version_tuple(latest_v7)
        needs_upd = curr_tuple < latest_tuple
        return latest_v7, needs_upd

    return latest_v6, True

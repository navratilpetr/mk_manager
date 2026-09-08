# Modul pro bezpecny fazovany update MikroTik routeru
import re
import time
import urllib.request
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional, Tuple
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

from config import Config
from database import Database
from auth import (
    create_ssh_connection,
    execute_ssh_command,
    audit_device,
    parse_key_value_output,
)
from scanner import ping_host, parse_version_tuple, evaluate_versions

logger = logging.getLogger("mk_manager.updater")
console = Console()


def parse_mikrotik_uptime(uptime_str: str) -> int:
    # Prevod MikroTik uptime retezce na sekundy
    if not uptime_str:
        return 999999
    s = uptime_str.strip().lower()

    if re.match(r"^\d{1,2}:\d{2}:\d{2}$", s):
        parts = s.split(":")
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])

    m_complex = re.match(r"^(?:(\d+)w)?(?:(\d+)d)?(?:(\d{1,2}):(\d{2}):(\d{2}))$", s)
    if m_complex:
        w = int(m_complex.group(1) or 0)
        d = int(m_complex.group(2) or 0)
        h = int(m_complex.group(3) or 0)
        m = int(m_complex.group(4) or 0)
        sec = int(m_complex.group(5) or 0)
        return w * 604800 + d * 86400 + h * 3600 + m * 60 + sec

    total = 0
    matches = re.findall(r"(\d+)([wdhms])", s)
    if matches:
        mult = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
        for val, unit in matches:
            total += int(val) * mult.get(unit, 1)
        return total

    return 999999


def fetch_latest_channel_version(url: str, fallback: str) -> str:
    # Zjisteni nejnovejsi verze z MikroTik update serveru
    if "NEWEST7.stable" in url:
        url = url.replace("NEWEST7.stable", "NEWESTa7.stable")
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "MikroTik-Manager/1.0"}
        )
        with urllib.request.urlopen(req, timeout=6.0) as resp:
            content = resp.read().decode("utf-8").strip()
            # Format odpovedi: "7.24.2 1788429434"
            parts = content.split()
            if parts:
                return parts[0]
    except Exception as e:
        logger.warning(f"Nelze nacist verzi z {url}: {e}. Pouzije se zalozni verze {fallback}")
    return fallback


def check_device_security(client: Any) -> Tuple[bool, Optional[str]]:
    # Kontrola bezpecnosti a kompromitace po upgradu (flagged: yes, ucet ops, exploit v logu)
    is_flagged = False
    reasons = []
    try:
        dm_raw = execute_ssh_command(client, "/system device-mode print", timeout=4.0)
        if dm_raw and re.search(r"flagged:\s*yes", dm_raw, re.IGNORECASE):
            is_flagged = True
            reasons.append("device-mode flagged=yes")
    except Exception:
        pass

    try:
        user_raw = execute_ssh_command(client, "/user print detail without-paging", timeout=4.0)
        if user_raw and re.search(r'name="?ops"?(\s+|$)', user_raw, re.IGNORECASE):
            is_flagged = True
            reasons.append("nalezen utocnicky ucet 'ops'")
    except Exception:
        pass

    try:
        log_raw = execute_ssh_command(client, '/log print without-paging where message~"-2"', timeout=4.0)
        if log_raw and ("user -2" in log_raw or "ssh:-2@" in log_raw):
            is_flagged = True
            reasons.append("detekovan exploit v logu (user -2)")
    except Exception:
        pass

    return is_flagged, (", ".join(reasons) if reasons else None)


class Updater:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db

    def get_latest_versions(self) -> Tuple[str, str]:
        # Nacteni aktualnich stabilnich verzi pro ROS v6 a v7
        v6 = fetch_latest_channel_version(self.config.channel_v6, fallback="6.49.21")
        v7 = fetch_latest_channel_version(self.config.channel_v7, fallback="7.24.2")
        logger.info(f"Aktualni MikroTik verze z kanalu: ROS v6={v6}, ROS v7={v7}")
        return v6, v7

    def _ensure_dns(self, client: Any, ip: str, dev_id: Optional[int] = None) -> None:
        # Kontrola a automaticke nastaveni DNS pokud router nema zadny DNS server
        try:
            dns_raw = execute_ssh_command(client, "/ip dns print without-paging")
            dns_data = parse_key_value_output(dns_raw)
            servers = dns_data.get("servers", "").strip()
            dyn_servers = dns_data.get("dynamic-servers", "").strip()

            if not servers and not dyn_servers:
                dns_str = ",".join(self.config.dns_servers)
                logger.info(f"{ip}: Router nema nastaveny DNS server, nastavuji zalozni DNS: {dns_str}")
                execute_ssh_command(client, f"/ip dns set servers={dns_str}")
                if dev_id:
                    self.db.update_device_dns(dev_id, has_dns=True, dns_servers=dns_str)
            else:
                if dev_id and (servers or dyn_servers):
                    self.db.update_device_dns(dev_id, has_dns=True, dns_servers=servers or dyn_servers)
        except Exception as e:
            logger.warning(f"{ip}: Nepodarilo se overit/nastavit DNS: {e}")

    def upgrade_single_device(self, device: Dict[str, Any], dry_run: bool = False) -> str:
        # Bezpecna aktualizace jednoho zarizeni s kontrolami a recovery
        ip = device["ip"]
        dev_id = device["id"]
        target_ver = device.get("target_version")
        user = device.get("username")
        pwd = device.get("password")
        port = dev_id and device.get("ssh_port", self.config.port_ssh)
        attempts = device.get("attempts", 0)

        logger.info(f"Zpracovani updatu pro {ip} (aktualni: {device.get('current_version')}, cil: {target_ver})")

        # 1. Kontrola internetoveho pripojeni
        if not device.get("has_internet"):
            msg = "Zarizeni nema pristup k internetu pro stazeni balicku"
            logger.warning(f"{ip}: {msg} - preskakovani")
            if not dry_run:
                self.db.update_device_status(dev_id, status="SKIPPED", error=msg)
            return "SKIPPED"

        # 2. Kontrola volneho mista na disku
        free_bytes = device.get("free_hdd_bytes", 0)
        min_bytes = int(self.config.min_disk_free_mb * 1024 * 1024)
        if free_bytes > 0 and free_bytes < min_bytes:
            free_mb = round(free_bytes / (1024 * 1024), 2)
            msg = f"Nedostatek mista na flash disku: {free_mb} MB (minimum: {self.config.min_disk_free_mb} MB)"
            logger.error(f"{ip}: {msg} - preskakovani")
            if not dry_run:
                self.db.update_device_status(dev_id, status="SKIPPED", error=msg)
            return "SKIPPED"

        # V rezimu dry-run simulujeme uspesny test bez odeslani prikazu
        if dry_run:
            logger.info(f"[DRY-RUN] {ip}: Simulace overeni a pripravenosti na upgrade probehla v poradku")
            return "DRY_RUN_OK"

        # 3. Predbezna kontrola verze pred zahajenim updatu
        if device.get("status") not in ("IN_PROGRESS", "UPDATING"):
            client_init = create_ssh_connection(ip, port, user, pwd, timeout=self.config.ssh_timeout)
            if client_init:
                try:
                    res_raw = execute_ssh_command(client_init, "/system resource print")
                    res_data = parse_key_value_output(res_raw)
                    live_ver = res_data.get("version", "").split()[0]
                    if live_ver == target_ver:
                        logger.info(f"{ip}: Router jiz bezi na cilove verzi {live_ver} - update neni nutny")
                        try:
                            rb_raw = execute_ssh_command(client_init, "/system routerboard print")
                            rb_data = parse_key_value_output(rb_raw)
                            cur_fw = rb_data.get("current-firmware")
                            upg_fw = rb_data.get("upgrade-firmware")
                            if cur_fw and upg_fw and cur_fw != upg_fw:
                                logger.info(f"{ip}: Aktualizace RouterBOOT firmware z {cur_fw} na {upg_fw}...")
                                execute_ssh_command(client_init, "/system routerboard upgrade")
                        except Exception:
                            pass

                        is_flag, flag_reason = check_device_security(client_init)
                        self.db.update_device_status(
                            dev_id,
                            status="UPDATED",
                            current_version=live_ver,
                            needs_update=False,
                            is_flagged=is_flag,
                            flagged_reason=flag_reason
                        )
                        return "UPDATED"
                except Exception as e:
                    logger.debug(f"{ip}: Nelze overit vychozi verzi: {e}")
                finally:
                    try:
                        client_init.close()
                    except Exception:
                        pass

        # 4. Samotny upgrade cyklus (max MAX_UPGRADE_ATTEMPTS)
        while attempts < self.config.max_attempts:
            attempts += 1
            self.db.update_device_status(dev_id, status="UPDATING", attempts=attempts)

            client = create_ssh_connection(ip, port, user, pwd, timeout=self.config.ssh_timeout)
            if not client:
                msg = "Nelze navazat SSH spojeni pred zahajenim updatu"
                logger.error(f"{ip}: {msg}")
                self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=msg)
                return "FAILED_UPGRADE"

            try:
                # A) Kontrola a automaticke nastaveni DNS pokud na routeru chybi
                self._ensure_dns(client, ip, dev_id)

                # B) Nastaveni kanalu a kontrola aktualizaci
                logger.info(f"{ip} (pokus {attempts}/{self.config.max_attempts}): Kontrola a stahovani updatu...")
                execute_ssh_command(client, "/system package update set channel=stable")
                chk_raw = execute_ssh_command(client, "/system package update check-for-updates once")
                time.sleep(2.0)

                # Overeni dostupnosti serveru
                upd_pr_raw = execute_ssh_command(client, "/system package update print without-paging")
                upd_pr = parse_key_value_output(upd_pr_raw)
                upd_status = upd_pr.get("status", "")
                if "ERROR" in upd_status.upper() or "ERROR" in chk_raw.upper():
                    err_msg = upd_status or chk_raw.strip()
                    logger.error(f"{ip}: Chyba pri kontrole aktualizaci na MikroTik serveru: {err_msg}")
                    self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=f"Chyba update: {err_msg}")
                    return "FAILED_UPGRADE"

                # C) Spusteni instalace (zahaji stahovani balicku a nasledny reboot)
                try:
                    stdin, stdout, stderr = client.exec_command("/system package update install", timeout=10.0)
                    time.sleep(1.0)
                    err_out = ""
                    if stdout.channel.recv_ready():
                        err_out += stdout.channel.recv(4096).decode("latin-1", errors="ignore")
                    if stderr.channel.recv_stderr_ready():
                        err_out += stderr.channel.recv_stderr(4096).decode("latin-1", errors="ignore")

                    if "bad command name" in err_out.lower() or "syntax error" in err_out.lower():
                        logger.info(f"{ip}: Router nepodporuje 'update install' (legacy verze), pouzivam stazeni pres /tool fetch...")
                        arch = device.get("architecture")
                        if not arch:
                            res_tmp = execute_ssh_command(client, "/system resource print")
                            arch = parse_key_value_output(res_tmp).get("architecture-name", "mipsbe")

                        pkg_name = f"routeros-{arch}-{target_ver}.npk"
                        logger.info(f"{ip}: Stahovani balicku {pkg_name} pres /tool fetch...")
                        fetch_cmd = f'/tool fetch url="http://upgrade.mikrotik.com/routeros/{target_ver}/{pkg_name}" mode=http'
                        execute_ssh_command(client, fetch_cmd, timeout=180.0)
                        time.sleep(2.0)

                        files_list = execute_ssh_command(client, "/file print")
                        if pkg_name in files_list or "routeros" in files_list:
                            logger.info(f"{ip}: Balicek uspesne stazen do uloziste, provadim restart routeru...")
                            execute_ssh_command(client, '/system script add name=reboot-upgrade source="/system reboot" policy=reboot,read,write')
                            try:
                                client.exec_command("/system script run reboot-upgrade", timeout=3.0)
                            except Exception:
                                pass
                        else:
                            msg = f"Nepodarilo se stahnout balicek {pkg_name}"
                            logger.error(f"{ip}: {msg}")
                            self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=msg)
                            return "FAILED_UPGRADE"
                except Exception as e:
                    logger.warning(f"{ip}: Chyba pri odesilani update prikazu: {e}")
            finally:
                try:
                    client.close()
                except Exception:
                    pass

            # 5. Cekani na stahovani, reboot a nabehnuti noveho systemu
            logger.info(f"{ip}: Prikaz odeslan, cekani na stazeni balicku a reboot (max {self.config.max_recovery_timeout}s)...")
            start_time = time.time()
            reboot_detected = False
            recovered = False

            while (time.time() - start_time) < self.config.max_recovery_timeout:
                time.sleep(self.config.ping_retry_interval)
                elapsed = int(time.time() - start_time)
                is_ping_ok = ping_host(ip, timeout=1.5)

                if not is_ping_ok:
                    if not reboot_detected:
                        logger.info(f"{ip}: Router se restartuje (ubehlo {elapsed}s)...")
                        reboot_detected = True
                    continue

                # Pokud ping odpovida, proverime stav pres SSH
                client_chk = create_ssh_connection(ip, port, user, pwd, timeout=4.0)
                if not client_chk:
                    # SSH jeste nenabehlo nebo router prave restartuje
                    continue

                try:
                    res_raw = execute_ssh_command(client_chk, "/system resource print")
                    res_data = parse_key_value_output(res_raw)
                    curr_check_ver = res_data.get("version", "").split()[0]
                    curr_uptime_sec = parse_mikrotik_uptime(res_data.get("uptime", ""))

                    # 1. Pokud jiz bezi cilova verze -> update uspesny
                    if curr_check_ver == target_ver:
                        logger.info(f"{ip}: Detekovana nova cilova verze {curr_check_ver}!")
                        recovered = True
                        break

                    # 2. Pokud ma router stale starou verzi, proverime uptime a stav stahovani
                    if curr_uptime_sec > (elapsed + 30):
                        # Dotaz na aktualni stav balicku
                        pkg_raw = execute_ssh_command(client_chk, "/system package update print without-paging", timeout=4.0)
                        pkg_data = parse_key_value_output(pkg_raw)
                        pkg_status = pkg_data.get("status", "")
                        if "ERROR" in pkg_status.upper():
                            logger.error(f"{ip}: Stahovani balicku selhalo: {pkg_status}")
                            self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=f"Chyba stahovani: {pkg_status}")
                            return "FAILED_UPGRADE"

                        status_info = f", stav: {pkg_status}" if pkg_status else ""
                        logger.info(f"{ip}: Router stahuje balicky a ceka na reboot (uptime: {res_data.get('uptime')}, ubehlo {elapsed}s{status_info})...")
                        continue
                    else:
                        # Router skutecne rebootoval, ale nabehl s meziverzi
                        logger.warning(f"{ip}: Router po restartu nabehl s verzi {curr_check_ver} (uptime: {res_data.get('uptime')})")
                        recovered = True
                        break
                except Exception:
                    pass
                finally:
                    try:
                        client_chk.close()
                    except Exception:
                        pass

            if not recovered:
                msg = f"Router nedokoncil update/reboot do {self.config.max_recovery_timeout}s"
                logger.critical(f"{ip}: {msg}!")
                self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=msg)
                return "FAILED_UPGRADE"

            # 6. Kontrola stavu, firmwaru a finalizace po rebootu
            time.sleep(3)
            client_after = create_ssh_connection(ip, port, user, pwd, timeout=self.config.ssh_timeout)
            if not client_after:
                msg = "Zarizeni odpovida na ping, ale SSH neodpovida"
                logger.error(f"{ip}: {msg}")
                self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=msg)
                return "FAILED_UPGRADE"

            try:
                # Vycteni nove verze
                res_raw = execute_ssh_command(client_after, "/system resource print")
                res_data = parse_key_value_output(res_raw)
                new_ver = res_data.get("version", "").split()[0]

                # Upgrade RouterBOOT firmware pokud je k dispozici novejsi
                rb_raw = execute_ssh_command(client_after, "/system routerboard print")
                rb_data = parse_key_value_output(rb_raw)
                cur_fw = rb_data.get("current-firmware")
                upg_fw = rb_data.get("upgrade-firmware")

                if cur_fw and upg_fw and cur_fw != upg_fw:
                    logger.info(f"{ip}: Aktualizace RouterBOOT firmware z {cur_fw} na {upg_fw}...")
                    execute_ssh_command(client_after, "/system routerboard upgrade")

                # Porovnani verze
                is_target = (new_ver == target_ver)
                needs_more = parse_version_tuple(new_ver) < parse_version_tuple(target_ver)

                if is_target or not needs_more:
                    logger.info(f"{ip}: Uspesne aktualizovan na cilovou verzi {new_ver}")
                    # Bezpecnostni test po dokonceni aktualizace (flagged: yes, ops)
                    is_flag, flag_reason = check_device_security(client_after)
                    if is_flag:
                        logger.critical(f"{ip}: POZOR! Zarizeni je po aktualizaci kompromitovano: {flag_reason}")
                        console.print(f"[bold white on red]KRITICKE VAROVANI: {ip} byl po aktualizaci detekovan jako KOMPROMITOVANY ({flag_reason})![/bold white on red]")
                    else:
                        logger.info(f"{ip}: Bezpecnostni kontrola v poradku (flagged: no, zadny neznamy ucet)")

                    self.db.update_device_status(
                        dev_id,
                        status="UPDATED",
                        current_version=new_ver,
                        needs_update=False,
                        attempts=attempts,
                        is_flagged=is_flag,
                        flagged_reason=flag_reason
                    )
                    return "UPDATED"
                else:
                    logger.warning(f"{ip}: Dosazena meziverze {new_ver} (cil: {target_ver})")
                    self.db.update_device_status(
                        dev_id,
                        status="IN_PROGRESS",
                        current_version=new_ver,
                        needs_update=True,
                        attempts=attempts
                    )
                    # Pokracuje se v cyklu dalsim pokusem (mezikrok)
            except Exception as e:
                logger.error(f"{ip}: Chyba pri overovani po upgradu: {e}")
            finally:
                try:
                    client_after.close()
                except Exception:
                    pass

        # Prekrocen pocet pokusu
        fail_msg = f"Prekrocen maximalni pocet pokusu ({self.config.max_attempts}) bez dosazeni cilove verze"
        logger.error(f"{ip}: {fail_msg}")
        self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=fail_msg)
        return "FAILED_UPGRADE"

    def run_update_waves(
        self,
        target_wave: Optional[int] = None,
        dry_run: bool = False,
        workers: Optional[int] = None,
    ) -> None:
        # Spusteni fazovaneho updatu podle vln
        stats = self.db.get_statistics()
        wave_dist = stats.get("waves", {})
        if not wave_dist:
            console.print("[yellow]Nebyly nalezeny zadne vlny. Spustte nejprve 'topology'.[/yellow]")
            return

        sorted_waves = sorted(wave_dist.keys())
        if target_wave is not None:
            if target_wave not in sorted_waves:
                console.print(f"[red]Zadana vlna {target_wave} neexistuje.[/red]")
                return
            sorted_waves = [target_wave]

        max_workers = workers if workers is not None else self.config.updater_workers
        if max_workers < 1:
            max_workers = 1

        console.print(f"[bold cyan]Spusteni fazovaneho updatu (celkem vln: {len(sorted_waves)}, soubeznych pracovniku: {max_workers})[/bold cyan]")

        for wave in sorted_waves:
            devices = self.db.get_all_devices(wave=wave)
            # Filtrovat pouze zarizeni vyzadujici update a seradit numericky podle IP
            to_update = [d for d in devices if d.get("needs_update")]
            to_update.sort(key=lambda d: [int(p) for p in d["ip"].split(".") if p.isdigit()] or [0])

            effective_workers = min(max_workers, len(to_update)) if to_update else 1
            console.print(f"\n[bold yellow]=== Zahajeni Vlny {wave} ({len(to_update)} zarizeni k aktualizaci z {len(devices)}, soubezne: {effective_workers}) ===[/bold yellow]")
            if not to_update:
                console.print(f"[green]Ve vlne {wave} jiz vsechna zarizeni odpovidaji cilove verzi.[/green]")
                continue

            if effective_workers > 1:
                with ThreadPoolExecutor(max_workers=effective_workers) as executor:
                    futures = {
                        executor.submit(self.upgrade_single_device, dev, dry_run): dev
                        for dev in to_update
                    }
                    for fut in as_completed(futures):
                        dev = futures[fut]
                        try:
                            res = fut.result()
                        except Exception as e:
                            res = f"EXCEPTION: {e}"
                        color = "green" if res in ("UPDATED", "DRY_RUN_OK") else ("yellow" if res == "SKIPPED" else "red")
                        console.print(f"  [{color}]* {dev['ip']} ({dev.get('identity')}): {res}[/{color}]")
            else:
                for dev in to_update:
                    res = self.upgrade_single_device(dev, dry_run=dry_run)
                    color = "green" if res in ("UPDATED", "DRY_RUN_OK") else ("yellow" if res == "SKIPPED" else "red")
                    console.print(f"  [{color}]* {dev['ip']} ({dev.get('identity')}): {res}[/{color}]")

            console.print(f"[bold green]=== Vlna {wave} dokoncena ===[/bold green]")

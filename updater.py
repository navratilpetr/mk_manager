# Modul pro bezpecny fazovany update MikroTik routeru
import re
import time
import urllib.request
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from typing import Dict, Any, List, Optional, Tuple
from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
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


def check_device_security(client: Any) -> Tuple[bool, Optional[str], Optional[str]]:
    # Kontrola bezpecnosti a kompromitace po upgradu
    # Vraci: (is_flagged, flagged_reason, security_notice)
    is_flagged = False
    reasons = []
    notice = None
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
        if log_raw:
            if "added by ssh:-2" in log_raw or re.search(r"logged in.*(-2|ssh:-2)", log_raw, re.IGNORECASE):
                is_flagged = True
                reasons.append("potvrzeny prunik v logu: ucet/pristup pres ssh:-2")
            elif "user -2" in log_raw or "ssh:-2@" in log_raw:
                notice = "neuspesny pokus o exploit v logu (login failure user -2 - odrazeno)"
    except Exception:
        pass

    return is_flagged, (", ".join(reasons) if reasons else None), notice


class Updater:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db
        self._waiting_lock = threading.Lock()
        self._waiting_devices: Dict[str, Dict[str, Any]] = {}

    def _register_waiting(self, ip: str, identity: str, timeout: int) -> None:
        # Registrace routeru cekajiciho na reboot pro live zobrazeni
        with self._waiting_lock:
            self._waiting_devices[ip] = {
                "identity": identity,
                "start": time.time(),
                "timeout": timeout,
            }

    def _unregister_waiting(self, ip: str) -> None:
        # Odregistrace routeru po dokonceni nabehnuti
        with self._waiting_lock:
            self._waiting_devices.pop(ip, None)

    def _get_waiting_status_str(self) -> str:
        # Sestaveni textu se zivym poctem vterin pro stavovy radek
        with self._waiting_lock:
            if not self._waiting_devices:
                return ""
            now = time.time()
            items = []
            for ip, info in list(self._waiting_devices.items()):
                elapsed = int(now - info["start"])
                timeout = info["timeout"]
                ident = info["identity"][:15]
                items.append(f"{ip} ({ident}, {elapsed}s/{timeout}s)")
            if len(items) <= 2:
                return " | Ceka na reboot: " + ", ".join(items)
            else:
                return f" | Ceka na reboot ({len(items)} routeru, napr. {items[0]})"

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

    def upgrade_single_device(self, device: Dict[str, Any], dry_run: bool = False) -> Tuple[str, str]:
        # Bezpecna aktualizace jednoho zarizeni s kontrolami a recovery
        ip = device["ip"]
        dev_id = device["id"]
        target_ver = device.get("target_version")
        user = device.get("username")
        pwd = device.get("password")
        port = dev_id and device.get("ssh_port", self.config.port_ssh)
        attempts = device.get("attempts", 0)

        logger.info(f"Zpracovani updatu pro {ip} (aktualni: {device.get('current_version')}, cil: {target_ver})")

        # 1. Kontrola volneho mista na disku
        free_bytes = device.get("free_hdd_bytes", 0)
        min_bytes = int(self.config.min_disk_free_mb * 1024 * 1024)
        if free_bytes > 0 and free_bytes < min_bytes:
            free_mb = round(free_bytes / (1024 * 1024), 2)
            msg = f"Nedostatek mista na flash disku: {free_mb} MB (minimum: {self.config.min_disk_free_mb} MB)"
            logger.error(f"{ip}: {msg} - preskakovani")
            if not dry_run:
                self.db.update_device_status(dev_id, status="SKIPPED", error=msg)
            return "SKIPPED", msg

        # V rezimu dry-run simulujeme uspesny test bez odeslani prikazu
        if dry_run:
            logger.info(f"[DRY-RUN] {ip}: Simulace overeni a pripravenosti na upgrade probehla v poradku")
            return "DRY_RUN_OK", "Simulace overeni v poradku"

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

                        is_flag, flag_reason, sec_notice = check_device_security(client_init)
                        self.db.update_device_status(
                            dev_id,
                            status="UPDATED",
                            current_version=live_ver,
                            needs_update=False,
                            is_flagged=is_flag,
                            flagged_reason=flag_reason,
                            security_notice=sec_notice
                        )
                        return "UPDATED", f"Jiz bezi na cilove verzi {live_ver}"
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
                return "FAILED_UPGRADE", msg

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
                    logger.warning(f"{ip}: Router se nemuze spojit s MikroTik update serverem: {err_msg}")
                    self.db.update_device_status(dev_id, status="SKIPPED", attempts=attempts, error=f"Nelze spojit s update serverem: {err_msg}", has_internet=False)
                    return "SKIPPED", f"Nelze spojit s update serverem ({err_msg})"

                # Router uspesne navazal spojeni se serverem - internet je funkcni
                self.db.update_device_status(dev_id, has_internet=True)

                # C) Spusteni instalace (zahaji stahovani balicku a nasledny reboot)
                try:
                    # 1. Zkusime moderni prikaz 'install' (RouterOS 6.36+ a RouterOS v7)
                    stdin, stdout, stderr = client.exec_command("/system package update install", timeout=10.0)
                    time.sleep(1.0)
                    err_out = ""
                    if stdout.channel.recv_ready():
                        err_out += stdout.channel.recv(4096).decode("latin-1", errors="ignore")
                    if stderr.channel.recv_stderr_ready():
                        err_out += stderr.channel.recv_stderr(4096).decode("latin-1", errors="ignore")

                    # 2. Pokud router nepodporuje 'install', zkusime starsi prikaz 'upgrade' (RouterOS <= 6.35)
                    if "bad command name" in err_out.lower() or "syntax error" in err_out.lower():
                        logger.info(f"{ip}: Router nepodporuje 'install' (ROS <= 6.35), zkousim legacy prikaz 'upgrade'...")
                        stdin, stdout, stderr = client.exec_command("/system package update upgrade", timeout=10.0)
                        time.sleep(1.0)
                        err_out = ""
                        if stdout.channel.recv_ready():
                            err_out += stdout.channel.recv(4096).decode("latin-1", errors="ignore")
                        if stderr.channel.recv_stderr_ready():
                            err_out += stderr.channel.recv_stderr(4096).decode("latin-1", errors="ignore")

                    # 3. Pokud router nepodporuje ani 'upgrade' (napr. ROS v5), pouzijeme stazeni pres /tool fetch
                    if "bad command name" in err_out.lower() or "syntax error" in err_out.lower():
                        logger.info(f"{ip}: Router nepodporuje 'package update' (legacy verze), pouzivam stazeni pres /tool fetch...")
                        arch = device.get("architecture")
                        if not arch:
                            res_tmp = execute_ssh_command(client, "/system resource print", timeout=5.0)
                            arch = parse_key_value_output(res_tmp).get("architecture-name", "mipsbe")

                        pkg_name = f"routeros-{arch}-{target_ver}.npk"
                        logger.info(f"{ip}: Stahovani balicku {pkg_name} pres /tool fetch...")
                        fetch_cmd = f'/tool fetch url="http://upgrade.mikrotik.com/routeros/{target_ver}/{pkg_name}" mode=http'
                        execute_ssh_command(client, fetch_cmd, timeout=120.0)
                        time.sleep(2.0)

                        files_list = execute_ssh_command(client, "/file print detail", timeout=5.0)
                        if pkg_name in files_list:
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
                            return "FAILED_UPGRADE", msg
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
            dev_ident = (device.get("identity") or device.get("model") or "MikroTik")
            self._register_waiting(ip, dev_ident, self.config.max_recovery_timeout)

            try:
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
                        res_raw = execute_ssh_command(client_chk, "/system resource print", timeout=5.0)
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
                                return "FAILED_UPGRADE", f"Chyba stahovani: {pkg_status}"

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
            finally:
                self._unregister_waiting(ip)

            if not recovered:
                msg = f"Router nedokoncil update/reboot do {self.config.max_recovery_timeout}s"
                logger.critical(f"{ip}: {msg}!")
                self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=msg)
                return "FAILED_UPGRADE", msg

            # 6. Kontrola stavu, firmwaru a finalizace po rebootu
            time.sleep(3)
            client_after = create_ssh_connection(ip, port, user, pwd, timeout=self.config.ssh_timeout)
            if not client_after:
                msg = "Zarizeni odpovida na ping, ale SSH neodpovida"
                logger.error(f"{ip}: {msg}")
                self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=msg)
                return "FAILED_UPGRADE", msg

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

                needs_post_reboot = False
                reboot_reasons = []

                if cur_fw and upg_fw and cur_fw != upg_fw:
                    logger.info(f"{ip}: Aktualizace RouterBOOT firmware z {cur_fw} na {upg_fw}...")
                    execute_ssh_command(client_after, "/system routerboard upgrade")
                    needs_post_reboot = True
                    reboot_reasons.append(f"RouterBOOT ({cur_fw} -> {upg_fw})")

                # Kontrola chyby poskozeneho SSH host klice v logu
                log_ssh = execute_ssh_command(client_after, '/log print without-paging where topics~"ssh"')
                if "corrupt host" in log_ssh.lower() or "regenerating it" in log_ssh.lower():
                    logger.warning(f"{ip}: Detekovan poskozeny SSH host klic v logu, vyvolavam regeneraci...")
                    try:
                        execute_ssh_command(client_after, '/system script add name=regen-ssh source="/ip ssh regenerate-host-key"')
                        execute_ssh_command(client_after, '/system script run regen-ssh')
                        execute_ssh_command(client_after, '/system script remove [find name="regen-ssh"]')
                    except Exception as e:
                        logger.error(f"{ip}: Chyba pri regeneraci SSH klice: {e}")
                    needs_post_reboot = True
                    reboot_reasons.append("regenerace SSH klice")

                # Pokud byl zmenen RouterBOOT nebo regenerovan SSH klic, provedeme restart pro aplikaci zmen
                if needs_post_reboot:
                    reason_desc = " a ".join(reboot_reasons)
                    logger.info(f"{ip}: Restart routeru pro aplikaci: {reason_desc}...")
                    try:
                        execute_ssh_command(client_after, '/system script add name=reboot-post source="/system reboot"')
                        client_after.exec_command("/system script run reboot-post", timeout=2.0)
                    except Exception:
                        pass
                    try:
                        client_after.close()
                    except Exception:
                        pass
                    client_after = None

                    # Cekani na dokonceni restartu a nabehnuti SSH
                    self._register_waiting(ip, dev_ident, 180)
                    try:
                        time.sleep(15)
                        post_reboot_recovered = False
                        p_start = time.time()
                        while (time.time() - p_start) < 180:
                            time.sleep(5)
                            if ping_host(ip, timeout=1.5):
                                c_test = create_ssh_connection(ip, port, user, pwd, timeout=4.0)
                                if c_test:
                                    client_after = c_test
                                    post_reboot_recovered = True
                                    break
                    finally:
                        self._unregister_waiting(ip)

                    if post_reboot_recovered and client_after:
                        logger.info(f"{ip}: Router po restartu ({reason_desc}) v poradku nabehl.")
                        try:
                            execute_ssh_command(client_after, '/system script remove [find name="reboot-post"]')
                        except Exception:
                            pass
                    else:
                        logger.warning(f"{ip}: Router po restartu ({reason_desc}) neodpovedel vcas na SSH.")

                # Porovnani verze
                is_target = (new_ver == target_ver)
                needs_more = parse_version_tuple(new_ver) < parse_version_tuple(target_ver)

                if is_target or not needs_more:
                    logger.info(f"{ip}: Uspesne aktualizovan na cilovou verzi {new_ver}")
                    # Bezpecnostni test po dokonceni aktualizace (flagged: yes, ops)
                    is_flag = False
                    flag_reason = None
                    sec_notice = None
                    if client_after:
                        is_flag, flag_reason, sec_notice = check_device_security(client_after)
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
                        flagged_reason=flag_reason,
                        security_notice=sec_notice
                    )
                    return "UPDATED", f"Aktualizovano na {new_ver}"
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
                if client_after is not None:
                    try:
                        client_after.close()
                    except Exception:
                        pass

        # Prekrocen pocet pokusu
        fail_msg = f"Prekrocen maximalni pocet pokusu ({self.config.max_attempts}) bez dosazeni cilove verze"
        logger.error(f"{ip}: {fail_msg}")
        self.db.update_device_status(dev_id, status="FAILED_UPGRADE", attempts=attempts, error=fail_msg)
        return "FAILED_UPGRADE", fail_msg

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

        # Spocitani zarizeni k aktualizaci napric vlnami
        all_to_update: Dict[int, List[Dict[str, Any]]] = {}
        total_to_update = 0
        for wave in sorted_waves:
            devs = self.db.get_all_devices(wave=wave)
            w_upd = [d for d in devs if d.get("needs_update")]
            w_upd.sort(key=lambda d: [int(p) for p in d["ip"].split(".") if p.isdigit()] or [0])
            all_to_update[wave] = w_upd
            total_to_update += len(w_upd)

        console.print(f"[bold cyan]Spusteni fazovaneho updatu (celkem vln: {len(sorted_waves)}, k aktualizaci: {total_to_update}, soubeznych pracovniku: {max_workers})[/bold cyan]")

        if total_to_update == 0:
            console.print("[bold green]Vsechna zarizeni v siti jiz odpovidaji cilove verzi, zadna aktualizace neni nutna.[/bold green]")
            return

        # Odhad casu dokonceni pouze pri vetsim poctu zarizeni (50+)
        if total_to_update >= 50:
            total_est_seconds = 0
            for wave in sorted_waves:
                w_count = len(all_to_update[wave])
                if w_count > 0:
                    eff = min(max_workers, w_count)
                    batches = (w_count + eff - 1) // eff
                    total_est_seconds += batches * 150

            est_minutes = max(1, round(total_est_seconds / 60))
            if est_minutes >= 60:
                h = est_minutes // 60
                m = est_minutes % 60
                est_str = f"{h} h {m} min"
            else:
                est_str = f"cca {est_minutes} min"

            console.print(f"[bold yellow]Odhadovany cas dokonceni cele site: {est_str} (pocitano pro {total_to_update} zarizeni pri prumeru 2.5 min/zarizeni)[/bold yellow]")

        # Potlaceni verbose logu z konzole behem updatu (vsechny detaily zustavaji v souboru mk_manager.log)
        root_logger = logging.getLogger("mk_manager")
        rich_handlers = [h for h in root_logger.handlers if isinstance(h, RichHandler)]
        orig_levels = {h: h.level for h in rich_handlers}
        for h in rich_handlers:
            h.setLevel(logging.CRITICAL)

        total_ok = 0
        total_skipped = 0
        total_failed = 0
        all_failed_summary: List[Tuple[Dict[str, Any], str, int]] = []

        try:
            for wave in sorted_waves:
                devices = self.db.get_all_devices(wave=wave)
                raw_to_update = all_to_update.get(wave, [])

                # Deduplikace zarizeni v ramci vlny (ochrana proti dvojitemu updatu tehoz routeru s vice IP)
                seen_sns = set()
                seen_macs = set()
                seen_ips = set()
                to_update = []
                for d in raw_to_update:
                    sn = d.get("serial_number")
                    mac = d.get("mac")
                    ip = d.get("ip")
                    if sn and sn.strip() and sn.strip().lower() not in ("none", "null", "unknown", "") and sn in seen_sns:
                        continue
                    if mac and mac.strip() and mac.strip().upper() not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", "") and mac in seen_macs:
                        continue
                    if ip and ip in seen_ips:
                        continue
                    if sn and sn.strip() and sn.strip().lower() not in ("none", "null", "unknown", ""):
                        seen_sns.add(sn)
                    if mac and mac.strip() and mac.strip().upper() not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", ""):
                        seen_macs.add(mac)
                    if ip:
                        seen_ips.add(ip)
                    to_update.append(d)

                total_wave = len(to_update)

                if not to_update:
                    continue

                effective_workers = min(max_workers, total_wave)
                console.print(f"\n[bold yellow]=== Zahajeni Vlny {wave} ({total_wave} zarizeni k aktualizaci z {len(devices)}, soubezne: {effective_workers}) ===[/bold yellow]")

                initial_batch = [f"{d['ip']} ({(d.get('identity') or d.get('model') or 'MikroTik')[:25]})" for d in to_update[:effective_workers]]
                console.print(f"  [cyan]-> Zahajeno zpracovani prvnich {len(initial_batch)} zarizeni (stahovani a restart routeru, cca 1.5 - 3 min):[/cyan]")
                for dev_str in initial_batch:
                    console.print(f"     [dim]• {dev_str}[/dim]")

                completed_count = 0
                wave_ok = 0
                wave_skipped = 0
                wave_failed = 0
                failed_in_wave: List[Tuple[Dict[str, Any], str]] = []

                def process_result(dev: Dict[str, Any], res: Any):
                    nonlocal completed_count, wave_ok, wave_skipped, wave_failed
                    completed_count += 1
                    status, detail = res if isinstance(res, tuple) else (str(res), "")
                    ip = dev["ip"]
                    ident = (dev.get("identity") or dev.get("model") or "MikroTik")[:25]
                    prefix = f"  [{completed_count}/{total_wave}]"

                    if status in ("UPDATED", "DRY_RUN_OK"):
                        wave_ok += 1
                        console.print(f"{prefix} [bold green][  OK  ][/bold green] {ip} ({ident}): {detail or status}")
                    elif status == "SKIPPED":
                        wave_skipped += 1
                        console.print(f"{prefix} [bold yellow][ SKIP ][/bold yellow] {ip} ({ident}): {detail or status}")
                    else:
                        wave_failed += 1
                        failed_in_wave.append((dev, detail or status))
                        console.print(f"{prefix} [bold red][CHYBA ][/bold red] {ip} ({ident}): {detail or status}")

                with console.status(f"[bold cyan]Vlna {wave}: Probiha stahovani a reboot routeru (zpracovano 0/{total_wave}, bezi {effective_workers} vlaken)...[/bold cyan]") as status_bar:
                    if effective_workers > 1:
                        with ThreadPoolExecutor(max_workers=effective_workers) as executor:
                            futures = {
                                executor.submit(self.upgrade_single_device, dev, dry_run): dev
                                for dev in to_update
                            }
                            remaining = set(futures.keys())
                            while remaining:
                                done, remaining = wait(remaining, timeout=2.0, return_when=FIRST_COMPLETED)
                                for fut in done:
                                    dev = futures[fut]
                                    try:
                                        res = fut.result()
                                    except Exception as e:
                                        res = ("FAILED_UPGRADE", f"Vyjinka: {e}")
                                    process_result(dev, res)
                                waiting_str = self._get_waiting_status_str()
                                status_bar.update(f"[bold cyan]Vlna {wave}: Probiha aktualizace ({completed_count}/{total_wave} | {wave_ok} OK, {wave_failed} chyb){waiting_str}...[/bold cyan]")
                    else:
                        for dev in to_update:
                            try:
                                res = self.upgrade_single_device(dev, dry_run=dry_run)
                            except Exception as e:
                                res = ("FAILED_UPGRADE", f"Vyjinka: {e}")
                            process_result(dev, res)
                            waiting_str = self._get_waiting_status_str()
                            status_bar.update(f"[bold cyan]Vlna {wave}: Probiha aktualizace ({completed_count}/{total_wave} | {wave_ok} OK, {wave_failed} chyb){waiting_str}...[/bold cyan]")

                # Automaticky 2. pokus (retry) pro neuspesne routery v ramci vlny
                if failed_in_wave:
                    retry_devs = [f[0] for f in failed_in_wave]
                    console.print(f"\n[bold yellow]-> Detekovano {len(retry_devs)} chyb ve Vlne {wave}. Vyckavam 15s na zklidneni site po rebootech a spoustim automaticky 2. pokus (retry)...[/bold yellow]")
                    time.sleep(15)

                    retry_workers = min(max_workers, len(retry_devs))
                    still_failed: List[Tuple[Dict[str, Any], str]] = []
                    retry_completed = 0
                    retry_total = len(retry_devs)

                    def process_retry_result(dev: Dict[str, Any], res: Any):
                        nonlocal wave_ok, wave_failed, wave_skipped, retry_completed
                        retry_completed += 1
                        status, detail = res if isinstance(res, tuple) else (str(res), "")
                        ip = dev["ip"]
                        ident = (dev.get("identity") or dev.get("model") or "MikroTik")[:25]
                        prefix = f"  [Retry {retry_completed}/{retry_total}]"

                        if status in ("UPDATED", "DRY_RUN_OK"):
                            wave_ok += 1
                            wave_failed -= 1
                            console.print(f"{prefix} [bold green][  OK  ][/bold green] {ip} ({ident}): {detail or status}")
                        elif status == "SKIPPED":
                            wave_skipped += 1
                            wave_failed -= 1
                            console.print(f"{prefix} [bold yellow][ SKIP ][/bold yellow] {ip} ({ident}): {detail or status}")
                        else:
                            still_failed.append((dev, detail or status))
                            console.print(f"{prefix} [bold red][CHYBA ][/bold red] {ip} ({ident}): {detail or status}")

                    with console.status(f"[bold cyan]Vlna {wave} (Retry): Probiha opakovany pokus...[/bold cyan]") as status_bar:
                        if retry_workers > 1:
                            with ThreadPoolExecutor(max_workers=retry_workers) as executor:
                                retry_futures = {
                                    executor.submit(self.upgrade_single_device, dev, dry_run): dev
                                    for dev in retry_devs
                                }
                                remaining = set(retry_futures.keys())
                                while remaining:
                                    done, remaining = wait(remaining, timeout=2.0, return_when=FIRST_COMPLETED)
                                    for fut in done:
                                        dev = retry_futures[fut]
                                        try:
                                            res = fut.result()
                                        except Exception as e:
                                            res = ("FAILED_UPGRADE", f"Vyjinka: {e}")
                                        process_retry_result(dev, res)
                                    waiting_str = self._get_waiting_status_str()
                                    status_bar.update(f"[bold cyan]Vlna {wave} (Retry): Probiha ({retry_completed}/{retry_total}){waiting_str}...[/bold cyan]")
                        else:
                            for dev in retry_devs:
                                try:
                                    res = self.upgrade_single_device(dev, dry_run=dry_run)
                                except Exception as e:
                                    res = ("FAILED_UPGRADE", f"Vyjinka: {e}")
                                process_retry_result(dev, res)
                                waiting_str = self._get_waiting_status_str()
                                status_bar.update(f"[bold cyan]Vlna {wave} (Retry): Probiha ({retry_completed}/{retry_total}){waiting_str}...[/bold cyan]")

                    failed_in_wave = still_failed

                for f_dev, f_err in failed_in_wave:
                    all_failed_summary.append((f_dev, f_err, wave))

                total_ok += wave_ok
                total_skipped += wave_skipped
                total_failed += wave_failed
                console.print(f"[bold green]=== Vlna {wave} dokoncena ({wave_ok} aktualizovano, {wave_skipped} preskoceno, {wave_failed} chyb) ===[/bold green]")

            console.print(f"\n[bold cyan]=== Fazovany update dokoncen (celkem: {total_ok} aktualizovano, {total_skipped} preskoceno, {total_failed} chyb) ===[/bold cyan]")

            # Zaverecna prehledna tabulka chybnych zarizeni pokud nejaka pretrvavaji
            if all_failed_summary:
                console.print()
                f_table = Table(title=f"[bold red]Zarizeni vyzadujici manualni pozornost (chyba i po opakovani: {len(all_failed_summary)})[/bold red]")
                f_table.add_column("IP", style="cyan", no_wrap=True)
                f_table.add_column("Identity", style="bold magenta")
                f_table.add_column("Model", style="blue")
                f_table.add_column("Vlna", justify="center")
                f_table.add_column("Duvod / Posledni chyba", style="yellow")
                for dev, err, w in all_failed_summary:
                    f_table.add_row(
                        dev.get("ip", ""),
                        dev.get("identity") or "-",
                        dev.get("model") or "-",
                        str(w),
                        str(err or dev.get("last_error") or "Chyba aktualizace"),
                    )
                console.print(f_table)
        finally:
            for h, lvl in orig_levels.items():
                h.setLevel(lvl)

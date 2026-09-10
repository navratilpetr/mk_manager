# Modul pro overovani credentials a audit zarizeni pres SSH s podporou legacy sifer
import re
import socket
import time
import logging
import threading
from typing import Dict, Any, List, Optional, Tuple
import paramiko

logger = logging.getLogger("mk_manager.auth")

# Potlaceni verbose "Unknown exception" a "Exception (client)" zprav z paramiko transport vlaken
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)
logging.getLogger("paramiko").setLevel(logging.WARNING)

# KEX algoritmy s plnou podporou v paramiko pro ROS v5, v6 i v7
LEGACY_KEX = (
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
)

# Ciphers s plnou podporou v paramiko pro ROS v5, v6 i v7
LEGACY_CIPHERS = (
    "aes128-ctr",
    "aes192-ctr",
    "aes256-ctr",
    "aes128-gcm@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "3des-cbc",
    "blowfish-cbc",
)

LEGACY_KEYS = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",
)

# Aplikace nastaveni do vychoziho transportu paramiko
from cryptography.hazmat.primitives import hashes
from paramiko.rsakey import RSAKey
try:
    from paramiko.dsskey import DSSKey
except ImportError:
    DSSKey = None

import paramiko.transport

# Uprava povolenych klicu podle dostupnosti v teto verzi paramiko
actual_legacy_keys = list(LEGACY_KEYS)
if DSSKey is None and "ssh-dss" in actual_legacy_keys:
    actual_legacy_keys.remove("ssh-dss")

# Registrace ssh-rsa do _key_info
try:
    for target in (paramiko.Transport, paramiko.transport):
        if hasattr(target, "_key_info"):
            target._key_info["ssh-rsa"] = RSAKey
            target._key_info["ssh-rsa-cert-v01@openssh.com"] = RSAKey
            if DSSKey is not None:
                target._key_info["ssh-dss"] = DSSKey
                target._key_info["ssh-dss-cert-v01@openssh.com"] = DSSKey

    if hasattr(RSAKey, "HASHES"):
        RSAKey.HASHES["ssh-rsa"] = hashes.SHA1
        RSAKey.HASHES["ssh-rsa-cert-v01@openssh.com"] = hashes.SHA1

    paramiko.Transport._preferred_kex = tuple(LEGACY_KEX)
    paramiko.Transport._preferred_ciphers = tuple(LEGACY_CIPHERS)
    paramiko.Transport._preferred_keys = tuple(actual_legacy_keys)
except Exception as e:
    logger.debug(f"Chyba pri registraci KEX/Key do paramiko Transport: {e}")

# Monkey-patch Transport.__init__ pro zajisteni existence vsech klicu v instanci
_orig_transport_init = paramiko.Transport.__init__

def _safe_transport_init(self, *args, **kwargs):
    _orig_transport_init(self, *args, **kwargs)
    if hasattr(self, "_key_info"):
        if "ssh-rsa" not in self._key_info:
            self._key_info["ssh-rsa"] = RSAKey
            self._key_info["ssh-rsa-cert-v01@openssh.com"] = RSAKey
        if DSSKey is not None and "ssh-dss" not in self._key_info:
            self._key_info["ssh-dss"] = DSSKey
            self._key_info["ssh-dss-cert-v01@openssh.com"] = DSSKey

paramiko.Transport.__init__ = _safe_transport_init

# Monkey-patch _verify_key pro zajisteni, ze self._key_info vzdy obsahuje ssh-rsa
_orig_verify_key = paramiko.Transport._verify_key

def _safe_verify_key(self, host_key, sig):
    if hasattr(self, "_key_info"):
        if "ssh-rsa" not in self._key_info:
            self._key_info["ssh-rsa"] = RSAKey
            self._key_info["ssh-rsa-cert-v01@openssh.com"] = RSAKey
        if DSSKey is not None and "ssh-dss" not in self._key_info:
            self._key_info["ssh-dss"] = DSSKey
            self._key_info["ssh-dss-cert-v01@openssh.com"] = DSSKey
    return _orig_verify_key(self, host_key, sig)

paramiko.Transport._verify_key = _safe_verify_key


def strip_ansi(text: str) -> str:
    # Odstraneni ANSI barev a ridicich sekvenci
    ansi_regex = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
    clean = ansi_regex.sub("", text)
    return clean.replace("\r", "")


def parse_key_value_output(output: str) -> Dict[str, str]:
    # Pomocna funkce pro parsovani vystupu MikroTik CLI (napr. key: value)
    data: Dict[str, str] = {}
    clean = strip_ansi(output)
    for line in clean.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            parts = line.split(":", 1)
            key = parts[0].strip().replace(" ", "-")
            val = parts[1].strip()
            data[key] = val
    return data


def execute_ssh_command(client: paramiko.SSHClient, command: str, timeout: float = 10.0) -> str:
    # Spusteni prikazu na MikroTiku s prisnym hlidanim celkoveho casu (zabranuje zamrznuti spojeni)
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        stdout.channel.settimeout(1.0)
        start_t = time.time()
        chunks = []
        while True:
            if time.time() - start_t > timeout:
                logger.debug(f"Prikaz '{command[:40]}' vyprsel po {timeout}s")
                break
            try:
                data = stdout.channel.recv(4096)
                if not data:
                    break
                chunks.append(data)
            except socket.timeout:
                if stdout.channel.exit_status_ready() or stdout.channel.closed:
                    break
                continue
            except Exception:
                break
        raw = b"".join(chunks).decode("utf-8", errors="ignore")
        return strip_ansi(raw)
    except Exception as e:
        logger.debug(f"Prikaz '{command[:40]}' selhal: {e}")
        return ""


def _close_client(client: paramiko.SSHClient) -> None:
    # Bezpecne ukonceni klienta vcetne transport vlakna
    try:
        transport = client.get_transport()
        if transport is not None:
            transport.stop_thread()
    except Exception:
        pass
    try:
        client.close()
    except Exception:
        pass


def create_ssh_connection_detail(
    ip: str,
    port: int,
    user: str,
    password: str,
    timeout: float = 8.0
) -> Tuple[Optional[paramiko.SSHClient], str]:
    # Zkousime variantu s +ct (potlaceni ANSI na ROS v6/v7) i bez +ct (legacy ROS v5)
    usernames_to_try = [f"{user}+ct", user]
    alg_variants = [
        dict(),  # Vsechny povolene algoritmy (moderni ROS v6/v7)
        {"keys": ["rsa-sha2-512", "rsa-sha2-256"]},  # Vynuceni legacy ssh-rsa pro starsi ROS
        {"keys": ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]},  # Vynuceni ssh-dss pro zarizeni pouze s DSA host klicem
    ]
    last_err = ""

    for u in usernames_to_try:
        for dis_alg in alg_variants:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    hostname=ip,
                    port=port,
                    username=u,
                    password=password,
                    timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False,
                    banner_timeout=timeout,
                    auth_timeout=timeout,
                    disabled_algorithms=dis_alg
                )
                trans = client.get_transport()
                if trans is not None:
                    trans.set_keepalive(5)
                return client, ""
            except TypeError:
                # Starsie verze paramiko bez parametru disabled_algorithms
                try:
                    client.connect(
                        hostname=ip,
                        port=port,
                        username=u,
                        password=password,
                        timeout=timeout,
                        allow_agent=False,
                        look_for_keys=False,
                        banner_timeout=timeout,
                        auth_timeout=timeout
                    )
                    trans = client.get_transport()
                    if trans is not None:
                        trans.set_keepalive(5)
                    return client, ""
                except Exception as te:
                    last_err = str(te)
                    _close_client(client)
            except paramiko.AuthenticationException:
                last_err = f"Chybne heslo nebo uzivatel ({u})"
                _close_client(client)
                break  # Prejdi na dalsiho uzivatele, jine algoritmy nepomozou
            except Exception as e:
                err_str = str(e)
                last_err = f"SSH chyba: {err_str}" if err_str else e.__class__.__name__
                logger.debug(f"Pokus o pripojeni {ip}:{port} (user={u}): {e}")
                _close_client(client)

    return None, last_err or "Nelze navazat SSH spojeni"


def create_ssh_connection(
    ip: str,
    port: int,
    user: str,
    password: str,
    timeout: float = 8.0
) -> Optional[paramiko.SSHClient]:
    client, _ = create_ssh_connection_detail(ip, port, user, password, timeout=timeout)
    return client


def try_authenticate(
    ip: str,
    port: int,
    users: List[str],
    passwords: List[str],
    timeout: float = 8.0
) -> Tuple[Optional[paramiko.SSHClient], Optional[str], Optional[str], str]:
    # Prochazeni matice hesel pro nalezeni funkcni kombinace s vracenim presneho duvodu chyby
    last_failure = "Zadne heslo z matice nefunguje"
    for user in users:
        for pwd in passwords:
            client, err = create_ssh_connection_detail(ip, port, user, pwd, timeout=timeout)
            if client:
                logger.info(f"Uspesne overeni pro {ip}:{port} s uzivatelem '{user}'")
                return client, user, pwd, ""
            if err:
                last_failure = err
    return None, None, None, last_failure


def audit_device(
    client: paramiko.SSHClient,
    ip: str,
    port: int,
    username: str,
    password: str
) -> Dict[str, Any]:
    # Komplexni vycteni informaci ze zarizeni
    device_data: Dict[str, Any] = {
        "ip": ip,
        "ssh_port": port,
        "username": username,
        "password": password,
        "status": "AUDITED",
        "has_internet": False,
        "needs_update": False,
        "free_hdd_bytes": 0,
        "total_hdd_bytes": 0,
        "all_ips": [ip],
    }

    try:
        # 1. System identity
        ident_raw = execute_ssh_command(client, "/system identity print")
        ident_data = parse_key_value_output(ident_raw)
        device_data["identity"] = ident_data.get("name", "MikroTik")

        # 2. System routerboard (seriove cislo, model)
        rb_raw = execute_ssh_command(client, "/system routerboard print")
        rb_data = parse_key_value_output(rb_raw)
        device_data["serial_number"] = rb_data.get("serial-number", "")
        device_data["model"] = rb_data.get("model", "")

        # 3. System resource (verze, architektura, HDD prostor)
        res_raw = execute_ssh_command(client, "/system resource print")
        res_data = parse_key_value_output(res_raw)
        version_str = res_data.get("version", "")
        # Odstraneni pripony typu (stable), (long-term)
        clean_version = version_str.split()[0] if version_str else ""
        device_data["current_version"] = clean_version
        device_data["architecture"] = res_data.get("architecture-name", "")

        # Parsovani volneho mista na disku
        free_hdd = res_data.get("free-hdd-space", "0")
        total_hdd = res_data.get("total-hdd-space", "0")
        device_data["free_hdd_bytes"] = _parse_size_bytes(free_hdd)
        device_data["total_hdd_bytes"] = _parse_size_bytes(total_hdd)

        # 4. MAC adresy vsech rozhrani (ignorujeme fiktivni a virtualni MAC 00:00:00:00:00:00)
        all_ifaces_raw = execute_ssh_command(client, "/interface print detail without-paging")
        found_macs = set()
        for match in re.finditer(r"mac-address=([0-9A-Fa-f:]{17})", all_ifaces_raw):
            m = match.group(1).upper()
            if m not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
                found_macs.add(m)
        device_data["all_macs"] = sorted(list(found_macs))

        # Primarni MAC adresa: prednostne z fyzickych ethernet rozhrani
        eth_raw = execute_ssh_command(client, "/interface ethernet print detail without-paging")
        eth_macs = [m.group(1).upper() for m in re.finditer(r"mac-address=([0-9A-Fa-f:]{17})", eth_raw) if m.group(1).upper() not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF")]
        if eth_macs:
            device_data["mac"] = eth_macs[0]
        elif device_data["all_macs"]:
            device_data["mac"] = device_data["all_macs"][0]
        else:
            device_data["mac"] = ""

        # 5. Vycteni vsech IP pro deduplikaci
        ip_raw = execute_ssh_command(client, "/ip address print detail without-paging")
        found_ips = set([ip])
        for match in re.finditer(r"address=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", ip_raw):
            found_ips.add(match.group(1))
        device_data["all_ips"] = sorted(list(found_ips))

        # 6. Vycteni vychozi brany (default gateway) pro urceni nadrazeneho routeru
        route_raw = execute_ssh_command(client, '/ip route print detail without-paging where dst-address="0.0.0.0/0"')
        gw_match = re.search(r"gateway=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", route_raw)
        device_data["gateway"] = gw_match.group(1) if gw_match else None

        # 7. Test internetoveho pripojeni (ping 8.8.8.8 s fallbackem na MikroTik update server)
        ping_raw = execute_ssh_command(client, "/ping 8.8.8.8 count=2", timeout=6.0)
        loss_match = re.search(r"packet-loss=([0-9]+)%", ping_raw)
        recv_match = re.search(r"received=([0-9]+)", ping_raw)

        has_internet = False
        if loss_match and int(loss_match.group(1)) < 100:
            has_internet = True
        elif recv_match and int(recv_match.group(1)) > 0:
            has_internet = True
        else:
            # Fallback pro routery v management siti kde firewall zahazuje odchozi ICMP ping
            upd_chk = execute_ssh_command(client, "/system package update check-for-updates once", timeout=6.0)
            if "latest-version" in upd_chk or ("status:" in upd_chk and "ERROR" not in upd_chk.upper()):
                has_internet = True
        device_data["has_internet"] = has_internet

        # 8. Vycteni nastaveni DNS
        dns_raw = execute_ssh_command(client, "/ip dns print without-paging")
        dns_data = parse_key_value_output(dns_raw)
        dns_srv = dns_data.get("servers", "").strip()
        dns_dyn = dns_data.get("dynamic-servers", "").strip()
        has_dns = bool(dns_srv or dns_dyn)
        device_data["has_dns"] = has_dns
        device_data["dns_servers"] = dns_srv or dns_dyn or ""

        # 9. Bezpecnostni audit - detekce kompromitace (MikroTrick, CVE-2026-67276, flagged: yes)
        is_flagged = False
        flagged_reasons = []
        security_notice = None

        # A) Kontrola /system device-mode
        try:
            dm_raw = execute_ssh_command(client, "/system device-mode print", timeout=4.0)
            if dm_raw and re.search(r"flagged:\s*yes", dm_raw, re.IGNORECASE):
                is_flagged = True
                flagged_reasons.append("device-mode flagged=yes")
        except Exception:
            pass

        # B) Kontrola existence neautorizovaneho uzivatele 'ops'
        try:
            user_raw = execute_ssh_command(client, "/user print detail without-paging", timeout=4.0)
            if user_raw and re.search(r'name="?ops"?(\s+|$)', user_raw, re.IGNORECASE):
                is_flagged = True
                flagged_reasons.append("nalezen utocnicky ucet 'ops'")
        except Exception:
            pass

        # C) Kontrola logu na anomalie 'user -2'
        try:
            log_raw = execute_ssh_command(client, '/log print without-paging where message~"-2"', timeout=4.0)
            if log_raw:
                # Rozliseni potvrzeneho pruniku vs neuspesneho pokusu o prihlaseni
                if "added by ssh:-2" in log_raw or re.search(r"logged in.*(-2|ssh:-2)", log_raw, re.IGNORECASE):
                    is_flagged = True
                    flagged_reasons.append("potvrzeny prunik v logu: ucet/pristup pres ssh:-2")
                elif "user -2" in log_raw or "ssh:-2@" in log_raw:
                    # Pouze neuspesny pokus o exploit (router pokus odrazil / login failure)
                    security_notice = "neuspesny pokus o exploit v logu (login failure user -2 - odrazeno)"
        except Exception:
            pass

        device_data["is_flagged"] = is_flagged
        device_data["flagged_reason"] = ", ".join(flagged_reasons) if flagged_reasons else None
        device_data["security_notice"] = security_notice

    except Exception as e:
        logger.warning(f"Chyba pri auditu zarizeni {ip}: {e}")
        return None

    # Overeni, ze zarizeni skutecne bezi na RouterOS (musi mit verzi nebo model/architekturu)
    if not device_data.get("current_version") and not device_data.get("model") and not device_data.get("architecture"):
        logger.warning(f"Zarizeni {ip} neodpovedelo na prikazy RouterOS, nejedna se o MikroTik")
        return None

    return device_data


def _parse_size_bytes(size_str: str) -> int:
    # Prevod MikroTik velikosti (napr. 15.2MiB, 128.0KiB, 1073741824) na bajty
    if not size_str:
        return 0
    size_str = size_str.strip().lower()
    try:
        if size_str.endswith("gib") or size_str.endswith("gb"):
            num = float(re.sub(r"[a-z]", "", size_str))
            return int(num * 1024 * 1024 * 1024)
        elif size_str.endswith("mib") or size_str.endswith("mb"):
            num = float(re.sub(r"[a-z]", "", size_str))
            return int(num * 1024 * 1024)
        elif size_str.endswith("kib") or size_str.endswith("kb"):
            num = float(re.sub(r"[a-z]", "", size_str))
            return int(num * 1024)
        else:
            return int(float(re.sub(r"[a-z]", "", size_str)))
    except Exception:
        return 0

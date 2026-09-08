# Modul pro analyzu topologie site a planovani vln aktualizaci (leaf-to-spine)
import re
import json
import logging
from collections import defaultdict, deque
from typing import Dict, Any, List, Set, Tuple, Optional
from rich.console import Console
from rich.table import Table

from config import Config
from database import Database
from auth import create_ssh_connection, execute_ssh_command, strip_ansi

logger = logging.getLogger("mk_manager.topology")
console = Console()


def parse_mikrotik_records(output: str) -> List[Dict[str, str]]:
    # Robustni parsovani vystupu MikroTik CLI print detail
    clean = strip_ansi(output)
    records: List[Dict[str, str]] = []
    current: Dict[str, str] = {}

    for line in clean.splitlines():
        line = line.strip()
        if not line or line.startswith("Flags:"):
            continue

        # Zaznam v MikroTik CLI obvykle zacina cislem indexu: "0 D", "1", " 0  ;;;"
        if re.match(r"^\s*\d+\s+", line) or line.startswith(";;;"):
            if current and (current.get("ip") or current.get("mac") or current.get("identity")):
                records.append(current)
                current = {}

        # Extrakce klicovych vlastnosti
        ip_match = re.search(r"address=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
        if ip_match and not current.get("ip"):
            current["ip"] = ip_match.group(1)

        mac_match = re.search(r"mac-address=([0-9A-Fa-f:]{17})", line)
        if mac_match and not current.get("mac"):
            current["mac"] = mac_match.group(1).upper()

        ident_match = re.search(r'identity="?([^"\n\r]+?)"?(?:\s+[a-z-]+=|;\s*|$)', line)
        if ident_match and not current.get("identity"):
            current["identity"] = ident_match.group(1).strip()

        iface_match = re.search(r'interface="?([^"\n\r\s]+)"?', line)
        if iface_match and not current.get("interface"):
            current["interface"] = iface_match.group(1)

    if current and (current.get("ip") or current.get("mac") or current.get("identity")):
        records.append(current)

    return records


class TopologyManager:
    def __init__(self, config: Config, db: Database):
        self.config = config
        self.db = db

    def collect_neighbors(self) -> None:
        # Paralelni sber vazeb: MNDP sousede, bezdratove registrace a default gateway/traceroute
        devices = self.db.get_all_devices()
        if not devices:
            logger.warning("V databazi nejsou zadna zarizeni pro sber topologie")
            return

        logger.info(f"Zahajeni paralelniho sberu topologie pro {len(devices)} zarizeni")

        from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
        import concurrent.futures

        def _collect_single(dev: Dict[str, Any]) -> None:
            ip = dev["ip"]
            dev_id = dev["id"]
            user = dev.get("username")
            pwd = dev.get("password")
            port = dev.get("ssh_port", self.config.port_ssh)

            if not user:
                return

            client = create_ssh_connection(ip, port, user, pwd, timeout=self.config.ssh_timeout)
            if not client:
                logger.warning(f"Nelze se pripojit k {ip} pro vycteni topologie")
                return

            all_detected_neighbors: List[Dict[str, Any]] = []
            try:
                # 1. Vycteni MNDP sousedu
                mndp_raw = execute_ssh_command(client, "/ip neighbor print detail without-paging")
                mndp_list = parse_mikrotik_records(mndp_raw)
                for item in mndp_list:
                    item["source"] = "MNDP"
                    all_detected_neighbors.append(item)

                # 2. Vycteni bezdratovych klientu (legacy wireless registration-table)
                wlan_raw = execute_ssh_command(client, "/interface wireless registration-table print detail without-paging")
                wlan_list = parse_mikrotik_records(wlan_raw)
                for item in wlan_list:
                    item["source"] = "WIRELESS"
                    all_detected_neighbors.append(item)

                # 3. Vycteni novejsich wifi klientu (ROS v7 wifi / wifiwave2)
                wifi_raw = execute_ssh_command(client, "/interface wifi registration-table print detail without-paging")
                wifi_list = parse_mikrotik_records(wifi_raw)
                for item in wifi_list:
                    item["source"] = "WIRELESS"
                    all_detected_neighbors.append(item)

                # 4. Vycteni vychozi brany (default route 0.0.0.0/0)
                route_raw = execute_ssh_command(client, '/ip route print detail without-paging where dst-address="0.0.0.0/0" and active=yes')
                if not route_raw or "gateway=" not in route_raw:
                    route_raw = execute_ssh_command(client, '/ip route print detail without-paging where dst-address="0.0.0.0/0"')

                gw_match = re.search(r"gateway=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", route_raw)
                gw_ip = gw_match.group(1) if gw_match else None
                if gw_ip:
                    if not dev.get("gateway"):
                        dev_update = dict(dev)
                        dev_update["gateway"] = gw_ip
                        self.db.upsert_device(dev_update)

                    # 5. Vycteni MAC adresy brany z /ip arp (L2/L3 vazba)
                    arp_raw = execute_ssh_command(client, f'/ip arp print detail without-paging where address="{gw_ip}"')
                    arp_mac_match = re.search(r"mac-address=([0-9A-Fa-f:]{17})", arp_raw)
                    if arp_mac_match:
                        gw_mac = arp_mac_match.group(1).upper()
                        all_detected_neighbors.append({
                            "ip": gw_ip,
                            "mac": gw_mac,
                            "source": "GATEWAY_MAC"
                        })

                # 6. Vycteni L3 cesty pres traceroute 1.1.1.1
                tr_raw = execute_ssh_command(client, "/tool traceroute address=1.1.1.1 count=1 use-dns=no", timeout=8.0)
                if tr_raw:
                    for line in tr_raw.splitlines():
                        m_tr = re.search(r"^\s*(\d+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", line)
                        if m_tr:
                            hop_num = int(m_tr.group(1))
                            hop_ip = m_tr.group(2)
                            if hop_ip not in ("1.1.1.1", "0.0.0.0", ip):
                                all_detected_neighbors.append({
                                    "ip": hop_ip,
                                    "interface": str(hop_num),
                                    "source": "TRACEROUTE"
                                })

                self.db.save_neighbors(dev_id, all_detected_neighbors)
                logger.debug(f"Zarizeni {ip} ({dev.get('identity')}): nalezeno {len(all_detected_neighbors)} vazeb")
            except Exception as e:
                logger.error(f"Chyba pri sberu topologie na {ip}: {e}")
            finally:
                try:
                    client.close()
                except Exception:
                    pass

        max_workers = min(20, len(devices))
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task(f"Sber topologie ({len(devices)} routeru)...", total=len(devices))
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(_collect_single, d): d for d in devices}
                for f in concurrent.futures.as_completed(futures):
                    dev = futures[f]
                    progress.advance(task)
                    ident_str = (dev.get("identity") or "")[:20]
                    progress.update(task, description=f"Sber topologie: [cyan]{dev['ip']}[/cyan] ({ident_str})...")

    def calculate_waves(self) -> Dict[int, List[int]]:
        # Vypocet aktualizacnich vln od listovych klientu (Leaf) k distribuci a jadru (Spine)
        devices = self.db.get_all_devices()
        if not devices:
            logger.warning("V databazi nejsou zadna zarizeni pro vypocet vln")
            return {}

        dev_by_id: Dict[int, Dict[str, Any]] = {d["id"]: d for d in devices}

        # Mapovani vsech IP a vsech MAC adres na ID zarizeni
        ip_to_id: Dict[str, int] = {}
        mac_to_id: Dict[str, int] = {}

        for dev_id, d in dev_by_id.items():
            # Primarni IP
            ip_to_id[d["ip"]] = dev_id
            # Vsechny IP adresy
            if d.get("all_ips"):
                try:
                    for extra_ip in json.loads(d["all_ips"]):
                        ip_to_id[extra_ip] = dev_id
                except Exception:
                    pass

            # Primarni MAC
            if d.get("mac"):
                mac_to_id[d["mac"].upper()] = dev_id
            # Vsechny MAC adresy rozhrani
            if d.get("all_macs"):
                try:
                    for extra_mac in json.loads(d["all_macs"]):
                        mac_to_id[extra_mac.upper()] = dev_id
                except Exception:
                    pass

        # Orientovany strom zavislosti:
        # downlinks[parent_id] = mnozina zarizeni, ktera jsou na parent_id zavisla (deti/klienti)
        # uplinks[child_id] = mnozina nadrazenych zarizeni (rodice/AP/Core)
        downlinks: Dict[int, Set[int]] = defaultdict(set)
        uplinks: Dict[int, Set[int]] = defaultdict(set)

        all_neighbors = self.db.get_all_neighbors()

        for n in all_neighbors:
            dev_id = n["device_id"]
            n_ip = n.get("neighbor_ip")
            n_mac = n.get("neighbor_mac")
            src = n.get("source", "MNDP")

            target_id = None
            if n_mac and n_mac.upper() in mac_to_id:
                target_id = mac_to_id[n_mac.upper()]
            elif n_ip and n_ip in ip_to_id:
                target_id = ip_to_id[n_ip]

            if not target_id or target_id == dev_id:
                continue

            # 1. GATEWAY_MAC: target_id je fyzicka L2 brana pro dev_id (target_id je parent)
            if src == "GATEWAY_MAC":
                downlinks[target_id].add(dev_id)
                uplinks[dev_id].add(target_id)

            # 2. TRACEROUTE: target_id je L3 uzel na ceste k internetu (target_id je parent)
            elif src == "TRACEROUTE":
                downlinks[target_id].add(dev_id)
                uplinks[dev_id].add(target_id)

            # 3. WIRELESS: AP registracni tabulka (AP je parent pro pripojeneho klienta)
            elif src == "WIRELESS":
                curr_dev = dev_by_id[dev_id]
                target_dev = dev_by_id[target_id]
                if dev_id not in downlinks[target_id]:
                    if _is_likely_ap(curr_dev) and not _is_likely_ap(target_dev):
                        downlinks[dev_id].add(target_id)
                        uplinks[target_id].add(dev_id)
                    elif _is_likely_ap(target_dev) and not _is_likely_ap(curr_dev):
                        downlinks[target_id].add(dev_id)
                        uplinks[dev_id].add(target_id)

            # 4. MNDP vazba: pouze pro jednoznacny Core router proti beznym uzlum
            elif src == "MNDP":
                curr_dev = dev_by_id[dev_id]
                target_dev = dev_by_id[target_id]
                is_curr_core = _is_core_router(curr_dev)
                is_target_core = _is_core_router(target_dev)

                if is_curr_core and not is_target_core:
                    if dev_id not in downlinks[target_id]:
                        downlinks[dev_id].add(target_id)
                        uplinks[target_id].add(dev_id)
                elif is_target_core and not is_curr_core:
                    if target_id not in downlinks[dev_id]:
                        downlinks[target_id].add(dev_id)
                        uplinks[dev_id].add(target_id)

        # Doplneni vazeb z vychozi brany podle IP
        for dev_id, d in dev_by_id.items():
            gw = d.get("gateway")
            if gw and gw in ip_to_id:
                parent_id = ip_to_id[gw]
                if parent_id != dev_id:
                    downlinks[parent_id].add(dev_id)
                    uplinks[dev_id].add(parent_id)

        # Odstraneni pripadnych obousmernych cyklu (A->B i B->A)
        for u in list(downlinks.keys()):
            for v in list(downlinks[u]):
                if u in downlinks[v]:
                    score_u = 2 if _is_core_router(dev_by_id[u]) else (1 if _is_likely_ap(dev_by_id[u]) else 0)
                    score_v = 2 if _is_core_router(dev_by_id[v]) else (1 if _is_likely_ap(dev_by_id[v]) else 0)
                    if score_u >= score_v:
                        downlinks[v].discard(u)
                        uplinks[u].discard(v)
                    else:
                        downlinks[u].discard(v)
                        uplinks[v].discard(u)

        # Fázovany rozpad do vln (Leaf-to-Spine):
        # Vlna 1 = Zarizeni, ktera nemaji zadne dalsi podrizene routery v remaining (Leaf/Klienti)
        # Postupnym orezavanim ziskame Vlny 2, 3... az po Spine/Core
        remaining: Set[int] = set(dev_by_id.keys())
        waves: Dict[int, List[int]] = defaultdict(list)
        current_wave = 1

        while remaining:
            # Hledame vsechny uzly, ktere v aktualnim podgrafu nemaji zadne potomky
            leaves = []
            for dev_id in remaining:
                active_children = downlinks[dev_id].intersection(remaining)
                if len(active_children) == 0:
                    leaves.append(dev_id)

            # Pokud vznikl cyklus a zadny uzel nema 0 potomku:
            # Prednostne vybereme uzel, ktery NENI Core router a ma nejmene aktivnich potomku
            if not leaves:
                candidates = sorted(
                    remaining,
                    key=lambda d: (
                        1 if _is_core_router(dev_by_id[d]) else 0,
                        len(downlinks[d].intersection(remaining))
                    )
                )
                leaves = [candidates[0]]

            # Prirazeni do aktualni vlny
            for dev_id in leaves:
                waves[current_wave].append(dev_id)
                self.db.set_device_wave(dev_id, current_wave)
                remaining.remove(dev_id)

            logger.info(f"Vlna {current_wave} (Leaf-to-Spine): {len(leaves)} zarizeni")
            current_wave += 1

        return waves

    def display_waves_summary(self) -> None:
        # Vykresleni prehledne rich tabulky s rozpadem vln
        stats = self.db.get_statistics()
        wave_dist = stats.get("waves", {})

        table = Table(title="[bold green]Rozpad aktualizacnich vln (Leaf -> Spine)[/bold green]")
        table.add_column("Vlna", justify="center", style="cyan", no_wrap=True)
        table.add_column("Typ uzlu", style="magenta")
        table.add_column("Pocet zarizeni", justify="right", style="bold")

        total_waves = len(wave_dist)
        for wave_num, count in sorted(wave_dist.items()):
            if wave_num == 1:
                role = "Leaf nodes (koncovi klienti, CPE)"
            elif wave_num == total_waves and total_waves > 1:
                role = "Spine / Core (paterni brany k internetu)"
            elif wave_num == 2 and total_waves > 2:
                role = "Sektory / Lokalne pristupove body"
            else:
                role = f"Distribuce / Agregace (uroven {wave_num})"
            table.add_row(str(wave_num), role, str(count))

        console.print(table)


def _is_core_router(dev: Dict[str, Any]) -> bool:
    # Rozpoznani paterniho routeru podle modelu nebo identity
    model = (dev.get("model") or "").lower()
    ident = (dev.get("identity") or "").lower()
    core_models = ("4011", "5009", "ccr", "crs", "3011", "2011", "1100", "x86", "chr")
    if any(m in model for m in core_models):
        return True
    if "core" in ident or "pater" in ident or "brana" in ident:
        return True
    return False


def _is_likely_ap(dev: Dict[str, Any]) -> bool:
    # Rozpoznani pristupoveho bodu / sektoru
    if _is_core_router(dev):
        return False
    model = (dev.get("model") or "").lower()
    # Klientske CPE modely nejsou AP
    if any(m in model for m in ("lhg", "disc", "cube")):
        return False
    ident = (dev.get("identity") or "").lower()
    if "ap" in ident or "sektor" in ident:
        return True
    ap_models = ("omnitik", "922", "wap", "433", "912", "groove", "basebox", "netmetal")
    if any(m in model for m in ap_models):
        return True
    return False

# Modul pro spravu SQLite databaze a auditnich zaznamu
import os
import json
import sqlite3
import csv
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("mk_manager.database")


class Database:
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=60.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        return conn

    def init_db(self) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    all_ips TEXT,
                    mac TEXT,
                    serial_number TEXT,
                    identity TEXT,
                    model TEXT,
                    architecture TEXT,
                    current_version TEXT,
                    target_version TEXT,
                    needs_update BOOLEAN DEFAULT 0,
                    has_internet BOOLEAN DEFAULT 0,
                    free_hdd_bytes INTEGER DEFAULT 0,
                    total_hdd_bytes INTEGER DEFAULT 0,
                    username TEXT,
                    password TEXT,
                    ssh_port INTEGER DEFAULT 22,
                    status TEXT DEFAULT 'DISCOVERED',
                    wave INTEGER DEFAULT 0,
                    attempts INTEGER DEFAULT 0,
                    all_macs TEXT,
                    gateway TEXT,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_error TEXT
                )
            """)
            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_sn ON devices(serial_number)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac)")

            # Automaticka migrace existujici databaze
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN all_macs TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN gateway TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN is_flagged BOOLEAN DEFAULT 0")
            except sqlite3.OperationalError:
                pass
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN flagged_reason TEXT")
            except sqlite3.OperationalError:
                pass
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN has_dns BOOLEAN DEFAULT 1")
            except sqlite3.OperationalError:
                pass
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN dns_servers TEXT")
            except sqlite3.OperationalError:
                pass

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS neighbors (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    neighbor_ip TEXT,
                    neighbor_mac TEXT,
                    neighbor_identity TEXT,
                    interface TEXT,
                    source TEXT DEFAULT 'MNDP',
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                )
            """)
            try:
                cursor.execute("ALTER TABLE neighbors ADD COLUMN source TEXT DEFAULT 'MNDP'")
            except sqlite3.OperationalError:
                pass

            # Odstraneni neplatnych zaznamu (zarizeni bez verze/modelu ktere nejsou MikroTik)
            try:
                cursor.execute("""
                    DELETE FROM devices
                    WHERE (model IS NULL OR model = '' OR model = '-')
                      AND (current_version IS NULL OR current_version = '' OR current_version = '-')
                      AND status = 'AUDITED'
                """)
            except Exception:
                pass

            conn.commit()
        self.cleanup_stale_records()

    def cleanup_stale_records(self) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # 1. Odstraneni ne-MikroTik zarizeni
            cursor.execute("""
                DELETE FROM devices
                WHERE (model IS NULL OR model = '' OR model = '-')
                  AND (current_version IS NULL OR current_version = '' OR current_version = '-')
                  AND status = 'AUDITED'
            """)
            # 2. Odstraneni falesne sloucenych zaznamu s neplatnou MAC 00:00:00:00:00:00
            cursor.execute("DELETE FROM devices WHERE mac = '00:00:00:00:00:00'")
            cursor.execute("DELETE FROM devices WHERE ip LIKE '192.168.86.%' AND ip NOT IN ('192.168.86.65', '192.168.86.8') AND mac = '00:00:00:00:00:00'")

            # 3. Odstraneni zastaralych zaznamu chyb vyresenych bugu s kex/ciphers
            cursor.execute("""
                DELETE FROM devices 
                WHERE status = 'AUTH_FAILED' 
                  AND (last_error LIKE '%curve25519%' OR last_error LIKE '%chacha20%')
            """)

            # 4. Obnova stavu zarizeni preskocenych pri predchozim behu kvuli prisnemu limitu mista na disku
            cursor.execute("""
                UPDATE devices 
                SET status = 'AUDITED', last_error = NULL 
                WHERE status = 'SKIPPED' AND last_error LIKE '%Nedostatek mista na disku%'
            """)
            conn.commit()

    def cleanup_networks(self, allowed_networks: List[str]) -> int:
        # Odstraneni zarizeni z databaze, jejichz rozsah byl odebran z config.yaml
        if not allowed_networks:
            return 0
        import ipaddress
        parsed_nets = []
        for n in allowed_networks:
            try:
                parsed_nets.append(ipaddress.ip_network(n, strict=False))
            except ValueError:
                pass

        if not parsed_nets:
            return 0

        removed_count = 0
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, ip, identity FROM devices")
            rows = cursor.fetchall()
            for r in rows:
                dev_id = r["id"]
                dev_ip = r["ip"]
                try:
                    ip_obj = ipaddress.ip_address(dev_ip)
                    in_network = any(ip_obj in net for net in parsed_nets)
                except ValueError:
                    in_network = False

                if not in_network:
                    cursor.execute("DELETE FROM devices WHERE id = ?", (dev_id,))
                    cursor.execute("DELETE FROM neighbors WHERE device_id = ?", (dev_id,))
                    removed_count += 1
                    logger.info(f"Odebran router {dev_ip} ({r['identity']}) z DB - rozsah odebran z config.yaml")

            conn.commit()

        return removed_count

    def upsert_device(self, data: Dict[str, Any]) -> int:
        ip = data.get("ip")
        if not ip:
            raise ValueError("IP adresa zarizeni je povinna")

        sn = data.get("serial_number")
        mac = data.get("mac")
        new_ips = set(data.get("all_ips", [ip]))
        new_ips.add(ip)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            existing_row = None

            # 1. Hledani podle serial number (deduplikace) - pouze platne SN
            if sn and sn.strip() and sn.strip().lower() not in ("none", "null", "unknown", ""):
                cursor.execute("SELECT * FROM devices WHERE serial_number = ? LIMIT 1", (sn.strip(),))
                existing_row = cursor.fetchone()

            # 2. Hledani podle MAC adresy (pokud neni SN) - NIKDY nededuplikovat podle fiktivni 00:00:00:00:00:00!
            if not existing_row and mac and mac.strip() and mac.strip().upper() not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF", ""):
                cursor.execute("SELECT * FROM devices WHERE mac = ? LIMIT 1", (mac.strip().upper(),))
                existing_row = cursor.fetchone()

            # 3. Hledani podle primarni IP
            if not existing_row:
                cursor.execute("SELECT * FROM devices WHERE ip = ? LIMIT 1", (ip,))
                existing_row = cursor.fetchone()

            if existing_row:
                dev_id = existing_row["id"]
                # Slouceni IP adres
                old_ips_json = existing_row["all_ips"]
                current_ips = set()
                if old_ips_json:
                    try:
                        current_ips = set(json.loads(old_ips_json))
                    except Exception:
                        pass
                current_ips.update(new_ips)
                merged_ips_json = json.dumps(sorted(list(current_ips)))

                # Slouceni MAC adres
                new_macs = set(data.get("all_macs", []))
                if mac:
                    new_macs.add(mac.upper())
                old_macs_json = existing_row["all_macs"] if "all_macs" in existing_row.keys() else None
                current_macs = set()
                if old_macs_json:
                    try:
                        current_macs = set(json.loads(old_macs_json))
                    except Exception:
                        pass
                current_macs.update(new_macs)
                merged_macs_json = json.dumps(sorted(list(current_macs)))

                cursor.execute("""
                    UPDATE devices SET
                        all_ips = ?,
                        all_macs = ?,
                        gateway = COALESCE(?, gateway),
                        mac = COALESCE(?, mac),
                        serial_number = COALESCE(?, serial_number),
                        identity = COALESCE(?, identity),
                        model = COALESCE(?, model),
                        architecture = COALESCE(?, architecture),
                        current_version = COALESCE(?, current_version),
                        target_version = COALESCE(?, target_version),
                        needs_update = COALESCE(?, needs_update),
                        has_internet = COALESCE(?, has_internet),
                        has_dns = COALESCE(?, has_dns),
                        dns_servers = COALESCE(?, dns_servers),
                        free_hdd_bytes = COALESCE(?, free_hdd_bytes),
                        total_hdd_bytes = COALESCE(?, total_hdd_bytes),
                        username = COALESCE(?, username),
                        password = COALESCE(?, password),
                        ssh_port = COALESCE(?, ssh_port),
                        status = COALESCE(?, status),
                        is_flagged = COALESCE(?, is_flagged),
                        flagged_reason = COALESCE(?, flagged_reason),
                        last_seen = CURRENT_TIMESTAMP,
                        last_error = ?
                    WHERE id = ?
                """, (
                    merged_ips_json,
                    merged_macs_json,
                    data.get("gateway"),
                    mac,
                    sn,
                    data.get("identity"),
                    data.get("model"),
                    data.get("architecture"),
                    data.get("current_version"),
                    data.get("target_version"),
                    data.get("needs_update"),
                    data.get("has_internet"),
                    1 if data.get("has_dns") else 0 if "has_dns" in data else None,
                    data.get("dns_servers"),
                    data.get("free_hdd_bytes"),
                    data.get("total_hdd_bytes"),
                    data.get("username"),
                    data.get("password"),
                    data.get("ssh_port", 22),
                    data.get("status"),
                    1 if data.get("is_flagged") else 0 if "is_flagged" in data else None,
                    data.get("flagged_reason"),
                    data.get("last_error"),
                    dev_id,
                ))
                conn.commit()
                return dev_id
            else:
                # Novy zaznam
                ips_json = json.dumps(sorted(list(new_ips)))
                new_macs = set(data.get("all_macs", []))
                if mac:
                    new_macs.add(mac.upper())
                macs_json = json.dumps(sorted(list(new_macs)))

                cursor.execute("""
                    INSERT INTO devices (
                        ip, all_ips, all_macs, gateway, mac, serial_number, identity, model, architecture,
                        current_version, target_version, needs_update, has_internet, has_dns, dns_servers,
                        free_hdd_bytes, total_hdd_bytes, username, password, ssh_port,
                        status, wave, attempts, is_flagged, flagged_reason, last_seen, last_error
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?
                    )
                """, (
                    ip,
                    ips_json,
                    macs_json,
                    data.get("gateway"),
                    mac,
                    sn,
                    data.get("identity"),
                    data.get("model"),
                    data.get("architecture"),
                    data.get("current_version"),
                    data.get("target_version"),
                    1 if data.get("needs_update") else 0,
                    1 if data.get("has_internet") else 0,
                    1 if data.get("has_dns", True) else 0,
                    data.get("dns_servers", ""),
                    data.get("free_hdd_bytes", 0),
                    data.get("total_hdd_bytes", 0),
                    data.get("username"),
                    data.get("password"),
                    data.get("ssh_port", 22),
                    data.get("status", "DISCOVERED"),
                    data.get("wave", 0),
                    data.get("attempts", 0),
                    1 if data.get("is_flagged") else 0,
                    data.get("flagged_reason"),
                    data.get("last_error"),
                ))
                conn.commit()
                return cursor.lastrowid

    def refresh_target_versions(self, latest_v6: str, latest_v7: str) -> None:
        # Prepocet cilovych verzi a needs_update podle aktualnich verzi z MikroTik serveru
        from scanner import evaluate_versions
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, current_version, status FROM devices WHERE current_version IS NOT NULL AND current_version != ''")
            rows = cursor.fetchall()
            for row in rows:
                dev_id = row["id"]
                curr_ver = row["current_version"]
                status = row["status"]
                target_ver, needs_upd = evaluate_versions(curr_ver, latest_v6, latest_v7)
                if status == "UPDATED" and not needs_upd:
                    continue
                cursor.execute("""
                    UPDATE devices SET
                        target_version = ?,
                        needs_update = ?
                    WHERE id = ?
                """, (target_ver, 1 if needs_upd else 0, dev_id))
            conn.commit()

    def update_device_status(
        self,
        device_id: int,
        status: str,
        current_version: Optional[str] = None,
        needs_update: Optional[bool] = None,
        attempts: Optional[int] = None,
        error: Optional[str] = None,
        is_flagged: Optional[bool] = None,
        flagged_reason: Optional[str] = None
    ) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            flag_val = None
            if is_flagged is not None:
                flag_val = 1 if is_flagged else 0
            cursor.execute("""
                UPDATE devices SET
                    status = ?,
                    current_version = COALESCE(?, current_version),
                    needs_update = COALESCE(?, needs_update),
                    attempts = COALESCE(?, attempts),
                    is_flagged = COALESCE(?, is_flagged),
                    flagged_reason = COALESCE(?, flagged_reason),
                    last_error = ?,
                    last_seen = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (status, current_version, needs_update, attempts, flag_val, flagged_reason, error, device_id))
            conn.commit()

    def update_device_dns(self, device_id: int, has_dns: bool, dns_servers: str) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE devices SET has_dns = ?, dns_servers = ? WHERE id = ?", (1 if has_dns else 0, dns_servers, device_id))
            conn.commit()

    def set_device_wave(self, device_id: int, wave: int) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE devices SET wave = ? WHERE id = ?", (wave, device_id))
            conn.commit()

    def get_device(self, device_id: int) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_device_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices WHERE ip = ?", (ip,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_all_devices(self, status: Optional[str] = None, wave: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM devices WHERE 1=1"
            params: List[Any] = []
            if status:
                query += " AND status = ?"
                params.append(status)
            if wave is not None:
                query += " AND wave = ?"
                params.append(wave)
            query += " ORDER BY wave ASC, id ASC"
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def save_neighbors(self, device_id: int, neighbors: List[Dict[str, Any]]) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM neighbors WHERE device_id = ?", (device_id,))
            for n in neighbors:
                cursor.execute("""
                    INSERT INTO neighbors (device_id, neighbor_ip, neighbor_mac, neighbor_identity, interface, source)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    device_id,
                    n.get("ip"),
                    n.get("mac"),
                    n.get("identity"),
                    n.get("interface"),
                    n.get("source", "MNDP"),
                ))
            conn.commit()

    def get_all_neighbors(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM neighbors")
            return [dict(row) for row in cursor.fetchall()]

    def export_audit_csv(self, file_path: str = "data/audit.csv") -> str:
        devices = self.get_all_devices()
        out_path = Path(file_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        fieldnames = [
            "id", "ip", "all_ips", "serial_number", "mac", "identity",
            "model", "architecture", "current_version", "target_version",
            "needs_update", "has_internet", "free_hdd_mb", "total_hdd_mb",
            "is_flagged", "flagged_reason",
            "wave", "status", "attempts", "last_seen", "last_error"
        ]

        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for d in devices:
                free_mb = round(d.get("free_hdd_bytes", 0) / (1024 * 1024), 2)
                total_mb = round(d.get("total_hdd_bytes", 0) / (1024 * 1024), 2)
                writer.writerow({
                    "id": d.get("id"),
                    "ip": d.get("ip"),
                    "all_ips": d.get("all_ips"),
                    "serial_number": d.get("serial_number"),
                    "mac": d.get("mac"),
                    "identity": d.get("identity"),
                    "model": d.get("model"),
                    "architecture": d.get("architecture"),
                    "current_version": d.get("current_version"),
                    "target_version": d.get("target_version"),
                    "needs_update": bool(d.get("needs_update")),
                    "has_internet": bool(d.get("has_internet")),
                    "free_hdd_mb": free_mb,
                    "total_hdd_mb": total_mb,
                    "is_flagged": bool(d.get("is_flagged")),
                    "flagged_reason": d.get("flagged_reason") or "",
                    "wave": d.get("wave", 0),
                    "status": d.get("status"),
                    "attempts": d.get("attempts", 0),
                    "last_seen": d.get("last_seen"),
                    "last_error": d.get("last_error"),
                })
        return str(out_path.resolve())

    def get_statistics(self) -> Dict[str, Any]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM devices")
            total = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM devices WHERE is_flagged = 1")
            flagged = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM devices WHERE needs_update = 1")
            needs_update = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'UPDATED'")
            updated = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'FAILED_UPGRADE'")
            failed = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM devices WHERE status = 'SKIPPED'")
            skipped = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM devices WHERE has_internet = 1")
            internet_ok = cursor.fetchone()[0]

            # Rozpad podle hlavni verze ROS
            cursor.execute("""
                SELECT
                    CASE
                        WHEN current_version LIKE '5.%' THEN 'ROS v5'
                        WHEN current_version LIKE '6.%' THEN 'ROS v6'
                        WHEN current_version LIKE '7.%' THEN 'ROS v7'
                        ELSE 'Neznama (Neprihlaseno)'
                    END as version_group,
                    COUNT(*) as count
                FROM devices
                GROUP BY version_group
            """)
            version_dist = {row["version_group"]: row["count"] for row in cursor.fetchall()}

            # Rozpad podle vln
            cursor.execute("SELECT wave, COUNT(*) as count FROM devices GROUP BY wave ORDER BY wave ASC")
            wave_dist = {row["wave"]: row["count"] for row in cursor.fetchall()}

            return {
                "total": total,
                "flagged": flagged,
                "needs_update": needs_update,
                "updated": updated,
                "failed": failed,
                "skipped": skipped,
                "has_internet": internet_ok,
                "no_internet": total - internet_ok,
                "versions": version_dist,
                "waves": wave_dist,
            }

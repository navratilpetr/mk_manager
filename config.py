# Modul pro nacitani konfigurace a inicializaci logovani
import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict, List
import yaml
from rich.logging import RichHandler


APP_VERSION = "1.0.0"


class Config:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.base_dir = self.config_path.parent.resolve()
        self.raw_data: Dict[str, Any] = self._load_yaml()

        # Site a rozsahy
        self.networks: List[str] = self.raw_data.get("networks", ["10.0.0.0/8"])

        # Prihlasovaci udaje
        cred = self.raw_data.get("credentials", {})
        self.users: List[str] = cred.get("users", ["admin"])
        self.passwords: List[str] = cred.get("passwords", ["", "admin"])

        # Porty (podpora pro int i list intu, napr. winbox: [8291, 33333])
        ports = self.raw_data.get("ports", {})
        ssh_cfg = ports.get("ssh", 22)
        self.ports_ssh: List[int] = [int(p) for p in ssh_cfg] if isinstance(ssh_cfg, list) else [int(ssh_cfg)]
        self.port_ssh: int = self.ports_ssh[0]

        winbox_cfg = ports.get("winbox", 8291)
        self.ports_winbox: List[int] = [int(p) for p in winbox_cfg] if isinstance(winbox_cfg, list) else [int(winbox_cfg)]
        self.port_winbox: int = self.ports_winbox[0]

        self.port_api: int = ports.get("api", 8728)
        self.port_api_ssl: int = ports.get("api_ssl", 8729)

        # Skener
        scanner = self.raw_data.get("scanner", {})
        self.ping_threads: int = scanner.get("ping_threads", 100)
        self.ping_timeout: float = float(scanner.get("ping_timeout", 1.0))
        self.port_threads: int = scanner.get("port_threads", 50)
        self.port_timeout: float = float(scanner.get("port_timeout", 1.5))
        self.auth_threads: int = scanner.get("auth_threads", 20)
        self.ssh_timeout: float = float(scanner.get("ssh_timeout", 8.0))

        # Timeouty
        tm = self.raw_data.get("timeouts", {})
        self.initial_boot_delay: int = tm.get("initial_boot_delay", 60)
        self.ping_retry_interval: int = tm.get("ping_retry_interval", 10)
        self.max_recovery_timeout: int = tm.get("max_recovery_timeout", 600)

        # DNS servery pro aktualizace
        dns_cfg = self.raw_data.get("dns", {})
        dns_list = dns_cfg.get("servers", ["46.149.125.37", "8.8.8.8"])
        if isinstance(dns_list, str):
            dns_list = [s.strip() for s in dns_list.split(",") if s.strip()]
        self.dns_servers: List[str] = [str(s) for s in dns_list]

        # Updater
        upd = self.raw_data.get("updater", {})
        self.updater_workers: int = int(upd.get("workers", 10))
        self.max_attempts: int = upd.get("max_attempts", 3)
        self.min_disk_free_mb: float = float(upd.get("min_disk_free_mb", 2.0))
        self.allow_major_upgrade: bool = upd.get("allow_major_upgrade", False)
        ch = upd.get("channels", {})
        self.channel_v6: str = ch.get("v6", "https://upgrade.mikrotik.com/routeros/NEWEST6.stable")
        v7_url = ch.get("v7", "https://upgrade.mikrotik.com/routeros/NEWESTa7.stable")
        if "NEWEST7.stable" in v7_url:
            v7_url = v7_url.replace("NEWEST7.stable", "NEWESTa7.stable")
        self.channel_v7: str = v7_url

        # Logovani
        log_cfg = self.raw_data.get("logging", {})
        self.log_level: str = log_cfg.get("level", "INFO").upper()
        self.log_file: str = str(self.base_dir / log_cfg.get("file", "data/mk_manager.log"))
        self.log_max_bytes: int = log_cfg.get("max_bytes", 10 * 1024 * 1024)
        self.log_backup_count: int = log_cfg.get("backup_count", 5)

        # Databaze
        db_cfg = self.raw_data.get("database", {})
        self.db_path: str = str(self.base_dir / db_cfg.get("path", "data/network.db"))

    def _load_yaml(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return {}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f)
                return content if isinstance(content, dict) else {}
        except Exception as e:
            print(f"Chyba pri nacitani {self.config_path}: {e}", file=sys.stderr)
            return {}

    def validate_config(self) -> List[str]:
        # Validace konfigurace a varovani pred ukazkovymi daty
        warnings: List[str] = []
        if not self.config_path.exists():
            warnings.append(f"Konfiguracni soubor '{self.config_path}' neexistuje. Spustte './install.sh' nebo zkopirujte 'config.example.yaml'.")
            return warnings

        dummy_pwds = {"VaseSilneHeslo1", "VaseSilneHeslo2", "admin", "password", "123456"}
        configured_pwds = set(self.passwords)
        intersect = configured_pwds.intersection(dummy_pwds)
        if intersect:
            warnings.append(f"V {self.config_path} jsou ponechana ukazkova hesla ({', '.join(intersect)})!")

        if self.networks == ["192.168.88.0/24", "10.10.10.0/24"]:
            warnings.append(f"V {self.config_path} jsou nastaveny vychozi ukazkove rozsahy. Nastavte vase skutecne CIDR rozsahy.")

        return warnings


def setup_logger(config: Config) -> logging.Logger:
    logger = logging.getLogger("mk_manager")
    numeric_level = getattr(logging, config.log_level, logging.INFO)
    logger.setLevel(numeric_level)

    # Zabraneni vicenasobnym handlerum
    if logger.handlers:
        return logger

    # Zajisteni existence ciloveho adresare pro log
    log_dir = Path(config.log_file).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    # Rotujici souborovy handler
    file_handler = RotatingFileHandler(
        config.log_file,
        maxBytes=config.log_max_bytes,
        backupCount=config.log_backup_count,
        encoding="utf-8",
    )
    file_fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] [%(name)s:%(filename)s:%(lineno)d]: %(message)s"
    )
    file_handler.setFormatter(file_fmt)
    file_handler.setLevel(numeric_level)
    logger.addHandler(file_handler)

    # Konzolovy rich handler pro CLI
    rich_handler = RichHandler(
        rich_tracebacks=True,
        show_time=True,
        show_level=True,
        show_path=False,
    )
    rich_handler.setLevel(numeric_level)
    logger.addHandler(rich_handler)

    # Potlaceni nadbytecneho debugu z paramiko
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    return logger

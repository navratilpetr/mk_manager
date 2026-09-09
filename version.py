# Definice verze aplikace a kontrola aktualizaci z GitHubu
import urllib.request
import json
from typing import Optional

__version__ = "1.0.1"


def get_latest_github_version(repo: str = "navratilpetr/mk_manager", timeout: float = 2.0) -> Optional[str]:
    # Zjisteni nejnovejsi verze z GitHub API s nizkym timeoutem
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"mk_manager/{__version__}", "Accept": "application/vnd.github.v3+json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            tag = data.get("tag_name", "")
            return tag.lstrip("v") if tag else None
    except Exception:
        # Fallback na tags API pokud release jeste nebyl rucne vytvoren pres UI
        try:
            url_tags = f"https://api.github.com/repos/{repo}/tags"
            req_tags = urllib.request.Request(
                url_tags,
                headers={"User-Agent": f"mk_manager/{__version__}", "Accept": "application/vnd.github.v3+json"}
            )
            with urllib.request.urlopen(req_tags, timeout=timeout) as resp:
                tags = json.loads(resp.read().decode("utf-8"))
                if tags and isinstance(tags, list):
                    first_tag = tags[0].get("name", "")
                    return first_tag.lstrip("v") if first_tag else None
        except Exception:
            pass
        return None


def parse_version_tuple(ver_str: str) -> tuple:
    parts = []
    for p in ver_str.lstrip("v").split("."):
        digits = "".join(filter(str.isdigit, p))
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def is_newer_version(remote: str, local: str) -> bool:
    try:
        return parse_version_tuple(remote) > parse_version_tuple(local)
    except Exception:
        return False


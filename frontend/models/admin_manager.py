"""
admin_manager.py
Handles administrator account storage and authentication.

Storage format (admins.txt) — one record per line:
    username,sha256_hash,backend_url,os_type

Backward-compatible: older 2-column lines (username,hash) are read fine;
missing fields default to "" and "auto".
"""

import hashlib
from pathlib import Path

ADMINS_FILE = Path(__file__).resolve().parent.parent / "admins.txt"

OS_CHOICES = ("auto", "windows", "linux")


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _parse_line(line: str) -> tuple[str, dict] | tuple[None, None]:
    """Parse a CSV line → (username, record_dict) or (None, None)."""
    parts = line.strip().split(",")
    if len(parts) < 2:
        return None, None
    username  = parts[0].strip()
    pwd_hash  = parts[1].strip()
    backend   = parts[2].strip() if len(parts) > 2 else ""
    os_type   = parts[3].strip() if len(parts) > 3 else "auto"
    if not username or not pwd_hash:
        return None, None
    return username, {"hash": pwd_hash, "backend_url": backend, "os_type": os_type}


def load_admins() -> dict:
    """Return {username: {hash, backend_url, os_type}} for all stored admins."""
    admins = {}
    try:
        with open(ADMINS_FILE, "r") as f:
            for line in f:
                username, record = _parse_line(line)
                if username:
                    admins[username] = record
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[AdminManager] Load error: {e}")
    return admins


def save_admins(admins: dict) -> None:
    """Persist all admin records."""
    try:
        with open(ADMINS_FILE, "w") as f:
            for username, rec in admins.items():
                pwd   = rec["hash"] if len(rec["hash"]) == 64 else _hash_password(rec["hash"])
                url   = rec.get("backend_url", "")
                os_t  = rec.get("os_type", "auto")
                f.write(f"{username},{pwd},{url},{os_t}\n")
    except Exception as e:
        print(f"[AdminManager] Save error: {e}")


def add_admin(username: str, password: str,
              backend_url: str = "", os_type: str = "auto") -> bool:
    admins = load_admins()
    if username in admins:
        return False
    admins[username] = {
        "hash"       : _hash_password(password),
        "backend_url": backend_url,
        "os_type"    : os_type if os_type in OS_CHOICES else "auto",
    }
    save_admins(admins)
    return True


def delete_admin(username: str) -> bool:
    admins = load_admins()
    if username not in admins:
        return False
    del admins[username]
    save_admins(admins)
    return True


def check_admin(username: str, password: str) -> bool:
    admins = load_admins()
    rec = admins.get(username)
    if rec is None:
        return False
    return rec["hash"] == _hash_password(password)


def get_admin_backend_url(username: str) -> str:
    rec = load_admins().get(username, {})
    return rec.get("backend_url", "")


def update_admin_backend(username: str, backend_url: str) -> bool:
    admins = load_admins()
    if username not in admins:
        return False
    admins[username]["backend_url"] = backend_url
    save_admins(admins)
    return True


def get_admin_os(username: str) -> str:
    rec = load_admins().get(username, {})
    return rec.get("os_type", "auto")


def update_admin_os(username: str, os_type: str) -> bool:
    admins = load_admins()
    if username not in admins:
        return False
    admins[username]["os_type"] = os_type if os_type in OS_CHOICES else "auto"
    save_admins(admins)
    return True


def admin_exists(username: str) -> bool:
    return username in load_admins()


def load_admin_full(username: str) -> dict:
    return load_admins().get(username, {})


def ensure_default_admin() -> None:
    if not load_admins():
        add_admin("admin", "admin123")
        print(
            "[AdminManager] WARNING: Default account created — "
            "username: admin  password: admin123. Please change this."
        )

"""
admin_manager.py
Handles administrator account storage and authentication.
Passwords are stored as SHA-256 hashes.
"""

import hashlib
from pathlib import Path

ADMINS_FILE = Path(__file__).resolve().parent.parent / "admins.txt"


def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def load_admins() -> dict:
    admins = {}
    try:
        with open(ADMINS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if "," in line:
                    parts = line.split(",", 1)
                    username, hashed_pwd = parts[0].strip(), parts[1].strip()
                    if username:
                        admins[username] = hashed_pwd
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"[AdminManager] Load error: {e}")
    return admins


def save_admins(admins: dict) -> None:
    try:
        with open(ADMINS_FILE, "w") as f:
            for username, pwd in admins.items():
                hashed = pwd if len(pwd) == 64 else _hash_password(pwd)
                f.write(f"{username},{hashed}\n")
    except Exception as e:
        print(f"[AdminManager] Save error: {e}")


def add_admin(username: str, password: str, backend_url: str = "") -> bool:
    admins = load_admins()
    if username in admins:
        return False
    admins[username] = _hash_password(password)
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
    stored_hash = admins.get(username)
    if stored_hash is None:
        return False
    return stored_hash == _hash_password(password)


def get_admin_backend_url(username: str) -> str:
    return ""


def update_admin_backend(username: str, backend_url: str) -> bool:
    return False


def admin_exists(username: str) -> bool:
    return username in load_admins()


def load_admin_full(username: str) -> dict:
    admins = load_admins()
    if username in admins:
        return {"hash": admins[username], "backend_url": ""}
    return {}


def ensure_default_admin() -> None:
    if not load_admins():
        add_admin("admin", "admin123")
        print(
            "[AdminManager] WARNING: Default account created — "
            "username: admin  password: admin123. Please change this."
        )

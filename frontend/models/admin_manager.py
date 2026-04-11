"""
admin_manager.py
Handles administrator account storage, retrieval, and authentication.
Passwords are stored as SHA-256 hashes — never in plain text.
"""

import hashlib
from pathlib import Path

# Always resolve relative to this file so it works regardless of
# which directory server.py is launched from
ADMINS_FILE = Path(__file__).resolve().parent.parent / "admins.txt"


def _hash_password(password: str) -> str:
    """Return the SHA-256 hex digest of a password string."""
    return hashlib.sha256(password.encode()).hexdigest()


def load_admins() -> dict:
    """
    Load admins from file.
    Returns a dict of {username: hashed_password}.
    Lines that don't match the expected format are silently skipped.
    """
    admins = {}
    try:
        with open(ADMINS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if "," in line:
                    parts = line.split(",", 1)   # only split on the first comma
                    username, hashed_pwd = parts[0].strip(), parts[1].strip()
                    if username:
                        admins[username] = hashed_pwd
    except FileNotFoundError:
        # First run — no admins file yet; that's fine
        pass
    except Exception as e:
        print(f"[AdminManager] Load error: {e}")
    return admins


def save_admins(admins: dict) -> None:
    """
    Persist admins dict to file.
    Values that are not yet hashed (plain text, length != 64) are hashed
    before saving so the UI can pass raw passwords directly.
    """
    try:
        with open(ADMINS_FILE, "w") as f:
            for username, pwd in admins.items():
                # If the stored value doesn't look like a SHA-256 hash, hash it now
                hashed = pwd if len(pwd) == 64 else _hash_password(pwd)
                f.write(f"{username},{hashed}\n")
    except Exception as e:
        print(f"[AdminManager] Save error: {e}")


def add_admin(username: str, password: str) -> bool:
    """
    Add a new admin account.
    Returns False if the username already exists, True on success.
    """
    admins = load_admins()
    if username in admins:
        return False
    admins[username] = _hash_password(password)
    save_admins(admins)
    return True


def delete_admin(username: str) -> bool:
    """
    Remove an admin account by username.
    Returns True if deleted, False if the user didn't exist.
    """
    admins = load_admins()
    if username not in admins:
        return False
    del admins[username]
    save_admins(admins)
    return True


def check_admin(username: str, password: str) -> bool:
    """
    Verify credentials.
    Returns True only when both the username exists and the
    SHA-256 hash of the supplied password matches the stored hash.
    """
    admins = load_admins()
    stored_hash = admins.get(username)
    if stored_hash is None:
        return False
    return stored_hash == _hash_password(password)


def admin_exists(username: str) -> bool:
    """Return True if an admin with this username is registered."""
    return username in load_admins()


def ensure_default_admin() -> None:
    """
    If no admins exist at all, create a default admin account so the
    application is never locked out on first run.
    Prints a warning so the operator knows to change the password.
    """
    if not load_admins():
        add_admin("admin", "admin123")
        print(
            "[AdminManager] WARNING: No admins found. "
            "Default account created — username: admin  password: admin123. "
            "Please change this immediately."
        )
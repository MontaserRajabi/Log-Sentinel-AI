"""
admin_manager.py
Handles user account storage and authentication using Azure Cosmos DB.

Container: sentinel / users
Partition key: /username
Document shape:
    {
        "id":             "username",
        "username":       "username",
        "hash":           "<sha256 hex>",
        "role":           "admin" | "user",
        "backend_url":    "",
        "os_type":        "auto",
        "email":          "",
        "source_machine": ""
    }
"""

import hashlib
import os
import logging
from dotenv import load_dotenv

load_dotenv()

try:
    from azure.cosmos import CosmosClient, exceptions as cosmos_exc
    _cosmos_available = True
except ImportError:
    _cosmos_available = False
    logging.warning("azure-cosmos not installed — falling back to admins.txt")

OS_CHOICES   = ("auto", "windows", "linux")
ROLE_CHOICES = ("admin", "user")

# ── Cosmos DB client (lazy) ────────────────────────────────────────────────

_container = None


def _get_container():
    global _container
    if _container is not None:
        return _container
    if not _cosmos_available:
        return None
    conn = os.getenv("COSMOS_CONNECTION_STRING", "")
    if not conn:
        return None
    try:
        client     = CosmosClient.from_connection_string(conn)
        database   = client.get_database_client("sentinel")
        _container = database.get_container_client("users")
        _container.read()
        logging.info("Cosmos DB connected — sentinel/users")
    except Exception as e:
        logging.error("Cosmos DB connection failed: %s", e)
        _container = None
    return _container


# ── Password hashing ───────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


# ── Fallback: flat-file (local dev without Cosmos) ────────────────────────

from pathlib import Path
_ADMINS_FILE = Path(__file__).resolve().parent.parent / "admins.txt"


def _file_load() -> dict:
    admins = {}
    try:
        with open(_ADMINS_FILE) as f:
            for line in f:
                parts = line.strip().split(",")
                if len(parts) < 2:
                    continue
                u = parts[0].strip()
                if not u:
                    continue
                raw_verified = parts[6].strip() if len(parts) > 6 else "1"
                admins[u] = {
                    "hash":        parts[1].strip(),
                    "backend_url": parts[2].strip() if len(parts) > 2 else "",
                    "os_type":     parts[3].strip() if len(parts) > 3 else "auto",
                    "email":       parts[4].strip() if len(parts) > 4 else "",
                    "role":        parts[5].strip() if len(parts) > 5 else "admin",
                    "verified":    raw_verified != "0",
                }
    except FileNotFoundError:
        pass
    return admins


def _file_save(admins: dict) -> None:
    with open(_ADMINS_FILE, "w") as f:
        for u, r in admins.items():
            h = r["hash"] if len(r["hash"]) == 64 else _hash_password(r["hash"])
            verified_flag = "1" if r.get("verified", True) else "0"
            f.write(f"{u},{h},{r.get('backend_url','')},{r.get('os_type','auto')},{r.get('email','')},{r.get('role','user')},{verified_flag}\n")


# ── Core Cosmos helpers ────────────────────────────────────────────────────

def _upsert(username: str, rec: dict) -> None:
    c = _get_container()
    if c is None:
        admins = _file_load()
        admins[username] = rec
        _file_save(admins)
        return
    doc = {
        "id":             username,
        "username":       username,
        "hash":           rec.get("hash", ""),
        "role":           rec.get("role", "user"),
        "backend_url":    rec.get("backend_url", ""),
        "os_type":        rec.get("os_type", "auto"),
        "email":          rec.get("email", ""),
        "source_machine": rec.get("source_machine", ""),
        "verified":       bool(rec.get("verified", True)),
    }
    try:
        c.upsert_item(doc)
    except Exception as e:
        logging.error("_upsert Cosmos error: %s", e)


def _read_user(username: str) -> dict | None:
    c = _get_container()
    if c is None:
        return _file_load().get(username)
    try:
        item = c.read_item(item=username, partition_key=username)
        return {
            "hash":           item.get("hash", ""),
            "role":           item.get("role", "user"),
            "backend_url":    item.get("backend_url", ""),
            "os_type":        item.get("os_type", "auto"),
            "email":          item.get("email", ""),
            "source_machine": item.get("source_machine", ""),
            "verified":       bool(item.get("verified", True)),
        }
    except cosmos_exc.CosmosResourceNotFoundError:
        return None
    except Exception as e:
        logging.error("_read_user Cosmos error: %s", e)
        return None


# ── Public API ─────────────────────────────────────────────────────────────

def load_admins() -> dict:
    c = _get_container()
    if c is None:
        return _file_load()
    try:
        items = list(c.query_items("SELECT * FROM users", enable_cross_partition_query=True))
        return {
            item["username"]: {
                "hash":           item.get("hash", ""),
                "role":           item.get("role", "user"),
                "backend_url":    item.get("backend_url", ""),
                "os_type":        item.get("os_type", "auto"),
                "email":          item.get("email", ""),
                "source_machine": item.get("source_machine", ""),
                "verified":       bool(item.get("verified", True)),
            }
            for item in items
        }
    except Exception as e:
        logging.error("load_admins Cosmos error: %s", e)
        return {}


def save_admins(admins: dict) -> None:
    c = _get_container()
    if c is None:
        _file_save(admins)
        return
    for username, rec in admins.items():
        _upsert(username, rec)


def add_admin(username: str, password: str,
              backend_url: str = "", os_type: str = "auto",
              email: str = "", role: str = "user",
              verified: bool = True) -> bool:
    if _read_user(username) is not None:
        return False
    _upsert(username, {
        "hash":        _hash_password(password),
        "role":        role if role in ROLE_CHOICES else "user",
        "backend_url": backend_url,
        "os_type":     os_type if os_type in OS_CHOICES else "auto",
        "email":       email.strip().lower(),
        "verified":    verified,
    })
    return True


def is_verified(username: str) -> bool:
    """Return True if the user's email has been verified (or if the field is absent for backward compat)."""
    rec = _read_user(username)
    if rec is None:
        return False
    return rec.get("verified", True)


def mark_verified(username: str) -> bool:
    """Mark a user's email as verified. Returns False if the user does not exist."""
    rec = _read_user(username)
    if rec is None:
        return False
    rec["verified"] = True
    _upsert(username, rec)
    return True


def delete_admin(username: str) -> bool:
    c = _get_container()
    if c is None:
        admins = _file_load()
        if username not in admins:
            return False
        del admins[username]
        _file_save(admins)
        return True
    try:
        c.delete_item(item=username, partition_key=username)
        return True
    except cosmos_exc.CosmosResourceNotFoundError:
        return False
    except Exception as e:
        logging.error("delete_admin Cosmos error: %s", e)
        return False


def check_admin(username: str, password: str) -> bool:
    rec = _read_user(username)
    if rec is None:
        return False
    return rec["hash"] == _hash_password(password)


def get_user_role(username: str) -> str:
    rec = _read_user(username) or {}
    return rec.get("role", "user")


def update_user_role(username: str, role: str) -> bool:
    rec = _read_user(username)
    if rec is None:
        return False
    rec["role"] = role if role in ROLE_CHOICES else "user"
    _upsert(username, rec)
    return True


def get_admin_backend_url(username: str) -> str:
    rec = _read_user(username) or {}
    return rec.get("backend_url", "")


def update_admin_backend(username: str, backend_url: str) -> bool:
    rec = _read_user(username)
    if rec is None:
        return False
    rec["backend_url"] = backend_url
    _upsert(username, rec)
    return True


def get_admin_os(username: str) -> str:
    rec = _read_user(username) or {}
    return rec.get("os_type", "auto")


def update_admin_os(username: str, os_type: str) -> bool:
    rec = _read_user(username)
    if rec is None:
        return False
    rec["os_type"] = os_type if os_type in OS_CHOICES else "auto"
    _upsert(username, rec)
    return True


def get_admin_email(username: str) -> str:
    rec = _read_user(username) or {}
    return rec.get("email", "")


def update_admin_email(username: str, email: str) -> bool | str:
    """Update email. Returns True on success, or an error string if the email is already in use."""
    rec = _read_user(username)
    if rec is None:
        return False
    email = email.strip().lower()
    if email:
        owner = find_admin_by_email(email)
        if owner and owner != username:
            return "email_taken"
    rec["email"] = email
    _upsert(username, rec)
    return True


def update_admin_password(username: str, new_password: str) -> bool:
    rec = _read_user(username)
    if rec is None:
        return False
    rec["hash"] = _hash_password(new_password)
    _upsert(username, rec)
    return True


def find_admin_by_email(email: str) -> str | None:
    email = email.strip().lower()
    c = _get_container()
    if c is None:
        for u, r in _file_load().items():
            if r.get("email", "").lower() == email:
                return u
        return None
    try:
        items = list(c.query_items(
            "SELECT * FROM users u WHERE u.email = @email",
            parameters=[{"name": "@email", "value": email}],
            enable_cross_partition_query=True,
        ))
        return items[0]["username"] if items else None
    except Exception as e:
        logging.error("find_admin_by_email Cosmos error: %s", e)
        return None


def admin_exists(username: str) -> bool:
    return _read_user(username) is not None


def load_admin_full(username: str) -> dict:
    return _read_user(username) or {}


def get_user_machine(username: str) -> str:
    rec = _read_user(username) or {}
    return rec.get("source_machine", "")


def update_user_machine(username: str, machine: str) -> bool:
    rec = _read_user(username)
    if rec is None:
        return False
    # Store lowercase so matching is case-insensitive regardless of OS
    rec["source_machine"] = machine.strip().lower()
    _upsert(username, rec)
    return True


def find_users_by_machine(machine: str) -> list[dict]:
    """Return list of {username, email} for users assigned to this machine."""
    machine = machine.strip().lower()
    if not machine:
        return []
    c = _get_container()
    if c is None:
        return [
            {"username": u, "email": r.get("email", "")}
            for u, r in _file_load().items()
            if r.get("source_machine", "").strip().lower() == machine and r.get("email")
        ]
    try:
        items = list(c.query_items(
            "SELECT * FROM users u WHERE u.source_machine = @m",
            parameters=[{"name": "@m", "value": machine}],
            enable_cross_partition_query=True,
        ))
        return [
            {"username": item["username"], "email": item.get("email", "")}
            for item in items
            if item.get("email")
        ]
    except Exception as e:
        logging.error("find_users_by_machine Cosmos error: %s", e)
        return []


def ensure_default_admin() -> None:
    if not load_admins():
        add_admin("admin", "admin123", role="admin")
        logging.warning(
            "Default account created — username: admin  password: admin123. "
            "Please change this immediately."
        )

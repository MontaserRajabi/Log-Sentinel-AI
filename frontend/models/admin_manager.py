"""
admin_manager.py
Handles administrator account storage, retrieval, and authentication.
Passwords are stored as SHA-256 hashes — never in plain text.

Storage backends (selected automatically):
  1. Azure SQL / PostgreSQL / any RDBMS  — when DATABASE_URL is set in env
  2. Flat file (admins.txt)              — fallback for local development
"""

import hashlib
import os
from pathlib import Path

# ── Flat-file fallback ────────────────────────────────────────────────────────
ADMINS_FILE = Path(__file__).resolve().parent.parent / "admins.txt"

# ── Database backend (optional) ───────────────────────────────────────────────
DATABASE_URL = os.environ.get("DATABASE_URL", "")

_engine = None
_db_ready = False


def _get_engine():
    """Lazy-init SQLAlchemy engine. Returns None if DATABASE_URL is not set."""
    global _engine, _db_ready
    if _db_ready:
        return _engine
    if not DATABASE_URL:
        _db_ready = True
        return None
    try:
        from sqlalchemy import create_engine, text

        # Azure SQL uses mssql+pyodbc:// — add TrustServerCertificate for Azure
        url = DATABASE_URL
        _engine = create_engine(
            url,
            pool_pre_ping=True,
            connect_args={"connect_timeout": 5},
        )
        # Create table if it doesn't exist
        with _engine.connect() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS admins (
                    username      VARCHAR(120) PRIMARY KEY,
                    password_hash VARCHAR(64)  NOT NULL,
                    backend_url   VARCHAR(500) DEFAULT ''
                )
            """))
            conn.commit()
        _db_ready = True
        print("[AdminManager] Connected to database.")
    except Exception as e:
        print(f"[AdminManager] DB init error: {e}  — falling back to file.")
        _engine = None
        _db_ready = True
    return _engine


# ── Password hashing ──────────────────────────────────────────────────────────

def _hash_password(password: str) -> str:
    """Return the SHA-256 hex digest of a password string."""
    return hashlib.sha256(password.encode()).hexdigest()


# ── Database helpers ──────────────────────────────────────────────────────────

def _db_load_admins() -> dict:
    """Load all admins from DB. Returns {username: {'hash': ..., 'backend_url': ...}}."""
    from sqlalchemy import text
    engine = _get_engine()
    if not engine:
        return None
    try:
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT username, password_hash, backend_url FROM admins")).fetchall()
        return {r[0]: {"hash": r[1], "backend_url": r[2] or ""} for r in rows}
    except Exception as e:
        print(f"[AdminManager] DB read error: {e}")
        return None


def _db_upsert_admin(username: str, password_hash: str, backend_url: str = "") -> bool:
    from sqlalchemy import text
    engine = _get_engine()
    if not engine:
        return False
    try:
        with engine.connect() as conn:
            # Try UPDATE first, then INSERT (works across SQL dialects)
            result = conn.execute(
                text("UPDATE admins SET password_hash=:h, backend_url=:b WHERE username=:u"),
                {"h": password_hash, "b": backend_url, "u": username}
            )
            if result.rowcount == 0:
                conn.execute(
                    text("INSERT INTO admins (username, password_hash, backend_url) VALUES (:u, :h, :b)"),
                    {"u": username, "h": password_hash, "b": backend_url}
                )
            conn.commit()
        return True
    except Exception as e:
        print(f"[AdminManager] DB write error: {e}")
        return False


def _db_delete_admin(username: str) -> bool:
    from sqlalchemy import text
    engine = _get_engine()
    if not engine:
        return False
    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("DELETE FROM admins WHERE username=:u"), {"u": username}
            )
            conn.commit()
        return result.rowcount > 0
    except Exception as e:
        print(f"[AdminManager] DB delete error: {e}")
        return False


# ── File helpers (fallback) ───────────────────────────────────────────────────

def load_admins() -> dict:
    """
    Load admins. Returns {username: hashed_password}.
    Uses DB when available, file otherwise.
    """
    db = _db_load_admins()
    if db is not None:
        return {u: v["hash"] for u, v in db.items()}

    # File fallback
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


def load_admin_full(username: str) -> dict:
    """
    Return full record {hash, backend_url} for a single user.
    Used at login to retrieve stored backend_url.
    """
    db = _db_load_admins()
    if db is not None:
        return db.get(username, {})
    # File fallback — no backend_url stored in file
    admins = load_admins()
    if username in admins:
        return {"hash": admins[username], "backend_url": ""}
    return {}


def save_admins(admins: dict) -> None:
    """Persist admins dict. DB takes priority over file."""
    engine = _get_engine()
    if engine:
        for username, pwd in admins.items():
            hashed = pwd if len(pwd) == 64 else _hash_password(pwd)
            _db_upsert_admin(username, hashed)
        return
    # File fallback
    try:
        with open(ADMINS_FILE, "w") as f:
            for username, pwd in admins.items():
                hashed = pwd if len(pwd) == 64 else _hash_password(pwd)
                f.write(f"{username},{hashed}\n")
    except Exception as e:
        print(f"[AdminManager] Save error: {e}")


# ── Public API ────────────────────────────────────────────────────────────────

def add_admin(username: str, password: str, backend_url: str = "") -> bool:
    """
    Add a new admin account.
    Returns False if the username already exists, True on success.
    """
    engine = _get_engine()
    if engine:
        db = _db_load_admins()
        if db is not None and username in db:
            return False
        return _db_upsert_admin(username, _hash_password(password), backend_url)

    # File fallback
    admins = load_admins()
    if username in admins:
        return False
    admins[username] = _hash_password(password)
    save_admins(admins)
    return True


def update_admin_backend(username: str, backend_url: str) -> bool:
    """Update the stored backend_url for an existing admin."""
    engine = _get_engine()
    if engine:
        db = _db_load_admins()
        if db is None or username not in db:
            return False
        return _db_upsert_admin(username, db[username]["hash"], backend_url)
    return False  # not supported in file mode


def delete_admin(username: str) -> bool:
    """Remove an admin account. Returns True if deleted."""
    engine = _get_engine()
    if engine:
        return _db_delete_admin(username)

    admins = load_admins()
    if username not in admins:
        return False
    del admins[username]
    save_admins(admins)
    return True


def check_admin(username: str, password: str) -> bool:
    """
    Verify credentials. Returns True only on match.
    """
    record = load_admin_full(username)
    stored_hash = record.get("hash")
    if stored_hash is None:
        return False
    return stored_hash == _hash_password(password)


def get_admin_backend_url(username: str) -> str:
    """Return the saved backend_url for this user (empty string if none)."""
    return load_admin_full(username).get("backend_url", "")


def admin_exists(username: str) -> bool:
    """Return True if an admin with this username is registered."""
    return username in load_admins()


def ensure_default_admin() -> None:
    """
    If no admins exist at all, create a default admin account.
    Prints a warning so the operator knows to change the password.
    """
    if not load_admins():
        add_admin("admin", "admin123")
        print(
            "[AdminManager] WARNING: No admins found. "
            "Default account created — username: admin  password: admin123. "
            "Please change this immediately."
        )

"""
log_collector.py — Log Sentinel AI
=====================================
Automatically detects the host operating system (Windows or Linux),
locates the appropriate system log files, reads new entries continuously,
and feeds them to the AI anomaly detection model in real time.

Aligns with the report:
  - Section 3.1.1 Functional Requirements:
      "detect the host OS and locate the appropriate log file paths"
      "continuously monitor log files for new or updated entries in real time"
      "resume log analysis from the last read position after a restart"
  - Section 3.3 System Architecture:
      Log Collector → AI Analyzer → Alert Generator
  - Section 3.7 Threat Model (Table 3.1):
      Detects brute-force, privilege escalation, DoS, log tampering,
      suspicious startup, and network intrusion patterns

Place this file at:
    src/ingest/log_collector.py

Run directly:
    python src/ingest/log_collector.py
    python src/ingest/log_collector.py --interval 10 --verbose

It is also importable so the GUI / API can call start_collector() in a
background thread.
"""

import argparse
import json
import logging
import os
import platform
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Project-root resolution (works from any cwd) ───────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parents[2]   # src/ingest/ → src/ → project/

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_MODEL       = PROJECT_ROOT / "models" / "isoforest.pkl"
DEFAULT_META        = PROJECT_ROOT / "models" / "feature_meta.json"
DEFAULT_CURSOR_FILE = PROJECT_ROOT / "data" / "staging" / "collector_cursor.json"
DEFAULT_EVENTS_OUT  = PROJECT_ROOT / "data" / "staging" / "events.jsonl"
DEFAULT_ALERTS_OUT  = PROJECT_ROOT / "data" / "staging" / "alerts.jsonl"
DEFAULT_INTERVAL    = 30         # seconds between polling cycles
ANOMALY_SCORE_THRESHOLD = 0.10   # decision_function scores below this → alert
                                  # Windows model scores range ~0.04–0.33; 0.10 catches bottom ~5th percentile

# ── OS-specific log source definitions ────────────────────────────────────────
#
# Each source is a dict:
#   name     : human-readable label
#   type     : "file" | "winlog"
#   path     : Path to log file  (type=file only)
#   channel  : Windows Event Log channel name  (type=winlog only)

LINUX_LOG_SOURCES = [
    {"name": "auth",    "type": "file", "path": Path("/var/log/auth.log")},
    {"name": "syslog",  "type": "file", "path": Path("/var/log/syslog")},
    {"name": "messages","type": "file", "path": Path("/var/log/messages")},
    {"name": "kern",    "type": "file", "path": Path("/var/log/kern.log")},
    {"name": "dpkg",    "type": "file", "path": Path("/var/log/dpkg.log")},
]

WINDOWS_LOG_SOURCES = [
    {"name": "Security",    "type": "winlog", "channel": "Security"},
    {"name": "System",      "type": "winlog", "channel": "System"},
    {"name": "Application", "type": "winlog", "channel": "Application"},
]

# Windows Event IDs that are always high-priority (mapped to threat category)
WINDOWS_HIGH_PRIORITY_IDS = {
    4625: "brute_force",       # Failed logon
    4648: "brute_force",       # Logon using explicit credentials
    4720: "privilege_esc",     # User account created
    4728: "privilege_esc",     # Member added to security-enabled global group
    4732: "privilege_esc",     # Member added to security-enabled local group
    4756: "privilege_esc",     # Member added to universal security group
    4698: "startup",           # Scheduled task created
    4702: "startup",           # Scheduled task updated
    7045: "startup",           # New service installed
    1102: "log_tamper",        # Audit log cleared
    4719: "log_tamper",        # System audit policy changed
    4657: "privilege_esc",     # Registry value modified
}

# ── Threat keyword map (mirrors build_features.py) ────────────────────────────
THREAT_KEYWORDS = {
    "brute_force"   : ["failed", "invalid", "wrong password", "authentication failure",
                       "login failed", "bad credentials"],
    "privilege_esc" : ["privilege", "escalation", "sudo", "root", "admin", "elevated",
                       "permission denied", "unauthorized"],
    "dos"           : ["flood", "overload", "too many requests", "rate limit",
                       "connection refused", "timeout"],
    "log_tamper"    : ["deleted", "modified", "cleared", "truncated", "log rotation"],
    "startup"       : ["startup", "boot", "init", "service start", "autorun",
                       "scheduled task", "cron"],
    "network"       : ["port scan", "ssh", "firewall", "connection attempt",
                       "remote", "intrusion"],
}


# ══════════════════════════════════════════════════════════════════════════════
# OS DETECTION + PRIVILEGE HANDLING
# ══════════════════════════════════════════════════════════════════════════════

def is_admin() -> bool:
    """
    Return True if the current process has administrator / root privileges.
    Works on both Windows and Linux.
    """
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def relaunch_as_admin() -> None:
    """
    Re-launch the current script with administrator privileges using UAC
    (Windows ShellExecute runas verb).  The current non-elevated process
    then exits so only the elevated copy runs.
    """
    import ctypes
    logger.warning(
        "Not running as Administrator. "
        "Requesting elevation via UAC — accept the prompt to continue."
    )
    # ShellExecuteW runas triggers the UAC elevation dialog
    ret = ctypes.windll.shell32.ShellExecuteW(
        None,                       # parent window handle
        "runas",                    # verb  → triggers UAC
        sys.executable,             # program to run
        " ".join(sys.argv),         # original arguments
        None,                       # working directory (inherit)
        1,                          # SW_NORMAL — show window
    )
    # ShellExecuteW returns > 32 on success
    if ret <= 32:
        logger.error(
            "UAC elevation failed or was denied (code %d). "
            "Please right-click and choose 'Run as administrator'.", ret
        )
    sys.exit(0)   # exit the non-elevated copy regardless


def _probe_winlog_channel(channel: str) -> bool:
    """
    Try to open a Windows Event Log channel to check if we have read access.
    Returns True if accessible, False if a privilege error occurs.
    Logs a single clear warning on failure instead of repeating every cycle.
    """
    try:
        import win32evtlog
        hand = win32evtlog.OpenEventLog(None, channel)
        win32evtlog.CloseEventLog(hand)
        return True
    except ImportError:
        return False
    except Exception as exc:
        err_code = getattr(exc, "winerror", None)
        if err_code == 1314:   # ERROR_PRIVILEGE_NOT_HELD
            logger.warning(
                "Skipping channel '%s': requires Administrator privileges "
                "(winerror 1314). Run the script as Administrator to include it.",
                channel,
            )
        else:
            logger.warning("Skipping channel '%s': %s", channel, exc)
        return False


def detect_os() -> str:
    """
    Detect the host operating system.
    Returns 'windows', 'linux', or raises RuntimeError for unsupported systems.
    """
    system = platform.system().lower()
    if system == "windows":
        logger.info("OS detected: Windows (%s)", platform.version())
        return "windows"
    elif system == "linux":
        logger.info("OS detected: Linux (%s)", platform.release())
        return "linux"
    else:
        raise RuntimeError(
            f"Unsupported operating system: {platform.system()}. "
            "Log Sentinel AI supports Windows and Linux only."
        )


def get_log_sources(os_name: str, auto_elevate: bool = False) -> list[dict]:
    """
    Return the list of accessible log sources for the detected OS.

    Windows
    -------
    Probes each Event Log channel before adding it to the list.
    If the Security channel needs admin rights and we don't have them,
    either requests UAC elevation (auto_elevate=True) or skips the
    channel with a single clear warning.

    Linux
    -----
    Only returns log files that actually exist on this machine.
    """
    if os_name == "windows":
        # Check admin status once and act accordingly
        admin = is_admin()
        if not admin:
            logger.warning(
                "Process is NOT running as Administrator.\n"
                "  → The 'Security' channel (login attempts, privilege changes)\n"
                "    REQUIRES admin rights and will be skipped.\n"
                "  → To enable full monitoring: run as Administrator, or\n"
                "    use the --elevate flag to trigger a UAC prompt automatically."
            )
            if auto_elevate:
                relaunch_as_admin()   # does not return — exits this process
        else:
            logger.info("Running as Administrator — full Event Log access available.")

        # Probe each channel regardless; skip any that are inaccessible
        available = []
        for src in WINDOWS_LOG_SOURCES:
            if _probe_winlog_channel(src["channel"]):
                available.append(src)
                logger.info(
                    "Event Log channel accessible: %s", src["channel"]
                )

        if not available:
            raise RuntimeError(
                "No Windows Event Log channels are accessible.\n"
                "Run the script as Administrator to fix this."
            )
        return available

    # ── Linux ──────────────────────────────────────────────────────────────────
    available = []
    for src in LINUX_LOG_SOURCES:
        if src["path"].exists():
            available.append(src)
            logger.info("Log source found: %s → %s", src["name"], src["path"])
        else:
            logger.debug("Log source not present on this system: %s", src["path"])

    if not available:
        raise RuntimeError(
            "No Linux log files found. "
            "Expected at least one of: " +
            ", ".join(str(s["path"]) for s in LINUX_LOG_SOURCES)
        )
    return available


# ══════════════════════════════════════════════════════════════════════════════
# CURSOR (resume position tracking)
# ══════════════════════════════════════════════════════════════════════════════

def _get_latest_record_number(channel: str) -> int:
    """
    Get the current latest record number in a Windows Event Log channel.
    Used to initialize the cursor on first run so we only read NEW events
    going forward — not the entire historical log.
    Returns 0 if unavailable.
    """
    try:
        import win32evtlog
        hand    = win32evtlog.OpenEventLog(None, channel)
        # Read the last record using BACKWARDS flag
        flags   = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        records = win32evtlog.ReadEventLog(hand, flags, 0)
        win32evtlog.CloseEventLog(hand)
        if records:
            return records[0].RecordNumber
    except Exception:
        pass
    return 0


def _get_file_end_offset(path: Path) -> int:
    """Return the current size of a file in bytes (used as initial cursor for Linux logs)."""
    try:
        return path.stat().st_size
    except Exception:
        return 0


def load_cursor(cursor_file: Path, sources: list[dict]) -> dict:
    """
    Load the last-read position for each log source.

    If the cursor file exists → load and resume from saved positions.
    If it does NOT exist (first run or after reset) → initialize each
    source to its CURRENT end position so only future events are read.

    This prevents the collector from dumping the entire Windows Event Log
    history on the first run.
    """
    if cursor_file.exists():
        with open(cursor_file) as f:
            cursor = json.load(f)
        logger.info("Cursor loaded — resuming from saved positions.")
        return cursor

    # First run — initialize to current end of each source
    logger.info(
        "No cursor file found — initializing to current log end positions. "
        "Only new events from this point forward will be collected."
    )
    cursor = {}
    for src in sources:
        if src["type"] == "winlog":
            latest = _get_latest_record_number(src["channel"])
            cursor[src["name"]] = latest
            logger.info(
                "  %-12s → starting at record #%d (skipping history)",
                src["name"], latest,
            )
        elif src["type"] == "file":
            offset = _get_file_end_offset(src["path"])
            cursor[src["name"]] = offset
            logger.info(
                "  %-12s → starting at byte offset %d (skipping history)",
                src["name"], offset,
            )
    return cursor


def save_cursor(cursor: dict, cursor_file: Path) -> None:
    """Persist the current read positions to disk."""
    cursor_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cursor_file, "w") as f:
        json.dump(cursor, f, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# LOG READING — LINUX (file tailing)
# ══════════════════════════════════════════════════════════════════════════════

def read_linux_file(source: dict, cursor: dict) -> tuple[list[dict], int]:
    """
    Read new lines from a Linux log file starting from the last byte offset.

    Returns
    -------
    events   : list of raw event dicts
    new_pos  : updated byte offset to store in the cursor
    """
    path     = source["path"]
    name     = source["name"]
    last_pos = cursor.get(name, 0)

    if not path.exists():
        return [], last_pos

    events   = []
    new_pos  = last_pos

    with open(path, "rb") as f:
        # Detect log rotation: if file is now smaller than our last position
        f.seek(0, 2)          # seek to end
        file_size = f.tell()
        if file_size < last_pos:
            logger.warning(
                "Log rotation detected for '%s' (size %d < cursor %d). "
                "Resetting cursor to 0.", name, file_size, last_pos,
            )
            last_pos = 0

        f.seek(last_pos)
        for raw_bytes in f:
            try:
                raw_line = raw_bytes.decode("utf-8", errors="replace").rstrip()
            except Exception:
                continue
            if not raw_line:
                continue

            events.append({
                "source"        : name,
                "source_machine": platform.node(),
                "os"            : "linux",
                "raw"           : raw_line,
                "collected_at"  : datetime.now().isoformat(timespec="seconds"),
                "block_id"      : _extract_block_id_linux(raw_line, name),
                "template_id"   : _classify_template(raw_line),
                "line_id"       : None,
            })
        new_pos = f.tell()

    return events, new_pos


def _extract_block_id_linux(raw: str, source_name: str) -> str:
    """
    Generate a block_id for a Linux log line.
    Groups by process name + PID if available, otherwise by source + minute.
    Example: 'sshd[1234]' → 'sshd_1234'
    """
    import re
    match = re.search(r"(\w+)\[(\d+)\]", raw)
    if match:
        return f"{match.group(1)}_{match.group(2)}"
    # Fallback: group by source + current minute
    minute = datetime.now().strftime("%Y%m%d_%H%M")
    return f"{source_name}_{minute}"


# ══════════════════════════════════════════════════════════════════════════════
# LOG READING — WINDOWS (Event Log)
# ══════════════════════════════════════════════════════════════════════════════

def read_windows_eventlog(source: dict, cursor: dict) -> tuple[list[dict], int]:
    """
    Read new events from a Windows Event Log channel using pywin32.
    Falls back gracefully if pywin32 is not installed.

    Returns
    -------
    events      : list of raw event dicts
    last_record : last record number read (stored in cursor)
    """
    try:
        import win32evtlog
        import win32evtlogutil
        import winerror
    except ImportError:
        logger.error(
            "pywin32 is not installed. Install it with: pip install pywin32\n"
            "Windows Event Log reading is unavailable without it."
        )
        return [], cursor.get(source["name"], 0)

    channel     = source["channel"]
    name        = source["name"]
    last_record = cursor.get(name, 0)
    events      = []
    new_last    = last_record

    try:
        hand = win32evtlog.OpenEventLog(None, channel)
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while True:
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            if not records:
                break
            for rec in records:
                if rec.RecordNumber <= last_record:
                    continue

                event_id  = rec.EventID & 0xFFFF
                try:
                    message = win32evtlogutil.SafeFormatMessage(rec, channel)
                except Exception:
                    message = f"EventID={event_id}"

                raw_line = (
                    f"{rec.TimeGenerated.Format()} "
                    f"[{channel}] EventID={event_id} "
                    f"{message}"
                ).replace("\r\n", " ").replace("\n", " ")

                threat_cat = WINDOWS_HIGH_PRIORITY_IDS.get(event_id, "")

                # ── Block grouping ─────────────────────────────────────────
                # Group by channel + 1-minute time window + threat category.
                # This gives each block multiple events so the model has
                # meaningful feature variance to work with, instead of
                # scoring every single record as its own block of size 1.
                try:
                    minute_str = rec.TimeGenerated.Format("%Y%m%d_%H%M")
                except Exception:
                    minute_str = datetime.now().strftime("%Y%m%d_%H%M")
                group = threat_cat if threat_cat else "general"
                block_id = f"win_{channel}_{minute_str}_{group}"

                events.append({
                    "source"         : name,
                    "source_machine" : platform.node(),
                    "os"             : "windows",
                    "raw"            : raw_line,
                    "collected_at"   : datetime.now().isoformat(timespec="seconds"),
                    "block_id"       : block_id,
                    "template_id"    : f"EVT_{event_id}",
                    "line_id"        : rec.RecordNumber,
                    "event_id"       : event_id,
                    "priority_threat": threat_cat,
                })
                new_last = max(new_last, rec.RecordNumber)

        win32evtlog.CloseEventLog(hand)

    except Exception as exc:
        err_code = getattr(exc, "winerror", None)
        if err_code == 1314:
            # Privilege error — already warned during probe; stay silent here
            # so the log isn't flooded every polling cycle.
            pass
        else:
            logger.error("Error reading Windows Event Log '%s': %s", channel, exc)

    return events, new_last


# ══════════════════════════════════════════════════════════════════════════════
# FEATURE EXTRACTION (single-event, lightweight)
# ══════════════════════════════════════════════════════════════════════════════

def _classify_template(raw: str) -> str:
    """
    Lightweight template classification for real-time events.
    Returns the first matching threat category, or 'INFO' as default.
    """
    lower = raw.lower()
    for cat, keywords in THREAT_KEYWORDS.items():
        if any(kw in lower for kw in keywords):
            return cat.upper()
    return "INFO"


def _parse_level(raw: str) -> str:
    lower = raw.lower()
    if any(k in lower for k in ("error", "exception", "critical", "fatal")):
        return "ERROR"
    if any(k in lower for k in ("warn", "warning")):
        return "WARN"
    return "INFO"


def extract_realtime_features(
    events: list[dict],
    min_events_per_block: int = 3,
) -> pd.DataFrame:
    """
    Build a feature row per block from a batch of raw collected events.

    Parameters
    ----------
    min_events_per_block : skip blocks with fewer events than this.
        Single-event blocks have no meaningful feature variance — every
        block of 1 looks the same to the model, causing mass false alerts.
        Default is 3; set to 1 only for testing.
    """
    from collections import Counter, defaultdict
    import math

    blocks: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        blocks[e["block_id"]].append(e)

    rows = []
    skipped = 0
    for block_id, evts in blocks.items():
        if len(evts) < min_events_per_block:
            skipped += 1
            continue

        raws      = [e["raw"] for e in evts]
        msg_lens  = [len(r) for r in raws]
        templates = [e["template_id"] for e in evts]
        levels    = [_parse_level(r) for r in raws]

        counts  = Counter(templates)
        total   = sum(counts.values())
        entropy = -sum((c/total)*math.log2(c/total) for c in counts.values() if c > 0)

        top_template_ratio = counts.most_common(1)[0][1] / total if total else 0.0

        # Threat keyword hit counts
        threat_hits = {f"{cat}_hits": 0 for cat in THREAT_KEYWORDS}
        for raw in raws:
            lower = raw.lower()
            for cat, kws in THREAT_KEYWORDS.items():
                if any(kw in lower for kw in kws):
                    threat_hits[f"{cat}_hits"] += 1

        # Windows high-priority events
        priority_hits = sum(
            1 for e in evts if e.get("priority_threat")
        )

        source_machine = evts[0].get("source_machine") or platform.node()
        row = {
            "block_id"          : block_id,
            "source_machine"    : source_machine,
            "num_events"        : len(evts),
            "unique_templates"  : len(set(templates)),
            "avg_msg_len"       : float(np.mean(msg_lens)),
            "std_msg_len"       : float(np.std(msg_lens)),
            "max_msg_len"       : max(msg_lens),
            "min_msg_len"       : min(msg_lens),
            "error_count"       : levels.count("ERROR"),
            "warn_count"        : levels.count("WARN"),
            "info_count"        : levels.count("INFO"),
            "error_ratio"       : levels.count("ERROR") / len(levels),
            "warn_ratio"        : levels.count("WARN")  / len(levels),
            "template_entropy"  : entropy,
            "top_template_ratio": top_template_ratio,
            "block_duration_sec": 0.0,   # unknown in real-time; set 0
            "events_per_sec"    : 0.0,
            "gap_count"         : 0,
            "priority_hits"     : priority_hits,
        }
        row.update(threat_hits)
        rows.append(row)

    if skipped:
        logger.debug(
            "Skipped %d block(s) with fewer than %d events (too small to score reliably).",
            skipped, min_events_per_block,
        )
    return pd.DataFrame(rows)


# ══════════════════════════════════════════════════════════════════════════════
# MODEL SCORING
# ══════════════════════════════════════════════════════════════════════════════

def load_model_and_meta(model_path: Path, meta_path: Path):
    """Load the trained pipeline and feature column list."""
    if not model_path.exists():
        raise FileNotFoundError(
            f"Model not found: {model_path}\n"
            "Run train_baseline.py first."
        )
    model = joblib.load(model_path)
    logger.info("Model loaded from %s", model_path)

    feature_cols = None
    if meta_path.exists():
        with open(meta_path) as f:
            feature_cols = json.load(f).get("feature_columns")
        logger.info("Feature metadata loaded: %d columns", len(feature_cols))
    else:
        logger.warning("feature_meta.json not found — will auto-select columns.")

    return model, feature_cols


def score_events(
    df_features: pd.DataFrame,
    model,
    feature_cols: list[str] | None,
    threshold: float = ANOMALY_SCORE_THRESHOLD,
) -> pd.DataFrame:
    """
    Run the trained model on a feature DataFrame.

    Returns the same DataFrame with two extra columns:
      anomaly_score : raw decision_function value (higher = more normal)
      is_anomaly    : True if score < threshold
    """
    EXCLUDE = {"block_id", "label", "anomaly", "split"}

    if feature_cols:
        # Use only columns the model knows; fill missing ones with 0
        cols = feature_cols
        for c in cols:
            if c not in df_features.columns:
                df_features[c] = 0.0
        X = df_features[cols]
    else:
        X = df_features[[c for c in df_features.columns if c not in EXCLUDE]]

    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    scores               = model.decision_function(X)
    df_features          = df_features.copy()
    df_features["anomaly_score"] = scores
    df_features["is_anomaly"]    = scores < threshold
    return df_features


# ══════════════════════════════════════════════════════════════════════════════
# ALERT GENERATION
# ══════════════════════════════════════════════════════════════════════════════

# Deduplication cache: signature → last emit timestamp
_alert_cache: dict[str, float] = {}
ALERT_COOLDOWN_SEC = 60   # suppress same alert signature for 60 s


def _alert_signature(row: pd.Series) -> str:
    """
    A short string identifying the *type* of alert (not the specific block)
    so bursts of identical events collapse into a single alert.
    Uses threat categories + score bucket (0.01 resolution).
    """
    threat_cols = [c for c in row.index if c.endswith("_hits") and row[c] > 0]
    cats        = "+".join(sorted(c.replace("_hits", "") for c in threat_cols)) or "unknown"
    score_bucket = round(float(row["anomaly_score"]) * 100) / 100
    return f"{cats}@{score_bucket}"


def emit_alert(row: pd.Series, events_out: Path, alerts_out: Path) -> None:
    """
    Write an alert to alerts.jsonl and log it.
    Suppresses duplicate alert signatures within ALERT_COOLDOWN_SEC to avoid
    flooding when a burst of identical events arrives in the same cycle.
    The GUI / notification.py reads from alerts.jsonl in real time.
    """
    sig = _alert_signature(row)
    now = time.time()

    # Deduplication: suppress if same signature emitted recently
    if sig in _alert_cache and (now - _alert_cache[sig]) < ALERT_COOLDOWN_SEC:
        logger.debug("Alert suppressed (cooldown active for '%s').", sig)
        return
    _alert_cache[sig] = now

    # Prune stale cache entries
    for k in [k for k, t in _alert_cache.items() if now - t > ALERT_COOLDOWN_SEC]:
        del _alert_cache[k]

    threat_cols = [c for c in row.index if c.endswith("_hits") and row[c] > 0]
    threat_cats = [c.replace("_hits", "") for c in threat_cols]

    raw_score = float(row["anomaly_score"])
    p_hits    = row.get("priority_hits", 0)
    is_hdfs   = raw_score < 0   # HDFS model produces negative scores

    # ── Priority assignment ────────────────────────────────────────────────────
    # Windows model (positive, lower = more anomalous, threshold ≈ 0.10):
    #   CRITICAL ≤ 0.02 | HIGH ≤ 0.05 | MEDIUM ≤ 0.08 | LOW otherwise
    # HDFS model (negative, more negative = more anomalous, threshold ≈ -0.10):
    #   CRITICAL ≤ -0.15 | HIGH ≤ -0.12 | MEDIUM ≤ -0.10 | LOW otherwise
    if is_hdfs:
        if p_hits >= 3 or raw_score <= -0.15:
            priority = "CRITICAL"
        elif p_hits > 0 or raw_score <= -0.12:
            priority = "HIGH"
        elif raw_score <= -0.10:
            priority = "MEDIUM"
        else:
            priority = "LOW"
    else:
        if p_hits >= 3 or raw_score <= 0.02:
            priority = "CRITICAL"
        elif p_hits > 0 or raw_score <= 0.05:
            priority = "HIGH"
        elif raw_score <= 0.08:
            priority = "MEDIUM"
        else:
            priority = "LOW"

    # ── CVSS score (0–10, banded to always match priority label) ──────────────
    # Each priority band maps linearly to its CVE range:
    #   CRITICAL → 9.0–10.0 | HIGH → 7.0–9.0 | MEDIUM → 4.0–7.0 | LOW → 0.1–4.0
    if is_hdfs:
        # HDFS: more negative = more dangerous
        if priority == "CRITICAL":
            cvss = round(min(10.0, 9.0 + (abs(raw_score) - 0.15) / 0.05), 1)
        elif priority == "HIGH":
            cvss = round(7.0 + (abs(raw_score) - 0.12) / 0.03 * 2.0, 1)
        elif priority == "MEDIUM":
            cvss = round(4.0 + (abs(raw_score) - 0.10) / 0.02 * 3.0, 1)
        else:
            cvss = round(max(0.1, abs(raw_score) * 10), 1)
    else:
        # Windows: lower score = more dangerous
        if priority == "CRITICAL":
            cvss = round(min(10.0, 9.0 + (0.02 - raw_score) / 0.02), 1)
        elif priority == "HIGH":
            cvss = round(7.0 + (0.05 - raw_score) / 0.03 * 2.0, 1)
        elif priority == "MEDIUM":
            cvss = round(4.0 + (0.08 - raw_score) / 0.03 * 3.0, 1)
        else:
            cvss = round(max(0.1, (0.10 - raw_score) / 0.02 * 3.9), 1)
    cvss = round(max(0.0, min(10.0, cvss)), 1)

    alert = {
        "alert_at"         : datetime.now().isoformat(timespec="seconds"),
        "block_id"         : row["block_id"],
        "source_machine"   : str(row.get("source_machine") or platform.node()),
        "anomaly_score"    : round(raw_score, 6),
        "cvss_score"       : cvss,
        "num_events"       : int(row.get("num_events", 0)),
        "error_count"      : int(row.get("error_count", 0)),
        "threat_categories": threat_cats,
        "priority"         : priority,
    }

    alerts_out.parent.mkdir(parents=True, exist_ok=True)
    with open(alerts_out, "a") as f:
        f.write(json.dumps(alert) + "\n")

    logger.warning(
        "🚨 ALERT | block=%-38s | score=%.4f | cvss=%.1f | threats=%s | priority=%s",
        alert["block_id"],
        alert["anomaly_score"],
        alert["cvss_score"],
        threat_cats or ["unknown"],
        alert["priority"],
    )


def save_events(events: list[dict], events_out: Path) -> None:
    """Append collected raw events to the staging JSONL file."""
    events_out.parent.mkdir(parents=True, exist_ok=True)
    with open(events_out, "a") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN COLLECTION LOOP
# ══════════════════════════════════════════════════════════════════════════════

def collect_once(
    sources     : list[dict],
    cursor      : dict,
    os_name     : str,
    model,
    feature_cols: list[str] | None,
    events_out  : Path,
    alerts_out  : Path,
    threshold   : float,
    verbose     : bool,
) -> dict:
    """
    One polling cycle:
      1. Read new log entries from every source
      2. Save raw events to staging/events.jsonl
      3. Extract features and score with the model
      4. Emit alerts for anomalous blocks
      5. Return the updated cursor
    """
    all_events: list[dict] = []

    for src in sources:
        if os_name == "linux":
            new_events, new_pos = read_linux_file(src, cursor)
            cursor[src["name"]] = new_pos
        else:
            new_events, new_pos = read_windows_eventlog(src, cursor)
            cursor[src["name"]] = new_pos

        if new_events:
            all_events.extend(new_events)
            if verbose:
                logger.info(
                    "  %-12s → %d new event(s)", src["name"], len(new_events)
                )

    if not all_events:
        if verbose:
            logger.info("No new log entries this cycle.")
        return cursor

    # Save raw events
    save_events(all_events, events_out)
    logger.info("Collected %d new log event(s).", len(all_events))

    # Feature extraction + scoring
    df_features = extract_realtime_features(all_events, min_events_per_block=3)
    if df_features.empty:
        return cursor

    df_scored = score_events(df_features, model, feature_cols, threshold)

    # Emit alerts
    anomalies = df_scored[df_scored["is_anomaly"]]
    if anomalies.empty:
        logger.info("No anomalies detected this cycle. ✓")
    else:
        logger.warning(
            "%d anomalous block(s) detected out of %d.",
            len(anomalies), len(df_scored),
        )
        for _, row in anomalies.iterrows():
            emit_alert(row, events_out, alerts_out)

    return cursor


def start_collector(
    model_path   : Path  = DEFAULT_MODEL,
    meta_path    : Path  = DEFAULT_META,
    cursor_file  : Path  = DEFAULT_CURSOR_FILE,
    events_out   : Path  = DEFAULT_EVENTS_OUT,
    alerts_out   : Path  = DEFAULT_ALERTS_OUT,
    interval     : int   = DEFAULT_INTERVAL,
    threshold    : float = ANOMALY_SCORE_THRESHOLD,
    verbose      : bool  = False,
    run_once     : bool  = False,
    auto_elevate : bool  = False,
    stop_event   : "threading.Event | None" = None,
) -> None:
    """
    Entry point for the log collection loop.
    Call this from the GUI in a daemon thread, or run the script directly.

    Parameters
    ----------
    interval  : seconds between polling cycles
    threshold : anomaly score cutoff (lower = more sensitive)
    verbose   : log every source even when nothing new is found
    run_once  : do one cycle then exit (useful for testing)
    """
    logger.info("=" * 60)
    logger.info("Log Sentinel AI — Log Collector Starting")
    logger.info("=" * 60)

    # OS detection
    os_name = detect_os()
    sources = get_log_sources(os_name, auto_elevate=auto_elevate)
    logger.info(
        "Monitoring %d log source(s) on %s.", len(sources), os_name.capitalize()
    )

    # Load model
    model, feature_cols = load_model_and_meta(model_path, meta_path)

    # Load cursor (resume from last position, or initialize to current end)
    cursor = load_cursor(cursor_file, sources)

    logger.info(
        "Polling every %ds  |  anomaly threshold=%.4f  |  alerts → %s",
        interval, threshold, alerts_out,
    )
    logger.info("Press Ctrl+C to stop.\n")

    try:
        while not (stop_event and stop_event.is_set()):
            cycle_start = time.time()
            logger.info("── Polling cycle %s ──", datetime.now().strftime("%H:%M:%S"))

            cursor = collect_once(
                sources, cursor, os_name,
                model, feature_cols,
                events_out, alerts_out,
                threshold, verbose,
            )

            # Always persist cursor so we resume cleanly after restart
            save_cursor(cursor, cursor_file)

            if run_once:
                break

            elapsed   = time.time() - cycle_start
            sleep_for = max(0.0, interval - elapsed)

            # Sleep in small chunks so the stop_event is checked promptly
            chunk = 1.0
            slept = 0.0
            while slept < sleep_for:
                if stop_event and stop_event.is_set():
                    break
                time.sleep(min(chunk, sleep_for - slept))
                slept += chunk

    except KeyboardInterrupt:
        logger.info("Collector stopped by user.")
    except Exception as exc:
        logger.error("Collector crashed: %s", exc, exc_info=True)
        raise
    finally:
        save_cursor(cursor, cursor_file)
        logger.info("Cursor saved. Collector shut down cleanly.")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Real-time OS log collector and anomaly detector"
    )
    parser.add_argument("--model",     type=Path, default=DEFAULT_MODEL,
                        help="Path to trained model .pkl")
    parser.add_argument("--meta",      type=Path, default=DEFAULT_META,
                        help="Path to feature_meta.json")
    parser.add_argument("--cursor",    type=Path, default=DEFAULT_CURSOR_FILE,
                        help="Path to cursor file for resume support")
    parser.add_argument("--events",    type=Path, default=DEFAULT_EVENTS_OUT,
                        help="Output path for collected events JSONL")
    parser.add_argument("--alerts",    type=Path, default=DEFAULT_ALERTS_OUT,
                        help="Output path for alert JSONL")
    parser.add_argument("--interval",  type=int,   default=DEFAULT_INTERVAL,
                        help="Seconds between polling cycles (default: 5)")
    parser.add_argument("--threshold", type=float, default=ANOMALY_SCORE_THRESHOLD,
                        help="Anomaly score threshold (default: -0.05). "
                             "Lower = more sensitive.")
    parser.add_argument("--verbose",   action="store_true",
                        help="Log every source on every cycle")
    parser.add_argument("--once",      action="store_true",
                        help="Run one collection cycle then exit (for testing)")
    parser.add_argument("--elevate",   action="store_true",
                        help="Automatically request UAC elevation on Windows if not "
                             "running as Administrator (triggers a UAC prompt)")
    args = parser.parse_args()

    start_collector(
        model_path   = args.model,
        meta_path    = args.meta,
        cursor_file  = args.cursor,
        events_out   = args.events,
        alerts_out   = args.alerts,
        interval     = args.interval,
        threshold    = args.threshold,
        verbose      = args.verbose,
        run_once     = args.once,
        auto_elevate = args.elevate,
    )


if __name__ == "__main__":
    main()
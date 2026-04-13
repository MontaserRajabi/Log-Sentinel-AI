"""
notification.py — Log Sentinel AI
=====================================
Watches alerts.jsonl in real time and delivers notifications to the
administrator through multiple channels:

  1. Desktop notifications (Windows toast via win10toast / Linux libnotify)
  2. Sound alert (system beep on HIGH priority)
  3. Email  (optional — configure in .env)
  4. Log file (always — full audit trail)

Aligns with the report:
  - Section 3.1.1: "generate alerts and notify administrators"
  - Section 3.3:   Alert Generator → Admin Dashboard
  - Section 3.7:   Threat model — HIGH priority for critical Windows Event IDs

Place this file at:
    src/notification.py

Run standalone (watches alerts.jsonl and notifies):
    python src/notification.py

Or import and call in a background thread from api.py or the GUI:
    from src.notification import start_notifier
    threading.Thread(target=start_notifier, daemon=True).start()

.env keys (all optional):
    NOTIFY_EMAIL_ENABLED=true
    NOTIFY_EMAIL_FROM=sentinel@example.com
    NOTIFY_EMAIL_TO=admin@example.com
    NOTIFY_EMAIL_HOST=smtp.gmail.com
    NOTIFY_EMAIL_PORT=587
    NOTIFY_EMAIL_USER=sentinel@example.com
    NOTIFY_EMAIL_PASS=yourpassword
    NOTIFY_MIN_PRIORITY=MEDIUM        # MEDIUM | HIGH  (skip MEDIUM if HIGH only)
    NOTIFY_COOLDOWN_SEC=60            # suppress same-signature alerts for N sec
    NOTIFY_SOUND=true                 # play beep on HIGH priority alerts
"""

import json
import logging
import os
import platform
import smtplib
import sys
import threading
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from dotenv import load_dotenv

# ── Environment ────────────────────────────────────────────────────────────────
load_dotenv()

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Project root ───────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ── Defaults (overridable via .env) ───────────────────────────────────────────
ALERTS_FILE      = PROJECT_ROOT / "data" / "staging" / "alerts.jsonl"
NOTIFY_LOG_FILE  = PROJECT_ROOT / "data" / "staging" / "notification_log.jsonl"

EMAIL_ENABLED    = os.getenv("NOTIFY_EMAIL_ENABLED", "false").lower() == "true"
EMAIL_FROM       = os.getenv("NOTIFY_EMAIL_FROM", "")
EMAIL_TO         = os.getenv("NOTIFY_EMAIL_TO", "")
EMAIL_HOST       = os.getenv("NOTIFY_EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT       = int(os.getenv("NOTIFY_EMAIL_PORT", 587))
EMAIL_USER       = os.getenv("NOTIFY_EMAIL_USER", "")
EMAIL_PASS       = os.getenv("NOTIFY_EMAIL_PASS", "")

MIN_PRIORITY     = os.getenv("NOTIFY_MIN_PRIORITY", "MEDIUM").upper()   # CRITICAL | HIGH | MEDIUM
COOLDOWN_SEC     = int(os.getenv("NOTIFY_COOLDOWN_SEC", 60))
SOUND_ENABLED    = os.getenv("NOTIFY_SOUND", "true").lower() == "true"
POLL_INTERVAL    = 2      # seconds between file checks


# ══════════════════════════════════════════════════════════════════════════════
# DESKTOP NOTIFICATION BACKENDS
# ══════════════════════════════════════════════════════════════════════════════

def _notify_windows(title: str, message: str, priority: str) -> bool:
    """
    Send a Windows 10/11 toast notification.
    Requires: pip install win10toast
    Falls back to a simple message box if win10toast is unavailable.
    """
    try:
        from win10toast import ToastNotifier
        toaster = ToastNotifier()
        toaster.show_toast(
            title,
            message,
            icon_path = None,
            duration  = 15 if priority == "CRITICAL" else 10 if priority == "HIGH" else 5,
            threaded  = True,
        )
        return True
    except ImportError:
        pass

    # Fallback: Windows MessageBox (always available, but blocking)
    try:
        import ctypes
        # MB_ICONWARNING = 0x30, MB_ICONERROR = 0x10, MB_OK = 0x0
        icon = 0x10 if priority in ("CRITICAL", "HIGH") else 0x30
        ctypes.windll.user32.MessageBoxW(0, message, title, icon | 0x40000)
        return True
    except Exception as exc:
        logger.warning("Windows notification fallback failed: %s", exc)
        return False


def _notify_linux(title: str, message: str, priority: str) -> bool:
    """
    Send a Linux desktop notification via libnotify (notify-send).
    Works on GNOME, KDE, XFCE and most modern desktops.
    """
    import subprocess
    urgency = "critical" if priority in ("CRITICAL", "HIGH") else "normal"
    try:
        subprocess.run(
            ["notify-send", "-u", urgency, "-t", "8000", title, message],
            check=True, capture_output=True,
        )
        return True
    except FileNotFoundError:
        logger.warning(
            "notify-send not found. Install libnotify: sudo apt install libnotify-bin"
        )
        return False
    except subprocess.CalledProcessError as exc:
        logger.warning("notify-send failed: %s", exc)
        return False


def send_desktop_notification(title: str, message: str, priority: str) -> bool:
    """
    Dispatch a desktop notification using the appropriate backend for the OS.
    Supported: Windows, Linux. macOS is not supported.
    Returns True if the notification was sent successfully.
    """
    os_name = platform.system().lower()
    if os_name == "windows":
        return _notify_windows(title, message, priority)
    elif os_name == "linux":
        return _notify_linux(title, message, priority)
    else:
        logger.warning("Desktop notifications not supported on %s.", platform.system())
        return False


# ══════════════════════════════════════════════════════════════════════════════
# SOUND ALERT
# ══════════════════════════════════════════════════════════════════════════════

def play_alert_sound(priority: str) -> None:
    """
    Play an audible alert.
    HIGH priority → 3 beeps, MEDIUM → 1 beep.
    Uses the system beep which works on both Windows and Linux without
    any extra dependencies.
    """
    if not SOUND_ENABLED:
        return

    beeps = 5 if priority == "CRITICAL" else 3 if priority == "HIGH" else 1
    os_name = platform.system().lower()

    try:
        if os_name == "windows":
            import winsound
            freq     = 1500 if priority == "CRITICAL" else 1200 if priority == "HIGH" else 800
            duration = 300
            for _ in range(beeps):
                winsound.Beep(freq, duration)
                time.sleep(0.1)
        else:
            # Linux: BEL character to terminal
            for _ in range(beeps):
                sys.stdout.write("\a")
                sys.stdout.flush()
                time.sleep(0.2)
    except Exception as exc:
        logger.debug("Sound alert failed: %s", exc)


# ══════════════════════════════════════════════════════════════════════════════
# EMAIL NOTIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def send_email_notification(alert: dict) -> bool:
    """
    Send an email alert to the administrator via SMTP.
    Configure credentials in .env (see module docstring).
    Returns True if the email was sent successfully.
    """
    if not EMAIL_ENABLED:
        return False

    if not all([EMAIL_FROM, EMAIL_TO, EMAIL_USER, EMAIL_PASS]):
        logger.warning(
            "Email notification enabled but credentials incomplete. "
            "Set NOTIFY_EMAIL_FROM/TO/USER/PASS in .env"
        )
        return False

    threats    = ", ".join(alert.get("threat_categories", [])) or "unknown"
    priority   = alert.get("priority", "MEDIUM")
    score      = alert.get("anomaly_score", 0)
    _PRIORITY_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}
    cvss       = alert.get("cvss_score") or _PRIORITY_CVSS.get(priority)
    block_id   = alert.get("block_id", "N/A")
    alert_time = alert.get("alert_at", datetime.now().isoformat())
    n_events   = alert.get("num_events", 0)

    priority_color = {
        "CRITICAL": "#7c3aed",
        "HIGH"    : "#c0392b",
        "MEDIUM"  : "#e67e22",
        "LOW"     : "#27ae60",
    }.get(priority, "#e67e22")

    subject = f"[Log Sentinel AI] {priority} Alert — {threats}"

    cvss_row = f"""
        <tr style="background:#f2f2f2;">
            <td style="padding:8px; font-weight:bold;">CVSS Score</td>
            <td style="padding:8px; font-weight:bold; color:{priority_color};">{cvss:.1f} / 10</td>
        </tr>""" if cvss is not None else ""

    body_html = f"""
    <html><body style="font-family: Arial, sans-serif; color: #222;">
    <h2 style="color: {priority_color};">
        🚨 Log Sentinel AI — {priority} Priority Alert
    </h2>
    <table style="border-collapse:collapse; width:100%; max-width:600px;">
        <tr style="background:#f2f2f2;">
            <td style="padding:8px; font-weight:bold;">Block ID</td>
            <td style="padding:8px;">{block_id}</td>
        </tr>
        <tr>
            <td style="padding:8px; font-weight:bold;">Alert Time</td>
            <td style="padding:8px;">{alert_time}</td>
        </tr>
        <tr style="background:#f2f2f2;">
            <td style="padding:8px; font-weight:bold;">Threat Categories</td>
            <td style="padding:8px;">{threats}</td>
        </tr>
        <tr>
            <td style="padding:8px; font-weight:bold;">Anomaly Score</td>
            <td style="padding:8px;">{score:.6f}</td>
        </tr>{cvss_row}
        <tr style="background:#f2f2f2;">
            <td style="padding:8px; font-weight:bold;">Events in Block</td>
            <td style="padding:8px;">{n_events}</td>
        </tr>
        <tr>
            <td style="padding:8px; font-weight:bold;">Priority</td>
            <td style="padding:8px; color:{priority_color}; font-weight:bold;">
                {priority}
            </td>
        </tr>
    </table>
    <p style="margin-top:16px; color:#555; font-size:12px;">
        This alert was generated automatically by Log Sentinel AI.<br>
        Log in to the dashboard to label this alert or review details.
    </p>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = EMAIL_FROM
    msg["To"]      = EMAIL_TO
    msg.attach(MIMEText(body_html, "html"))

    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logger.info("Email alert sent to %s for block %s", EMAIL_TO, block_id)
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error(
            "Email authentication failed. Check NOTIFY_EMAIL_USER/PASS in .env"
        )
        return False
    except Exception as exc:
        logger.error("Failed to send email alert: %s", exc)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# NOTIFICATION LOG (audit trail)
# ══════════════════════════════════════════════════════════════════════════════

def log_notification(alert: dict, channels: list[str]) -> None:
    """
    Append a record to notification_log.jsonl every time an alert fires.
    This provides the audit trail required by Section 3.2.1 of the report:
    'log all user actions for auditing and accountability'.
    """
    record = {
        "notified_at"      : datetime.now().isoformat(timespec="seconds"),
        "block_id"         : alert.get("block_id"),
        "priority"         : alert.get("priority"),
        "threat_categories": alert.get("threat_categories", []),
        "anomaly_score"    : alert.get("anomaly_score"),
        "channels_used"    : channels,
    }
    NOTIFY_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(NOTIFY_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# DEDUPLICATION
# ══════════════════════════════════════════════════════════════════════════════

_notified_cache: dict[str, float] = {}


def _should_notify(alert: dict) -> bool:
    """
    Return True if this alert has not been notified within the cooldown window.
    Uses block_id as the deduplication key — each unique block only fires once
    per COOLDOWN_SEC window, preventing repeat notifications for the same event.
    """
    key = alert.get("block_id", "unknown")
    now = time.time()

    # Prune expired entries
    expired = [k for k, t in _notified_cache.items() if now - t > COOLDOWN_SEC]
    for k in expired:
        del _notified_cache[k]

    if key in _notified_cache:
        return False

    _notified_cache[key] = now
    return True


def _meets_priority(alert: dict) -> bool:
    """Return True if the alert priority meets the minimum configured level."""
    priority = alert.get("priority", "MEDIUM")
    # Priority order: CRITICAL > HIGH > MEDIUM > LOW
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return order.get(priority, 0) >= order.get(MIN_PRIORITY, 2)


# ══════════════════════════════════════════════════════════════════════════════
# DISPATCH
# ══════════════════════════════════════════════════════════════════════════════

def dispatch(alert: dict) -> None:
    """
    Send all configured notifications for a single alert.
    Checks priority filter and cooldown before dispatching.
    """
    if not _meets_priority(alert):
        logger.debug(
            "Alert skipped (priority %s < min %s): %s",
            alert.get("priority"), MIN_PRIORITY, alert.get("block_id"),
        )
        return

    if not _should_notify(alert):
        logger.debug("Alert suppressed (cooldown): %s", alert.get("block_id"))
        return

    priority   = alert.get("priority", "MEDIUM")
    threats    = ", ".join(alert.get("threat_categories", [])) or "Unknown"
    block_id   = alert.get("block_id", "N/A")
    score      = alert.get("anomaly_score", 0)

    # Use stored cvss_score only if it's consistent with the priority band.
    # If the stored value is too low for the label (stale/inconsistent data),
    # fall back to the representative midpoint for that priority.
    _PRIORITY_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}
    _PRIORITY_MIN  = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.0}
    raw_cvss = alert.get("cvss_score")
    if raw_cvss is not None and raw_cvss >= _PRIORITY_MIN.get(priority, 0):
        cvss = raw_cvss
    else:
        cvss = _PRIORITY_CVSS.get(priority, 5.0)

    title   = f"🚨 Log Sentinel AI — {priority} Alert"
    message = (
        f"Threat: {threats}\n"
        f"Block:  {block_id}\n"
        f"CVSS:   {cvss:.1f}/10"
    )

    logger.warning(
        "NOTIFICATION | priority=%-8s | cvss=%-4s | threats=%-30s | block=%s",
        priority, f"{cvss:.1f}" if cvss is not None else "n/a", threats, block_id,
    )

    channels_used = []

    # 1. Desktop notification
    if send_desktop_notification(title, message, priority):
        channels_used.append("desktop")

    # 2. Sound
    play_alert_sound(priority)
    if SOUND_ENABLED:
        channels_used.append("sound")

    # 3. Email
    if EMAIL_ENABLED:
        if send_email_notification(alert):
            channels_used.append("email")

    # 4. Audit log (always)
    log_notification(alert, channels_used)


# ══════════════════════════════════════════════════════════════════════════════
# FILE WATCHER
# ══════════════════════════════════════════════════════════════════════════════

def start_notifier(
    alerts_file: Path = ALERTS_FILE,
    poll_interval: int = POLL_INTERVAL,
    run_once: bool = False,
) -> None:
    """
    Watch alerts.jsonl for new entries and dispatch notifications.

    Tracks the file size; when it grows, reads and processes the new lines.
    This is the same tail-based approach used by log_collector.py so it
    works reliably on both Windows and Linux without inotify dependencies.

    Parameters
    ----------
    alerts_file   : path to watch (default: data/staging/alerts.jsonl)
    poll_interval : seconds between file checks (default: 2)
    run_once      : process any pending alerts then exit (for testing)
    """
    logger.info("=" * 60)
    logger.info("Log Sentinel AI — Notification Service Starting")
    logger.info("=" * 60)
    logger.info("Watching: %s", alerts_file)
    logger.info(
        "Config: min_priority=%s  cooldown=%ds  email=%s  sound=%s",
        MIN_PRIORITY, COOLDOWN_SEC,
        "enabled" if EMAIL_ENABLED else "disabled",
        "enabled" if SOUND_ENABLED else "disabled",
    )

    last_size = alerts_file.stat().st_size if alerts_file.exists() else 0

    try:
        while True:
            if not alerts_file.exists():
                if not run_once:
                    time.sleep(poll_interval)
                    continue
                break

            current_size = alerts_file.stat().st_size

            if current_size > last_size:
                # Read only the new bytes since last check
                with open(alerts_file, "rb") as f:
                    f.seek(last_size)
                    new_bytes = f.read()
                last_size = current_size

                for line in new_bytes.decode("utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        alert = json.loads(line)
                        dispatch(alert)
                    except json.JSONDecodeError:
                        logger.warning("Skipping malformed alert line: %s", line[:80])

            elif current_size < last_size:
                # File was cleared/rotated — skip existing content, watch only future writes
                logger.info("alerts.jsonl was reset — watching from current end.")
                last_size = current_size

            if run_once:
                break

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        logger.info("Notification service stopped by user.")
    finally:
        logger.info("Notification service shut down.")


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global MIN_PRIORITY   # declare at the very top before any use

    import argparse
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Notification Service"
    )
    parser.add_argument("--alerts",    type=Path, default=ALERTS_FILE,
                        help="Path to alerts.jsonl to watch")
    parser.add_argument("--interval",  type=int,  default=POLL_INTERVAL,
                        help="Seconds between file checks (default: 2)")
    parser.add_argument("--once",      action="store_true",
                        help="Process pending alerts then exit (for testing)")
    parser.add_argument("--min-priority", default=MIN_PRIORITY,
                        choices=["MEDIUM", "HIGH"],
                        help="Minimum priority level to notify (default: MEDIUM)")
    args = parser.parse_args()

    MIN_PRIORITY = args.min_priority

    start_notifier(
        alerts_file   = args.alerts,
        poll_interval = args.interval,
        run_once      = args.once,
    )


if __name__ == "__main__":
    main()
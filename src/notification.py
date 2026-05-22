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
import re
import smtplib
import sys
import threading
import time
import uuid
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
EMAIL_TO         = os.getenv("NOTIFY_EMAIL_TO", "")   # fallback admin email
EMAIL_HOST       = os.getenv("NOTIFY_EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT       = int(os.getenv("NOTIFY_EMAIL_PORT", 587))
EMAIL_USER       = os.getenv("NOTIFY_EMAIL_USER", "")
EMAIL_PASS       = os.getenv("NOTIFY_EMAIL_PASS", "")

# ── Cosmos DB user lookup (to email the right user per machine) ────────────
def _get_emails_for_machine(machine: str) -> list[str]:
    """
    Return email recipients for an alert on this machine.
    Sends to paired users only; falls back to NOTIFY_EMAIL_TO (admin)
    if no users are found or Cosmos is unreachable.
    """
    if not machine:
        return [EMAIL_TO] if EMAIL_TO else []

    try:
        conn = os.getenv("COSMOS_CONNECTION_STRING", "")
        if not conn:
            logger.debug("COSMOS_CONNECTION_STRING not set — falling back to admin email.")
            return [EMAIL_TO] if EMAIL_TO else []
        from azure.cosmos import CosmosClient
        client        = CosmosClient.from_connection_string(conn)
        container     = client.get_database_client("sentinel").get_container_client("users")
        machine_lower = machine.strip().lower()
        items = list(container.query_items(
            "SELECT * FROM users u WHERE u.source_machine = @m",
            parameters=[{"name": "@m", "value": machine_lower}],
            enable_cross_partition_query=True,
        ))
        user_emails = [item.get("email", "") for item in items if item.get("email")]
        if user_emails:
            logger.info("Machine '%s' → sending to user(s): %s", machine_lower, user_emails)
            return user_emails
        logger.info("Machine '%s' → no paired users found; falling back to admin email.", machine_lower)
    except Exception as e:
        logger.warning("Cosmos user lookup failed: %s — falling back to admin email.", e)

    return [EMAIL_TO] if EMAIL_TO else []

MIN_PRIORITY       = os.getenv("NOTIFY_MIN_PRIORITY", "HIGH").upper()        # desktop notifications minimum
EMAIL_MIN_PRIORITY = os.getenv("NOTIFY_EMAIL_MIN_PRIORITY", "HIGH").upper()  # email notifications minimum (HIGH or CRITICAL only)
COOLDOWN_SEC       = int(os.getenv("NOTIFY_COOLDOWN_SEC", 60))
SOUND_ENABLED      = os.getenv("NOTIFY_SOUND", "true").lower() == "true"
POLL_INTERVAL      = 2      # seconds between file checks


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

def _split_tip_steps(tip: str) -> tuple[list[str], list[str]]:
    """
    Split a numbered tip string into (immediate_steps, later_steps).
    Items 1-2 are urgent "do right now"; items 3+ are preventive "next steps".
    """
    if not tip:
        return [], []
    steps = [s.strip() for s in re.split(r'\s*\d+\.\s+', tip.strip()) if s.strip()]
    return steps[:2], steps[2:]


def send_email_notification(alert: dict, recipients: list[str] | None = None) -> bool:
    """
    Send a stand-alone (non-threaded) email alert via SMTP.
    Every email has a unique subject so it never appears as a reply/thread.
    Only HIGH and CRITICAL alerts are sent (controlled by EMAIL_MIN_PRIORITY).
    Returns True if at least one email was sent successfully.
    """
    if not EMAIL_ENABLED:
        return False

    if not all([EMAIL_FROM, EMAIL_USER, EMAIL_PASS]):
        logger.warning(
            "Email notification enabled but credentials incomplete. "
            "Set NOTIFY_EMAIL_FROM/USER/PASS in .env"
        )
        return False

    if recipients is None:
        recipients = _get_emails_for_machine(alert.get("source_machine", ""))

    if not recipients:
        logger.warning("No email recipients found for this alert.")
        return False

    DASHBOARD_URL = "https://log-sentinel-ai-h3bmh3hbh6e3c6bx.francecentral-01.azurewebsites.net"

    threats    = ", ".join(alert.get("threat_categories", [])) or "Unknown"
    threats_hr = threats.replace("_", " ").title()
    priority   = alert.get("priority", "MEDIUM")
    machine    = alert.get("source_machine", "unknown")
    block_id   = alert.get("block_id", "N/A")
    alert_time = alert.get("alert_at", datetime.now().isoformat())
    n_events   = alert.get("num_events", 0)
    rule_based = alert.get("rule_based", False)

    # CVE / vulnerability fields — prefer values stored in the alert itself
    vuln_name  = alert.get("vulnerability_name", "")
    vuln_desc  = alert.get("vulnerability_desc", alert.get("description", ""))
    cve_ids    = alert.get("cve_ids", [])
    cwe        = alert.get("cwe", "")
    tip        = alert.get("remediation_tip", "")

    # Fall back to cve_lookup if alert predates the enrichment
    if not vuln_name or not tip:
        try:
            from cve_lookup import get_cve_info
            cats     = alert.get("threat_categories", [])
            cve_info = get_cve_info(cats)
            vuln_name = vuln_name or cve_info["name"]
            vuln_desc = vuln_desc or cve_info["description"]
            cve_ids   = cve_ids   or cve_info["cve_ids"]
            cwe       = cwe       or cve_info["cwe"]
            tip       = tip       or cve_info["tip"]
        except Exception:
            pass

    _PRIORITY_CVSS = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}
    cvss = alert.get("cvss_score") or _PRIORITY_CVSS.get(priority, 5.0)

    priority_color = {
        "CRITICAL": "#b91c1c",
        "HIGH"    : "#c2410c",
        "MEDIUM"  : "#b45309",
        "LOW"     : "#15803d",
    }.get(priority, "#b45309")

    priority_bg = {
        "CRITICAL": "#fef2f2",
        "HIGH"    : "#fff7ed",
        "MEDIUM"  : "#fffbeb",
        "LOW"     : "#f0fdf4",
    }.get(priority, "#fffbeb")

    priority_emoji = {
        "CRITICAL": "🔴",
        "HIGH"    : "🟠",
        "MEDIUM"  : "🟡",
        "LOW"     : "🟢",
    }.get(priority, "🟡")

    urgency_label = {
        "CRITICAL": "Act immediately — within the next 15 minutes",
        "HIGH"    : "Act today — within the next few hours",
        "MEDIUM"  : "Review soon — within 24 hours",
        "LOW"     : "Review when convenient",
    }.get(priority, "Review when convenient")

    # ── Unique subject — timestamp makes every email a new thread ─────────
    time_display = alert_time[:19].replace("T", " ") if "T" in alert_time else alert_time[:19]
    subject = (
        f"[Log Sentinel AI] {priority_emoji} {priority} Alert — "
        f"{machine} at {time_display}"
    )

    # ── Split tip into "right now" (urgent) vs "next steps" (preventive) ──
    immediate_steps, later_steps = _split_tip_steps(tip)

    def _li(text: str, color: str = "#1a1a1a") -> str:
        return (
            f'<li style="margin-bottom:10px; padding-left:4px; '
            f'color:{color}; line-height:1.6;">{text}</li>'
        )

    immediate_html = ""
    if immediate_steps:
        items = "".join(_li(s, "#7f1d1d") for s in immediate_steps)
        immediate_html = f"""
        <div style="margin:0 0 16px 0; padding:18px 20px; background:#fef2f2;
                    border-left:4px solid #dc2626; border-radius:6px;">
            <p style="margin:0 0 10px 0; font-size:15px; font-weight:700;
                      color:#991b1b;">
                🚨 Do This Right Now
            </p>
            <ul style="margin:0; padding-left:18px;">
                {items}
            </ul>
        </div>"""

    later_html = ""
    if later_steps:
        items = "".join(_li(s, "#1e3a5f") for s in later_steps)
        later_html = f"""
        <div style="margin:0 0 16px 0; padding:18px 20px; background:#eff6ff;
                    border-left:4px solid #2563eb; border-radius:6px;">
            <p style="margin:0 0 10px 0; font-size:15px; font-weight:700;
                      color:#1d4ed8;">
                📋 Next Steps (when you have time)
            </p>
            <ol style="margin:0; padding-left:18px;">
                {items}
            </ol>
        </div>"""

    _td_label     = "padding:9px 10px; font-weight:600; color:#374151; width:150px; border-bottom:1px solid #e5e7eb; vertical-align:top; font-size:13px;"
    _td_val       = "padding:9px 10px; color:#1f2937; border-bottom:1px solid #e5e7eb; font-size:13px;"
    _td_label_alt = _td_label + "background:#f9fafb;"
    _td_val_alt   = _td_val   + "background:#f9fafb;"

    # ── CVE references (compact) ──────────────────────────────────────────
    cve_html = ""
    if cve_ids:
        badges = " ".join(
            f'<code style="background:#1e293b; color:#93c5fd; padding:2px 7px; '
            f'border-radius:3px; font-size:11px; margin-right:4px;">{cid}</code>'
            for cid in cve_ids[:5]
        )
        cve_html = f'<tr><td style="{_td_label}">CVE References</td><td style="{_td_val}">{badges}</td></tr>'

    detection_label = "Rule-Based Detection" if rule_based else "AI Anomaly Detection"

    body_html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0; padding:0; background:#f3f4f6; font-family:'Segoe UI',Arial,sans-serif;">
<div style="max-width:600px; margin:24px auto; background:#ffffff;
            border-radius:10px; overflow:hidden;
            box-shadow:0 4px 20px rgba(0,0,0,0.10);">

    <!-- ── HEADER ── -->
    <div style="background:{priority_color}; padding:28px 28px 22px 28px;">
        <p style="margin:0 0 6px 0; color:rgba(255,255,255,0.75);
                  font-size:11px; letter-spacing:1.5px; text-transform:uppercase;">
            Log Sentinel AI · Security Alert
        </p>
        <h1 style="margin:0 0 6px 0; color:#ffffff; font-size:24px; font-weight:700; line-height:1.2;">
            {priority_emoji} {priority} Priority Alert
        </h1>
        <p style="margin:0; color:rgba(255,255,255,0.9); font-size:14px;">
            {vuln_name or threats_hr}
        </p>
    </div>

    <!-- ── URGENCY BANNER ── -->
    <div style="background:{priority_bg}; padding:10px 28px;
                border-bottom:1px solid #e5e7eb;">
        <p style="margin:0; font-size:13px; font-weight:600; color:{priority_color};">
            ⏱ {urgency_label}
        </p>
    </div>

    <!-- ── WHAT HAPPENED ── -->
    <div style="padding:22px 28px 0 28px;">
        <h2 style="margin:0 0 10px 0; font-size:16px; color:#111827; font-weight:700;">
            What happened?
        </h2>
        <p style="margin:0 0 12px 0; color:#374151; font-size:14px; line-height:1.7;">
            Log Sentinel AI detected a <strong>{threats_hr}</strong> event on
            <strong style="color:{priority_color};">{machine}</strong>.
            This alert was triggered at <strong>{time_display}</strong> and
            scored <strong>{cvss:.1f}/10</strong> on the CVSS severity scale
            ({n_events} system event{'' if n_events == 1 else 's'} analyzed).
        </p>
        {f'<p style="margin:0 0 18px 0; color:#4b5563; font-size:13px; line-height:1.7; padding:12px 14px; background:#f9fafb; border-radius:6px; border:1px solid #e5e7eb;">{vuln_desc}</p>' if vuln_desc else ''}
    </div>

    <!-- ── ACTION STEPS ── -->
    <div style="padding:6px 28px 6px 28px;">
        {immediate_html}
        {later_html}
    </div>

    <!-- ── ALERT DETAILS TABLE ── -->
    <div style="padding:0 28px 20px 28px;">
        <h2 style="margin:0 0 10px 0; font-size:14px; color:#6b7280;
                   font-weight:600; letter-spacing:0.5px; text-transform:uppercase;">
            Alert Details
        </h2>
        <table style="width:100%; border-collapse:collapse; font-size:13px;
                      border:1px solid #e5e7eb; border-radius:6px; overflow:hidden;">
            <tr>
                <td style="{_td_label_alt}">Machine</td>
                <td style="{_td_val_alt} font-family:monospace; color:{priority_color}; font-weight:600;">{machine}</td>
            </tr>
            <tr>
                <td style="{_td_label}">Time Detected</td>
                <td style="{_td_val}">{time_display}</td>
            </tr>
            <tr>
                <td style="{_td_label_alt}">Threat Type</td>
                <td style="{_td_val_alt}">{threats_hr}</td>
            </tr>
            <tr>
                <td style="{_td_label}">CVSS Score</td>
                <td style="{_td_val} font-weight:700; color:{priority_color};">{cvss:.1f} / 10</td>
            </tr>
            <tr>
                <td style="{_td_label_alt}">Detection Method</td>
                <td style="{_td_val_alt}">{detection_label}</td>
            </tr>
            {f'<tr><td style="{_td_label}">CWE</td><td style="{_td_val} font-family:monospace;">{cwe}</td></tr>' if cwe else ''}
            {cve_html}
        </table>
    </div>

    <!-- ── CTA BUTTON ── -->
    <div style="padding:4px 28px 28px 28px; text-align:center;">
        <a href="{DASHBOARD_URL}"
           style="display:inline-block; background:{priority_color}; color:#ffffff;
                  padding:13px 36px; border-radius:7px; text-decoration:none;
                  font-weight:700; font-size:15px; letter-spacing:0.3px;">
            Open Dashboard →
        </a>
    </div>

    <!-- ── FOOTER ── -->
    <div style="background:#f9fafb; padding:14px 28px;
                border-top:1px solid #e5e7eb; text-align:center;">
        <p style="margin:0; color:#9ca3af; font-size:11px; line-height:1.6;">
            This alert was sent by Log Sentinel AI. You are receiving this because
            your account is linked to <strong>{machine}</strong>.<br>
            Open the dashboard to review, label, or dismiss this alert.
        </p>
    </div>

</div>
</body></html>"""

    try:
        sent = False
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            for to_addr in recipients:
                try:
                    msg = MIMEMultipart("alternative")
                    msg["Subject"] = subject
                    msg["From"]    = EMAIL_FROM
                    msg["To"]      = to_addr
                    # Message-ID makes each email a completely independent thread
                    msg["Message-ID"] = f"<sentinel-{uuid.uuid4().hex}@logsentinel>"
                    msg.attach(MIMEText(body_html, "html", "utf-8"))
                    server.sendmail(EMAIL_FROM, to_addr, msg.as_string())
                    logger.info("Email sent to %s | %s | block=%s", to_addr, priority, block_id)
                    sent = True
                except Exception as exc:
                    logger.error("Failed to send to %s: %s", to_addr, exc)
        return sent
    except smtplib.SMTPAuthenticationError:
        logger.error("Email auth failed. Check NOTIFY_EMAIL_USER/PASS in .env")
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
        "sent_at"          : datetime.now().isoformat(timespec="seconds"),
        "block_id"         : alert.get("block_id"),
        "machine"          : alert.get("source_machine", ""),
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

_notified_cache: dict[str, float] = {}       # block_id → sent_timestamp


def _load_notified_cache() -> None:
    """Load previously sent block_ids from notification_log so we don't re-notify after a restart."""
    if not NOTIFY_LOG_FILE.exists():
        return
    now = time.time()
    try:
        with open(NOTIFY_LOG_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    block_id = rec.get("block_id", "")
                    sent_at  = rec.get("sent_at", "")
                    machine  = rec.get("machine", "")
                    if not block_id or not sent_at:
                        continue
                    ts  = datetime.fromisoformat(sent_at).timestamp()
                    age = now - ts
                    if age < COOLDOWN_SEC:
                        _notified_cache[block_id] = ts
                except Exception:
                    pass
    except Exception as e:
        logger.warning("Could not load notification log for dedup: %s", e)


def _should_notify(alert: dict) -> bool:
    """Deduplicate by block_id — each block fires at most once per COOLDOWN_SEC."""
    key = alert.get("block_id", "unknown")
    now = time.time()
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

    # 3. Email — HIGH and CRITICAL only (separate threshold from desktop)
    _order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if EMAIL_ENABLED and _order.get(priority, 0) >= _order.get(EMAIL_MIN_PRIORITY, 3):
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

    _load_notified_cache()
    logger.info("Loaded %d previously notified block_ids from log.", len(_notified_cache))

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
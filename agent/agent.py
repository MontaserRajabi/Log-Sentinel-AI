"""
agent.py  —  Log Sentinel AI  |  Log Agent
Run this on the SOURCE machine (the one generating logs).
Watches system logs and POSTs new lines to the central Log Sentinel frontend.

Usage examples:
    # Auto-detect OS and watch default log paths:
    python agent.py --server http://192.168.1.10:5000 --source web-server-01

    # Force a specific OS:
    python agent.py --server http://192.168.1.10:5000 --os linux --source db-01

    # Watch a custom log file (any OS):
    python agent.py --server http://192.168.1.10:5000 --log /var/log/nginx/access.log

Requirements:
    pip install requests psutil watchdog
"""

import argparse
import os
import platform
import random
import socket
import string
import subprocess
import sys
import time
import threading
import requests
import xml.etree.ElementTree as ET

# Force UTF-8 output on Windows (avoids UnicodeEncodeError for symbols)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG = True
except ImportError:
    WATCHDOG = False

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_SERVER  = "http://localhost:5000"
DEFAULT_SOURCE  = (platform.node() or "agent").lower()
API_KEY         = "sentinel-secret-key"
BATCH_SIZE      = 20
POLL_INTERVAL   = 3      # seconds between event log polls
HEALTH_INTERVAL = 10     # seconds between health reports
STATUS_INTERVAL = 120    # seconds between console status summaries
MAX_BACKOFF     = 60     # max seconds to wait on repeated connection failures

# Default log paths per OS
DEFAULT_LOG_PATHS = {
    "windows": [],       # handled via wevtutil — no file paths needed
    "linux"  : [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/kern.log",
    ],
    "macos"  : [],
}

# ---------------------------------------------------------------------------
# Stats (shared across threads via simple counters — no lock needed for display)
# ---------------------------------------------------------------------------
_stats = {"sent": 0, "alerts": 0, "errors": 0}


# ---------------------------------------------------------------------------
# Machine pairing
# ---------------------------------------------------------------------------

def _generate_code() -> str:
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choices(chars, k=6))


def register_pairing_code(server: str, machine: str, api_key: str) -> str | None:
    """
    Register a one-time pairing code with the server.
    Returns the code, or None if the server is unreachable.
    """
    code = _generate_code()
    try:
        resp = requests.post(
            f"{server}/api/pair/register",
            json={"machine": machine, "code": code},
            headers={"X-API-Key": api_key},
            timeout=8,
        )
        if resp.status_code == 200:
            return code
        print(f"[Agent] Pairing registration failed: HTTP {resp.status_code}")
        return None
    except Exception:
        return None


def _pairing_retry_loop(server: str, machine: str, api_key: str) -> None:
    """
    Background thread: if initial pairing registration failed, retry every 5 minutes
    until it succeeds. Useful when the server is briefly unreachable at startup.
    """
    interval = 300  # 5 minutes
    while True:
        time.sleep(interval)
        code = register_pairing_code(server, machine, api_key)
        if code:
            print()
            print_pairing_banner(code, machine, server)
            print("[Agent] Pairing code registered (retry succeeded).")
            break  # done — user can now pair


def print_pairing_banner(code: str, machine: str, server: str) -> None:
    width = 46
    border = "+" + "-" * width + "+"
    blank  = "|" + " " * width + "|"
    print()
    print(f"  {border}")
    print(f"  {blank}")
    print(f"  |  MACHINE PAIRING CODE" + " " * (width - 22) + "|")
    print(f"  {blank}")
    print(f"  |  Code: {code}" + " " * (width - 8 - len(code)) + "|")
    print(f"  {blank}")
    print(f"  | Machine : {machine}" + " " * (width - 12 - len(machine)) + "|")
    print(f"  {blank}")
    print(f"  {border}")
    print(f"  1. Go to the dashboard")
    print(f"  2. Click  Connect Machine")
    print(f"  3. Enter the code above")
    print(f"  (expires in 10 minutes)")
    print()


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


# ---------------------------------------------------------------------------
# Core sender  (with retry + backoff)
# ---------------------------------------------------------------------------

def _show_alert_toast(priority: str, description: str) -> None:
    """Show a Windows balloon-tip notification for a detected security alert."""
    if sys.platform != "win32":
        return
    title   = f"Log Sentinel AI — {priority} Alert"
    message = description[:200] if description else "Threat detected on your machine."
    title   = title.replace("'", "''")
    message = message.replace("'", "''")
    ps = (
        "Add-Type -AssemblyName System.Windows.Forms\n"
        "$n = New-Object System.Windows.Forms.NotifyIcon\n"
        "$n.Icon = [System.Drawing.SystemIcons]::Warning\n"
        "$n.Visible = $true\n"
        f"$n.ShowBalloonTip(8000, '{title}', '{message}', "
        "[System.Windows.Forms.ToolTipIcon]::Warning)\n"
        "Start-Sleep -Seconds 9\n"
        "$n.Dispose()\n"
    )
    try:
        import subprocess as _sp
        _sp.Popen(
            ["powershell", "-WindowStyle", "Hidden", "-NonInteractive", "-Command", ps],
            stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
            creationflags=0x08000000,
        )
    except Exception:
        pass


def send_logs(server: str, lines: list, source: str, api_key: str,
              max_retries: int = 3) -> bool:
    """Send a batch of log lines, retrying up to max_retries times on failure."""
    if not lines:
        return True
    payload = [{"log": line, "source": source} for line in lines]
    delay = 2
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.post(
                f"{server}/api/logs",
                json=payload,
                headers={"X-API-Key": api_key},
                timeout=10,
            )
            if resp.status_code == 201:
                _stats["sent"] += len(lines)
                print(f"[Agent] ✓  Sent {len(lines)} line(s)  [total: {_stats['sent']}]")
                try:
                    body = resp.json()
                    for alert in body.get("alerts", []):
                        priority    = alert.get("priority", "MEDIUM")
                        description = alert.get("description", "")
                        _stats["alerts"] += 1
                        print(f"[Agent] ⚠  Alert [{priority}]: {description[:100]}")
                        _show_alert_toast(priority, description)
                except Exception:
                    pass
                return True
            print(f"[Agent] ✗  Server {resp.status_code}: {resp.text[:120]}")
        except requests.ConnectionError:
            _stats["errors"] += 1
            print(f"[Agent] ✗  Cannot reach {server}"
                  + (f" — retry {attempt}/{max_retries} in {delay}s" if attempt < max_retries else " — giving up"))
        except Exception as e:
            _stats["errors"] += 1
            print(f"[Agent] ✗  {e}")
        if attempt < max_retries:
            time.sleep(delay)
            delay = min(delay * 2, 30)
    return False


# ---------------------------------------------------------------------------
# System health reporter
# ---------------------------------------------------------------------------

def _get_machine_ip() -> str:
    """Best-effort: return the machine's LAN IP address."""
    try:
        with socket.create_connection(("8.8.8.8", 80), timeout=2) as s:
            return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "unknown"


def _health_loop(server: str, source: str, api_key: str) -> None:
    """Send CPU / RAM / disk / IP stats every HEALTH_INTERVAL seconds."""
    try:
        import psutil
    except ImportError:
        print("[Agent] WARNING: psutil not installed — health metrics will NOT be sent.")
        print("[Agent]          Machine will show OFFLINE on the dashboard.")
        print("[Agent]          Fix: pip install psutil")
        return

    disk_path = "C:\\" if platform.system().lower() == "windows" else "/"
    machine_ip = _get_machine_ip()
    last_status_print = 0.0

    while True:
        try:
            cpu  = psutil.cpu_percent(interval=1)
            mem  = psutil.virtual_memory()
            disk = psutil.disk_usage(disk_path)
            payload = {
                "machine"   : source,
                "ip"        : machine_ip,
                "cpu"       : round(cpu, 1),
                "ram"       : round(mem.percent, 1),
                "ram_used"  : round(mem.used   / (1024 ** 3), 2),
                "ram_total" : round(mem.total  / (1024 ** 3), 2),
                "disk"      : round(disk.percent, 1),
                "disk_used" : round(disk.used   / (1024 ** 3), 1),
                "disk_total": round(disk.total  / (1024 ** 3), 1),
            }
            requests.post(
                f"{server}/api/health",
                json=payload,
                headers={"X-API-Key": api_key},
                timeout=5,
            )
        except Exception:
            pass

        # Periodic status summary so the console doesn't look frozen
        now = time.monotonic()
        if now - last_status_print >= STATUS_INTERVAL:
            last_status_print = now
            print(
                f"[Agent] Status — sent: {_stats['sent']} lines | "
                f"alerts: {_stats['alerts']} | errors: {_stats['errors']} | "
                f"ip: {machine_ip}"
            )

        time.sleep(HEALTH_INTERVAL)


# ---------------------------------------------------------------------------
# File tailer  (Linux / macOS / custom file)
# ---------------------------------------------------------------------------

class LogTailer:
    def __init__(self, path: str):
        self.path   = path
        self.offset = self._size()

    def _size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def read_new(self) -> list:
        try:
            current = self._size()
            if current < self.offset:
                print(f"[Agent] {self.path} rotated — resetting.")
                self.offset = 0
            if current == self.offset:
                return []
            with open(self.path, "r", errors="replace") as f:
                f.seek(self.offset)
                data = f.read()
                self.offset = f.tell()
            return [l.strip() for l in data.splitlines() if l.strip()]
        except FileNotFoundError:
            return []
        except Exception as e:
            print(f"[Agent] Read error ({self.path}): {e}")
            return []


# ---------------------------------------------------------------------------
# Windows Event Log reader  (uses wevtutil + XML for robust deduplication)
# ---------------------------------------------------------------------------

_WIN_CHANNELS  = ["Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational"]
_win_last_record: dict[str, int] = {}   # channel → last EventRecordID seen

_WEVT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Human-readable keywords for known security EventIDs
_EVTID_KEYWORDS: dict[int, str] = {
    # Authentication
    4624: "successful logon authentication",
    4625: "failed logon authentication failure brute force",
    4648: "explicit logon credentials used brute force",
    4634: "logoff session ended",
    4647: "user initiated logoff",
    4800: "workstation locked screen lock",
    4801: "workstation unlocked screen unlock",
    # Privilege / elevation
    4672: "special privileges assigned admin elevation",
    4703: "token right adjusted privilege escalation",
    4674: "operation attempted on privileged object",
    # Process execution
    4688: "process created new process execution",
    4689: "process terminated",
    # Scheduled tasks / services / persistence
    4698: "scheduled task created persistence autorun startup",
    4699: "scheduled task deleted",
    4702: "scheduled task updated",
    7034: "service crashed unexpected termination",
    7036: "service state changed started stopped",
    7040: "service start type changed persistence",
    7045: "new service installed persistence",
    # User / group management
    4720: "user account created privilege escalation admin",
    4722: "user account enabled",
    4723: "password change attempt",
    4724: "password reset attempt",
    4725: "user account disabled",
    4726: "user account deleted",
    4728: "member added security group privilege escalation",
    4732: "member added Administrators group privilege escalation admin",
    4756: "member added universal security group",
    4738: "user account changed",
    4740: "user account locked out brute force",
    # Kerberos / NTLM
    4768: "kerberos ticket requested authentication",
    4769: "kerberos service ticket requested",
    4771: "kerberos pre-authentication failed brute force",
    4776: "credential validation NTLM authentication",
    # Audit / policy / registry / time
    1102: "audit log cleared log deleted cover tracks",
    4616: "system time changed clock manipulation",
    4657: "registry value modified persistence",
    4719: "audit policy modified system policy changed",
    4826: "boot configuration changed bootkit",
    # Object access
    4663: "object access attempt file folder delete",
    # Network shares
    5140: "network share accessed lateral movement",
    5142: "network share added persistence",
    5143: "network share modified",
    5144: "network share deleted",
    # Firewall rule changes
    4946: "firewall rule added",
    4947: "firewall rule modified",
    4948: "firewall rule deleted",
    4950: "firewall setting changed",
    # RDP / remote access
    4778: "remote desktop session reconnected",
    4779: "remote desktop session disconnected",
    1149: "remote desktop authentication succeeded",
    # PowerShell
    4103: "powershell pipeline execution script",
    4104: "powershell script block logging execution",
    # External devices (USB)
    6416: "new device plugged in USB external storage",
    # Application crashes / errors
    1000: "application crashed unexpected error",
    1001: "windows error reporting crash",
}


def _parse_wevtutil_xml(xml_text: str) -> list[tuple[int, str]]:
    """
    Parse wevtutil XML output into (record_id, summary_line) pairs.
    Returns pairs sorted ascending by record_id (oldest first).
    """
    if not xml_text.strip():
        return []
    try:
        root = ET.fromstring(f"<Events>{xml_text}</Events>")
    except ET.ParseError:
        return []

    results = []
    ns = _WEVT_NS

    for ev in root:
        try:
            sys_el = ev.find(f"{{{ns}}}System")
            if sys_el is None:
                sys_el = ev.find("System")
            if sys_el is None:
                continue

            def _find(tag):
                el = sys_el.find(f"{{{ns}}}{tag}")
                if el is None:
                    el = sys_el.find(tag)
                return el

            rec_el  = _find("EventRecordID")
            evid_el = _find("EventID")
            time_el = _find("TimeCreated")
            ch_el   = _find("Channel")
            lvl_el  = _find("Level")
            comp_el = _find("Computer")

            record_id = int(rec_el.text) if rec_el is not None and rec_el.text else 0
            event_id  = evid_el.text.strip() if evid_el is not None and evid_el.text else "?"
            ts        = time_el.get("SystemTime", "") if time_el is not None else ""
            channel   = ch_el.text.strip() if ch_el is not None and ch_el.text else "?"
            computer  = comp_el.text.strip() if comp_el is not None and comp_el.text else ""
            level_val = lvl_el.text.strip() if lvl_el is not None and lvl_el.text else ""
            level_map = {"1": "CRITICAL", "2": "ERROR", "3": "WARNING", "4": "INFO", "0": "LOG"}
            level     = level_map.get(level_val, level_val)

            # EventData / UserData fields
            data_el = ev.find(f"{{{ns}}}EventData")
            if data_el is None:
                data_el = ev.find("EventData")
            if data_el is None:
                data_el = ev.find(f"{{{ns}}}UserData")
            if data_el is None:
                data_el = ev.find("UserData")
            data_parts = []
            if data_el is not None:
                for item in data_el.iter():
                    val = (item.text or "").strip()
                    if not val or val == item.tag:
                        continue
                    name = item.get("Name", "")
                    data_parts.append(f"{name}={val}" if name else val)

            summary = f"Channel={channel} EventID={event_id} Level={level} Time={ts}"
            if computer:
                summary += f" Computer={computer}"
            if data_parts:
                summary += " | " + " | ".join(data_parts[:8])

            # Append human-readable keywords so the threat classifier can match
            try:
                eid_int = int(event_id)
                kw = _EVTID_KEYWORDS.get(eid_int)
                if kw:
                    summary += f" | keywords={kw}"
            except ValueError:
                pass

            results.append((record_id, summary))
        except Exception:
            continue

    results.sort(key=lambda x: x[0])
    return results


def _read_windows_events(channel: str, max_events: int = 50) -> list[str]:
    """
    Pull new events from a Windows Event Log channel since the last seen RecordID.
    Uses wevtutil with XML format for reliable, gap-free deduplication.
    """
    last_id = _win_last_record.get(channel, 0)

    if last_id > 0:
        query = f"*[System[EventRecordID > {last_id}]]"
        cmd = [
            "wevtutil", "qe", channel,
            f"/c:{max_events}", "/rd:false",    # oldest first
            "/f:xml",
            f"/q:{query}",
        ]
    else:
        # First run — seed the cursor; don't send stale events
        cmd = [
            "wevtutil", "qe", channel,
            "/c:1", "/rd:true",
            "/f:xml",
        ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace",
        )
        if result.returncode != 0:
            return []

        pairs = _parse_wevtutil_xml(result.stdout)
        if not pairs:
            return []

        if last_id == 0:
            _win_last_record[channel] = pairs[-1][0]
            return []

        _win_last_record[channel] = pairs[-1][0]
        return [line for _, line in pairs]

    except FileNotFoundError:
        print("[Agent] wevtutil not found — are you on Windows?")
        return []
    except subprocess.TimeoutExpired:
        return []
    except Exception as e:
        print(f"[Agent] wevtutil error ({channel}): {e}")
        return []


# ---------------------------------------------------------------------------
# Watchdog handler for file-based collection
# ---------------------------------------------------------------------------

if WATCHDOG:
    class _Handler(FileSystemEventHandler):
        def __init__(self, tailers: list, server: str, source: str, api_key: str):
            self.tailers = tailers
            self.server  = server
            self.source  = source
            self.api_key = api_key
            self._buf: list[str] = []

        def on_modified(self, event):
            for tailer in self.tailers:
                if os.path.abspath(event.src_path) == os.path.abspath(tailer.path):
                    self._buf.extend(tailer.read_new())
            while len(self._buf) >= BATCH_SIZE:
                send_logs(self.server, self._buf[:BATCH_SIZE], self.source, self.api_key)
                self._buf = self._buf[BATCH_SIZE:]

        def flush(self):
            if self._buf:
                send_logs(self.server, self._buf, self.source, self.api_key)
                self._buf = []


# ---------------------------------------------------------------------------
# Collection loops  (with exponential backoff on repeated failures)
# ---------------------------------------------------------------------------

def run_windows(server: str, source: str, api_key: str) -> None:
    """Poll Windows Event Log channels in a loop."""
    # Filter out channels that aren't available on this machine (e.g. PowerShell logging disabled)
    active_channels = []
    for ch in _WIN_CHANNELS:
        test = subprocess.run(
            ["wevtutil", "qe", ch, "/c:1", "/rd:true", "/f:xml"],
            capture_output=True, timeout=5,
        )
        if test.returncode == 0:
            active_channels.append(ch)
        else:
            print(f"[Agent] Skipping channel (unavailable): {ch}")

    if not active_channels:
        print("[Agent] No Windows Event Log channels available. Are you running as Administrator?")
        return

    print(f"[Agent] Watching channels: {', '.join(active_channels)}")

    # Seed cursors so we don't flood old events on first run
    for ch in active_channels:
        _read_windows_events(ch, max_events=1)

    buf: list[str] = []
    consecutive_failures = 0

    try:
        while True:
            for ch in active_channels:
                buf.extend(_read_windows_events(ch))

            if buf:
                while len(buf) >= BATCH_SIZE:
                    ok = send_logs(server, buf[:BATCH_SIZE], source, api_key)
                    buf = buf[BATCH_SIZE:]
                    consecutive_failures = 0 if ok else consecutive_failures + 1
                if buf:
                    ok = send_logs(server, buf, source, api_key)
                    buf = []
                    consecutive_failures = 0 if ok else consecutive_failures + 1
            else:
                consecutive_failures = 0

            if consecutive_failures > 0:
                backoff = min(POLL_INTERVAL * (2 ** consecutive_failures), MAX_BACKOFF)
                time.sleep(backoff)
            else:
                time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        if buf:
            send_logs(server, buf, source, api_key)


def run_files(log_paths: list[str], server: str, source: str, api_key: str) -> None:
    """Tail one or more log files (Linux / macOS / custom)."""
    existing = [p for p in log_paths if os.path.exists(p)]
    if not existing:
        print(f"[Agent] Waiting for log files to appear: {log_paths}")
        while not existing:
            time.sleep(5)
            existing = [p for p in log_paths if os.path.exists(p)]

    print(f"[Agent] Watching {len(existing)} file(s): {', '.join(existing)}")
    tailers = [LogTailer(p) for p in existing]

    if WATCHDOG:
        watched_dirs: set[str] = {os.path.dirname(os.path.abspath(p)) for p in existing}
        handler  = _Handler(tailers, server, source, api_key)
        observer = Observer()
        for d in watched_dirs:
            observer.schedule(handler, path=d, recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(5)
                handler.flush()
        except KeyboardInterrupt:
            handler.flush()
            observer.stop()
        observer.join()
    else:
        buf: list[str] = []
        consecutive_failures = 0
        try:
            while True:
                for tailer in tailers:
                    buf.extend(tailer.read_new())
                if buf:
                    while len(buf) >= BATCH_SIZE:
                        ok = send_logs(server, buf[:BATCH_SIZE], source, api_key)
                        buf = buf[BATCH_SIZE:]
                        consecutive_failures = 0 if ok else consecutive_failures + 1
                    if buf:
                        ok = send_logs(server, buf, source, api_key)
                        buf = []
                        consecutive_failures = 0 if ok else consecutive_failures + 1
                else:
                    consecutive_failures = 0

                backoff = min(POLL_INTERVAL * (2 ** consecutive_failures), MAX_BACKOFF) if consecutive_failures else POLL_INTERVAL
                time.sleep(backoff)
        except KeyboardInterrupt:
            if buf:
                send_logs(server, buf, source, api_key)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help="Log Sentinel frontend URL (default: %(default)s)")
    parser.add_argument("--source", default=DEFAULT_SOURCE,
                        help="Label for this machine (default: hostname)")
    parser.add_argument("--key",    default=API_KEY,
                        help="API key (must match AGENT_API_KEY on the server)")
    parser.add_argument("--os",     default="auto",
                        choices=["auto", "windows", "linux"],
                        help="OS mode — auto-detects if omitted")
    parser.add_argument("--log",    default=None, nargs="+",
                        help="Custom log file path(s) — overrides OS default paths")
    args = parser.parse_args()

    os_mode = args.os if args.os != "auto" else detect_os()

    print()
    print(f"  +--------------------------------------------------+")
    print(f"  |  LogSentinelAI  —  Security Agent  v1.2          |")
    print(f"  +--------------------------------------------------+")
    print(f"  Server  : {args.server}")
    print(f"  Machine : {args.source}")
    print(f"  IP      : {_get_machine_ip()}")
    print(f"  OS mode : {os_mode}")
    print(f"  Polling : every {POLL_INTERVAL}s"
          + (" (event-driven)" if WATCHDOG else ""))
    print()

    code = register_pairing_code(args.server, args.source, args.key)
    if code:
        print_pairing_banner(code, args.source, args.server)
    else:
        print("[Agent] Could not reach server — will retry pairing every 5 minutes.")
        t = threading.Thread(
            target=_pairing_retry_loop,
            args=(args.server, args.source, args.key),
            daemon=True,
        )
        t.start()

    ht = threading.Thread(
        target=_health_loop,
        args=(args.server, args.source, args.key),
        daemon=True,
    )
    ht.start()

    if args.log:
        run_files(args.log, args.server, args.source, args.key)
    elif os_mode == "windows":
        run_windows(args.server, args.source, args.key)
    else:
        paths = DEFAULT_LOG_PATHS.get(os_mode, DEFAULT_LOG_PATHS["linux"])
        run_files(paths, args.server, args.source, args.key)

    print("[Agent] Stopped.")


if __name__ == "__main__":
    main()

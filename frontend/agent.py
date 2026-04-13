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
    pip install requests
    pip install watchdog   (optional — enables event-driven mode instead of polling)

Default log paths per OS
-------------------------
Windows : Windows Event Log  — Security, System, Application  (via wevtutil)
Linux   : /var/log/auth.log, /var/log/syslog  (or /var/log/messages on RHEL/CentOS)
macOS   : /var/log/system.log, /var/log/install.log
"""

import argparse
import os
import platform
import subprocess
import sys
import time
import requests

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
DEFAULT_SOURCE  = platform.node() or "agent"   # hostname by default
API_KEY         = "sentinel-secret-key"         # must match server.py AGENT_API_KEY
BATCH_SIZE      = 20
POLL_INTERVAL   = 3     # seconds

# Default log paths for each OS
DEFAULT_LOG_PATHS = {
    "windows": [],       # handled via wevtutil — no file paths needed
    "linux"  : [
        "/var/log/auth.log",        # Debian/Ubuntu
        "/var/log/syslog",          # Debian/Ubuntu
        "/var/log/messages",        # RHEL/CentOS/Fedora
        "/var/log/secure",          # RHEL/CentOS auth
        "/var/log/kern.log",        # kernel messages
    ],
    "macos"  : [],   # not supported
}


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def detect_os() -> str:
    """Return 'windows', 'linux', or 'macos' based on platform."""
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


# ---------------------------------------------------------------------------
# Core sender
# ---------------------------------------------------------------------------

def send_logs(server: str, lines: list, source: str, api_key: str) -> bool:
    if not lines:
        return True
    payload = [{"log": line, "source": source} for line in lines]
    try:
        resp = requests.post(
            f"{server}/api/logs",
            json=payload,
            headers={"X-API-Key": api_key},
            timeout=10,
        )
        if resp.status_code == 201:
            print(f"[Agent] ✓  Sent {len(lines)} line(s)")
            return True
        print(f"[Agent] ✗  Server {resp.status_code}: {resp.text[:120]}")
        return False
    except requests.ConnectionError:
        print(f"[Agent] ✗  Cannot reach {server} — will retry")
        return False
    except Exception as e:
        print(f"[Agent] ✗  {e}")
        return False


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
# Windows Event Log reader  (uses built-in wevtutil — no extra packages)
# ---------------------------------------------------------------------------

_WIN_CHANNELS = ["Security", "System", "Application"]
_win_last_record: dict[str, int] = {}   # channel → last record number seen


def _read_windows_events(channel: str, max_events: int = 30) -> list[str]:
    """
    Pull the latest events from a Windows Event Log channel.
    Uses wevtutil which is built into Windows Vista+ — no pip packages needed.
    Returns a list of single-line strings (one per event).
    """
    try:
        result = subprocess.run(
            [
                "wevtutil", "qe", channel,
                f"/c:{max_events}",
                "/rd:true",          # read direction: newest first
                "/f:text",           # plain-text format
            ],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return []

        lines = []
        current_parts: list[str] = []
        for raw in result.stdout.splitlines():
            raw = raw.strip()
            if not raw:
                if current_parts:
                    # Collapse multi-line event into single log line
                    lines.append(" | ".join(current_parts))
                    current_parts = []
            else:
                current_parts.append(raw)
        if current_parts:
            lines.append(" | ".join(current_parts))

        # Deduplicate: only return events we haven't sent before.
        # We use the first token (usually the event number / date) as a cursor.
        last = _win_last_record.get(channel, "")
        new_lines = []
        for line in lines:
            if last and line == last:
                break
            new_lines.append(line)
        if new_lines:
            _win_last_record[channel] = new_lines[0]   # newest event
        return list(reversed(new_lines))   # return oldest-first

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
# Collection loops
# ---------------------------------------------------------------------------

def run_windows(server: str, source: str, api_key: str) -> None:
    """Poll Windows Event Log channels in a loop."""
    print(f"[Agent] Watching Windows Event Log channels: {', '.join(_WIN_CHANNELS)}")
    # Seed last-seen so we don't flood old events on first start
    for ch in _WIN_CHANNELS:
        events = _read_windows_events(ch, max_events=1)
        if events:
            _win_last_record[ch] = events[-1]

    buf: list[str] = []
    try:
        while True:
            for ch in _WIN_CHANNELS:
                buf.extend(_read_windows_events(ch))
            while len(buf) >= BATCH_SIZE:
                send_logs(server, buf[:BATCH_SIZE], source, api_key)
                buf = buf[BATCH_SIZE:]
            if buf:
                send_logs(server, buf, source, api_key)
                buf = []
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        if buf:
            send_logs(server, buf, source, api_key)


def run_files(log_paths: list[str], server: str, source: str, api_key: str) -> None:
    """Tail one or more log files (Linux / macOS / custom)."""
    # Filter to existing paths
    existing = [p for p in log_paths if os.path.exists(p)]
    if not existing:
        print(f"[Agent] None of the target log files exist yet: {log_paths}")
        print("[Agent] Waiting for files to appear...")
        # Keep checking until at least one exists
        while not existing:
            time.sleep(5)
            existing = [p for p in log_paths if os.path.exists(p)]

    print(f"[Agent] Watching {len(existing)} file(s): {', '.join(existing)}")
    tailers = [LogTailer(p) for p in existing]

    if WATCHDOG:
        # Group tailers by directory for watchdog scheduling
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
        try:
            while True:
                for tailer in tailers:
                    buf.extend(tailer.read_new())
                while len(buf) >= BATCH_SIZE:
                    send_logs(server, buf[:BATCH_SIZE], source, api_key)
                    buf = buf[BATCH_SIZE:]
                if buf:
                    send_logs(server, buf, source, api_key)
                    buf = []
                time.sleep(POLL_INTERVAL)
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
                        help="OS mode — auto-detects if omitted (Windows and Linux only)")
    parser.add_argument("--log",    default=None, nargs="+",
                        help="Custom log file path(s) — overrides OS default paths")
    args = parser.parse_args()

    # Resolve OS
    os_mode = args.os if args.os != "auto" else detect_os()

    print(f"\n  Log Sentinel AI — Agent")
    print(f"  Server  : {args.server}")
    print(f"  Source  : {args.source}")
    print(f"  OS mode : {os_mode}")
    print(f"  Polling : every {POLL_INTERVAL}s"
          + (" (watchdog available)" if WATCHDOG else " (install watchdog for event-driven mode)"))
    print()

    if args.log:
        # Explicit file(s) provided — ignore OS default
        run_files(args.log, args.server, args.source, args.key)
    elif os_mode == "windows":
        run_windows(args.server, args.source, args.key)
    else:
        paths = DEFAULT_LOG_PATHS.get(os_mode, DEFAULT_LOG_PATHS["linux"])
        run_files(paths, args.server, args.source, args.key)

    print("[Agent] Stopped.")


if __name__ == "__main__":
    main()

"""
agent.py  —  Log Sentinel AI  |  Log Agent
Run this on the SOURCE server (the one generating logs).
It watches a log file and POSTs new lines to the central backend.

Usage:
    python agent.py --server http://<your-server-ip>:5000 --log /var/log/syslog --source web-server-01

Requirements:
    pip install requests watchdog
"""

import argparse
import os
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
# Config (can also be overridden by CLI args)
# ---------------------------------------------------------------------------
DEFAULT_SERVER   = "http://localhost:5000"
DEFAULT_LOG_FILE = "logs/sample_logs.txt"
DEFAULT_SOURCE   = "agent"
API_KEY          = "sentinel-secret-key"    # must match server.py
BATCH_SIZE       = 20                        # lines per POST
POLL_INTERVAL    = 3                         # seconds (fallback polling)

# ---------------------------------------------------------------------------
# Core sender
# ---------------------------------------------------------------------------

def send_logs(server: str, lines: list, source: str) -> bool:
    """POST a batch of log lines to the backend. Returns True on success."""
    if not lines:
        return True
    payload = [{"log": line, "source": source} for line in lines]
    try:
        resp = requests.post(
            f"{server}/api/logs",
            json=payload,
            headers={"X-API-Key": API_KEY},
            timeout=10
        )
        if resp.status_code == 201:
            print(f"[Agent] ✓  Sent {len(lines)} log(s)")
            return True
        else:
            print(f"[Agent] ✗  Server returned {resp.status_code}: {resp.text[:120]}")
            return False
    except requests.ConnectionError:
        print(f"[Agent] ✗  Cannot reach {server} — will retry")
        return False
    except Exception as e:
        print(f"[Agent] ✗  Error: {e}")
        return False


# ---------------------------------------------------------------------------
# File tail  (reads only NEW lines appended since last check)
# ---------------------------------------------------------------------------

class LogTailer:
    def __init__(self, path: str):
        self.path   = path
        self.offset = self._get_size()   # start from end of file

    def _get_size(self) -> int:
        try:
            return os.path.getsize(self.path)
        except OSError:
            return 0

    def read_new(self) -> list:
        """Return list of newly appended lines since last call."""
        try:
            current_size = self._get_size()
            if current_size < self.offset:
                # File was rotated / truncated — reset
                print("[Agent] Log file rotated — resetting offset.")
                self.offset = 0
            if current_size == self.offset:
                return []
            with open(self.path, "r", errors="replace") as f:
                f.seek(self.offset)
                new_data = f.read()
                self.offset = f.tell()
            lines = [l.strip() for l in new_data.splitlines() if l.strip()]
            return lines
        except FileNotFoundError:
            print(f"[Agent] Waiting for log file: {self.path}")
            return []
        except Exception as e:
            print(f"[Agent] Read error: {e}")
            return []


# ---------------------------------------------------------------------------
# Watchdog handler  (event-driven; used when watchdog is installed)
# ---------------------------------------------------------------------------

if WATCHDOG:
    class _Handler(FileSystemEventHandler):
        def __init__(self, tailer, server, source):
            self.tailer = tailer
            self.server = server
            self.source = source
            self._buf   = []

        def on_modified(self, event):
            if os.path.abspath(event.src_path) == os.path.abspath(self.tailer.path):
                self._buf.extend(self.tailer.read_new())
                while len(self._buf) >= BATCH_SIZE:
                    send_logs(self.server, self._buf[:BATCH_SIZE], self.source)
                    self._buf = self._buf[BATCH_SIZE:]

        def flush(self):
            if self._buf:
                send_logs(self.server, self._buf, self.source)
                self._buf = []


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Log Sentinel AI — Agent")
    parser.add_argument("--server", default=DEFAULT_SERVER,
                        help="Backend URL, e.g. http://192.168.1.10:5000")
    parser.add_argument("--log",    default=DEFAULT_LOG_FILE,
                        help="Path to the log file to monitor")
    parser.add_argument("--source", default=DEFAULT_SOURCE,
                        help="Label for this server (e.g. web-server-01)")
    parser.add_argument("--key",    default=API_KEY,
                        help="API key (must match backend)")
    args = parser.parse_args()

    global API_KEY
    API_KEY = args.key

    print(f"\n  Log Sentinel AI — Agent")
    print(f"  Server : {args.server}")
    print(f"  Watching: {args.log}")
    print(f"  Source : {args.source}")
    print(f"  Mode   : {'watchdog (event-driven)' if WATCHDOG else 'polling every ' + str(POLL_INTERVAL) + 's'}")
    print()

    tailer = LogTailer(args.log)

    if WATCHDOG:
        handler  = _Handler(tailer, args.server, args.source)
        observer = Observer()
        observer.schedule(handler, path=os.path.dirname(os.path.abspath(args.log)) or ".", recursive=False)
        observer.start()
        try:
            while True:
                time.sleep(5)
                handler.flush()   # flush partial batches every 5 s
        except KeyboardInterrupt:
            handler.flush()
            observer.stop()
        observer.join()
    else:
        # Simple polling fallback
        buf = []
        try:
            while True:
                buf.extend(tailer.read_new())
                while len(buf) >= BATCH_SIZE:
                    send_logs(args.server, buf[:BATCH_SIZE], args.source)
                    buf = buf[BATCH_SIZE:]
                if buf:
                    send_logs(args.server, buf, args.source)
                    buf = []
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            if buf:
                send_logs(args.server, buf, args.source)

    print("[Agent] Stopped.")


if __name__ == "__main__":
    main()

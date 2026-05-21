"""
Log Sentinel AI — Launcher  v1.2
Runs the log agent in-process, registers Windows startup, opens the dashboard.

Built with PyInstaller --onefile. The agent code is loaded directly via importlib
so the EXE is fully self-contained — no Python installation required on the user's machine.
"""

import argparse
import importlib.util
import os
import platform
import subprocess
import sys
import threading
import time
import webbrowser
from pathlib import Path

VERSION = "1.2"

# ── UTF-8 output ───────────────────────────────────────────────────────────
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Single-instance lock ───────────────────────────────────────────────────
def _acquire_single_instance() -> bool:
    """Return True if this is the only running instance, False otherwise."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        _acquire_single_instance._mutex = ctypes.windll.kernel32.CreateMutexW(
            None, False, "Global\\LogSentinelAI_SingleInstance"
        )
        return ctypes.windll.kernel32.GetLastError() != 183  # 183 = ERROR_ALREADY_EXISTS
    except Exception:
        return True


# ── Auto-elevate (needed to read Security event log) ──────────────────────
def _ensure_admin():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
        # Re-launch with admin rights.
        # When frozen the EXE is self-contained; when running as a script pass __file__.
        if getattr(sys, "frozen", False):
            params = None
        else:
            params = f'"{__file__}"'
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if ret > 32:
            sys.exit(0)
    except Exception:
        pass

_ensure_admin()

# ── Paths ──────────────────────────────────────────────────────────────────
FROZEN       = getattr(sys, "frozen", False)
ROOT         = Path(sys.executable).parent if FROZEN else Path(__file__).resolve().parent
AGENT_SCRIPT = ROOT / "agent.py"

AZURE_FRONTEND = "https://log-sentinel-ai-h3bmh3hbh6e3c6bx.francecentral-01.azurewebsites.net"

# ── Load optional .env overrides ──────────────────────────────────────────
def _load_env():
    env_file = ROOT / ".env"
    if not env_file.exists():
        return
    for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())

_load_env()
AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "sentinel-secret-key")

# ── ANSI colours ───────────────────────────────────────────────────────────
GRN = "\033[92m"
YEL = "\033[93m"
RED = "\033[91m"
CYN = "\033[96m"
DIM = "\033[2m"
RST = "\033[0m"


# ── Helpers ────────────────────────────────────────────────────────────────
def _machine_name() -> str:
    return (platform.node() or "local").lower()


def _log(tag: str, msg: str, colour: str = GRN):
    ts = time.strftime("%H:%M:%S")
    print(f"{DIM}[{ts}]{RST} {colour}[{tag}]{RST} {msg}")


def _show_toast(title: str, message: str, duration: int = 6) -> None:
    if sys.platform != "win32":
        return
    # Escape single quotes for PowerShell string literals
    title   = title.replace("'", "''")
    message = message.replace("'", "''")
    ps = (
        f"Add-Type -AssemblyName System.Windows.Forms\n"
        f"$n = New-Object System.Windows.Forms.NotifyIcon\n"
        f"$n.Icon = [System.Drawing.SystemIcons]::Shield\n"
        f"$n.Visible = $true\n"
        f"$n.ShowBalloonTip({duration * 1000}, '{title}', '{message}', "
        f"[System.Windows.Forms.ToolTipIcon]::Info)\n"
        f"Start-Sleep -Seconds {duration + 1}\n"
        f"$n.Dispose()\n"
    )
    try:
        subprocess.Popen(
            ["powershell", "-WindowStyle", "Hidden", "-NonInteractive", "-Command", ps],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=0x08000000,
        )
    except Exception:
        pass


def _register_startup():
    """Ask once if user wants to auto-start with Windows."""
    if sys.platform != "win32":
        return
    reg_key  = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "LogSentinelAI"
    try:
        import winreg, ctypes

        # Already registered?
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_READ)
            winreg.QueryValueEx(k, app_name)
            winreg.CloseKey(k)
            _log("OK  ", "Auto-start with Windows: enabled.")
            return
        except (FileNotFoundError, OSError):
            pass

        # Already asked?
        flag = ROOT / ".startup_asked"
        if flag.exists():
            return

        answer = ctypes.windll.user32.MessageBoxW(
            0,
            "Would you like Log Sentinel AI to start automatically when Windows starts?\n\n"
            "This keeps your machine monitored for threats in the background.\n"
            "You can remove it later by running:  LogSentinelAI.exe --uninstall",
            "Log Sentinel AI — Autostart",
            4,  # MB_YESNO
        )
        flag.touch()

        if answer == 6:  # IDYES
            cmd = f'"{sys.executable}"'
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, app_name, 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(k)
            _log("OK  ", "Registered in Windows startup.")
        else:
            _log("INFO", "Skipped Windows startup registration.", DIM)
    except Exception:
        pass


def _uninstall_startup():
    """Remove from Windows startup registry and clean up flags."""
    if sys.platform != "win32":
        print("Startup registration is only supported on Windows.")
        return
    reg_key  = r"Software\Microsoft\Windows\CurrentVersion\Run"
    app_name = "LogSentinelAI"
    try:
        import winreg
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(k, app_name)
            winreg.CloseKey(k)
            print(f"{GRN}[OK  ]{RST} Removed from Windows startup.")
        except FileNotFoundError:
            print(f"{YEL}[INFO]{RST} Not registered in Windows startup — nothing to remove.")
        flag = ROOT / ".startup_asked"
        if flag.exists():
            flag.unlink()
    except Exception as e:
        print(f"{RED}[ERR ]{RST} Could not remove startup entry: {e}")


def _install_deps():
    """Install Python dependencies — only runs when NOT frozen (script mode)."""
    if FROZEN:
        return   # deps are bundled inside the EXE
    req = ROOT / "requirements.txt"
    if not req.exists():
        return
    import shutil
    python = shutil.which("python3") or shutil.which("python") or sys.executable
    _log("DEPS", "Checking agent dependencies...", YEL)
    r = subprocess.run(
        [python, "-m", "pip", "install", "-r", str(req),
         "--quiet", "--disable-pip-version-check"],
        capture_output=True, text=True,
    )
    if r.returncode == 0:
        _log("OK  ", "Dependencies ready.")
    else:
        _log("WARN", f"pip install had errors:\n{r.stderr[:300]}", YEL)


# ── Agent runner (in-process, no subprocess needed) ────────────────────────
def _load_agent():
    """
    Load agent.py as a module from the same directory as the EXE / script.
    Works whether running frozen or as a plain Python script.
    """
    if not AGENT_SCRIPT.exists():
        raise FileNotFoundError(f"agent.py not found at {AGENT_SCRIPT}")
    spec = importlib.util.spec_from_file_location("_agent_module", AGENT_SCRIPT)
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run_agent(server: str, source: str, api_key: str) -> None:
    try:
        agent = _load_agent()
    except FileNotFoundError as e:
        _log("ERR ", str(e), RED)
        return

    os_mode = agent.detect_os()

    code = agent.register_pairing_code(server, source, api_key)
    if code:
        agent.print_pairing_banner(code, source, server)
    else:
        _log("WARN", "Could not reach server for pairing — will retry every 5 minutes.", YEL)
        t = threading.Thread(
            target=agent._pairing_retry_loop,
            args=(server, source, api_key),
            daemon=True,
        )
        t.start()

    ht = threading.Thread(
        target=agent._health_loop,
        args=(server, source, api_key),
        daemon=True,
    )
    ht.start()

    if os_mode == "windows":
        agent.run_windows(server, source, api_key)
    else:
        paths = agent.DEFAULT_LOG_PATHS.get(os_mode, agent.DEFAULT_LOG_PATHS["linux"])
        agent.run_files(paths, server, source, api_key)


# ── Main ───────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--uninstall", action="store_true",
                        help="Remove LogSentinelAI from Windows startup and exit.")
    parser.add_argument("--help", "-h", action="store_true")
    args, _ = parser.parse_known_args()

    if args.help:
        print(f"Log Sentinel AI v{VERSION}")
        print("Usage:")
        print("  LogSentinelAI.exe              Run the agent (normal mode)")
        print("  LogSentinelAI.exe --uninstall  Remove from Windows startup")
        return

    if args.uninstall:
        _uninstall_startup()
        input(f"\n{YEL}  Press Enter to close...{RST}")
        return

    print(f"""
{CYN}  +--------------------------------------------------+
  |   LOG  SENTINEL  AI  v{VERSION}                       |
  |   AI-Powered Intrusion Detection System         |
  +--------------------------------------------------+{RST}
""")

    if not _acquire_single_instance():
        print(f"{YEL}  Log Sentinel AI is already running on this machine.{RST}")
        print(f"  Dashboard: {CYN}{AZURE_FRONTEND}{RST}")
        print(f"\n{DIM}  (Close the other instance first if you want to restart.){RST}")
        input(f"\n{YEL}  Press Enter to close...{RST}")
        return

    v = sys.version_info
    if v < (3, 10):
        _log("WARN", f"Python 3.10+ recommended. You have {v.major}.{v.minor}.", YEL)
    else:
        _log("OK  ", f"Python {v.major}.{v.minor}.{v.micro}")

    _register_startup()
    _install_deps()

    machine = _machine_name()
    print()
    _log("INFO", f"Machine  : {machine}", CYN)
    _log("INFO", f"Dashboard: {AZURE_FRONTEND}", CYN)
    _log("INFO", "Starting agent...", CYN)
    print()

    _show_toast(
        "Log Sentinel AI — Active",
        f"Monitoring {machine} for threats. Opening dashboard...",
    )

    time.sleep(1)
    webbrowser.open(AZURE_FRONTEND)

    print(f"  {GRN}Agent is running.{RST}")
    print(f"  Dashboard : {CYN}{AZURE_FRONTEND}{RST}")
    print(f"\n  {YEL}Press Ctrl+C to stop.{RST}\n")

    while True:
        t = threading.Thread(
            target=_run_agent,
            args=(AZURE_FRONTEND, machine, AGENT_API_KEY),
            daemon=False,
        )
        t.start()
        try:
            while t.is_alive():
                t.join(timeout=2)
        except KeyboardInterrupt:
            _log("STOP", "Shutting down...", YEL)
            break

        if not t.is_alive():
            _log("WARN", "Agent stopped unexpectedly — restarting in 5s...", YEL)
            time.sleep(5)

    _log("STOP", "Agent stopped.")
    print(f"\n{GRN}  Goodbye.{RST}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n{RED}  ERROR: {e}{RST}")
        import traceback
        traceback.print_exc()
        print(f"\n{YEL}  Press Enter to close...{RST}")
        input()

"""
test_threat.py — Log Sentinel AI
==================================
Executes REAL threat simulations on this Windows machine.
The running agent picks up the generated events from the Windows
Event Log and sends them to the dashboard automatically.

REQUIREMENTS:
  - Run as Administrator (right-click → Run as administrator)
  - The agent (launcher.py or START.bat) must be running first

Usage:
    python test_threat.py                  # run all scenarios
    python test_threat.py --scenario brute_force
    python test_threat.py --list           # show available scenarios
    python test_threat.py --delay 10       # wait 10s between scenarios
"""

import argparse
import base64
import ctypes
import os
import platform
import subprocess
import sys
import time

# ── Force UTF-8 output on Windows (avoids UnicodeEncodeError for ⚠ ✓ → etc.)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ── Colour output ──────────────────────────────────────────────────────────
GRN = "\033[92m"; YEL = "\033[93m"; RED = "\033[91m"
CYN = "\033[96m"; DIM = "\033[2m";  RST = "\033[0m"

def ok(msg):   print(f"  {GRN}✓{RST}  {msg}")
def warn(msg): print(f"  {YEL}⚠{RST}  {msg}")
def err(msg):  print(f"  {RED}✗{RST}  {msg}")
def info(msg): print(f"  {CYN}→{RST}  {msg}")

def _run(cmd, timeout=15) -> bool:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0
    except Exception:
        return False


# ── Admin check ────────────────────────────────────────────────────────────

def is_admin() -> bool:
    if platform.system() != "Windows":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — Brute Force Login
# Windows Event ID 4625 (An account failed to log on)
# ══════════════════════════════════════════════════════════════════════════

def sim_brute_force(count: int = 6):
    """
    Simulate a brute-force attack by attempting multiple failed logons.
    Uses the Windows LogonUser API directly — generates real Event ID 4625
    entries in the Security log without any network calls.
    """
    info("Generating failed logon attempts → Event ID 4625")

    LOGON32_LOGON_NETWORK   = 3
    LOGON32_PROVIDER_DEFAULT = 0
    LogonUser = ctypes.windll.advapi32.LogonUserW

    succeeded = 0
    for i in range(count):
        token = ctypes.c_void_p()
        # Deliberately wrong password — will always fail and log 4625
        LogonUser(
            f"attacker_probe_{i:02d}",   # username  (non-existent)
            ".",                          # domain    (local machine)
            f"WrongP@ss#{i}!xZ",         # password  (wrong)
            LOGON32_LOGON_NETWORK,
            LOGON32_PROVIDER_DEFAULT,
            ctypes.byref(token),
        )
        succeeded += 1
        time.sleep(0.2)

    ok(f"Generated {succeeded} failed logon events (Event ID 4625 × {succeeded})")
    info("The IDS should flag this as: BRUTE_FORCE / HIGH or CRITICAL")


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — Privilege Escalation
# Events: 4720 (user created), 4732 (added to Admins),
#         4733 (removed from Admins), 4726 (user deleted)
# ══════════════════════════════════════════════════════════════════════════

def sim_privilege_escalation():
    """
    Create a test local user, elevate it to Administrator, then clean up.
    Generates the full privilege escalation event chain.
    """
    USERNAME = "SentinelProbe99"
    PASSWORD = "TmpT3st@2025!"

    info(f"Creating test user '{USERNAME}' → Event ID 4720")
    if not _run(["net", "user", USERNAME, PASSWORD, "/add"]):
        warn("Could not create user — may need Administrator rights")
        return

    time.sleep(0.5)
    info("Adding to Administrators group → Event ID 4732")
    _run(["net", "localgroup", "Administrators", USERNAME, "/add"])

    time.sleep(0.5)
    info("Removing from Administrators group → Event ID 4733")
    _run(["net", "localgroup", "Administrators", USERNAME, "/delete"])

    time.sleep(0.3)
    info("Deleting test user → Event ID 4726")
    _run(["net", "user", USERNAME, "/delete"])

    ok("Privilege escalation chain complete (4720 → 4732 → 4733 → 4726)")
    info("The IDS should flag this as: PRIVILEGE_ESC / HIGH")


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — Malicious Scheduled Task
# Events: 4698 (task created), 4699 (task deleted)
# ══════════════════════════════════════════════════════════════════════════

def sim_scheduled_task():
    """
    Register a scheduled task with a suspicious PowerShell payload,
    then delete it. Mimics a common persistence technique.
    """
    TASK = "\\SentinelMalwareTest"
    # Encoded payload: harmless "ipconfig" but looks like malware
    payload = base64.b64encode("ipconfig /all".encode("utf-16-le")).decode()
    cmd = f"powershell -WindowStyle Hidden -NoProfile -EncodedCommand {payload}"

    info(f"Creating suspicious scheduled task → Event ID 4698")
    created = _run([
        "schtasks", "/create",
        "/tn", TASK,
        "/tr", cmd,
        "/sc", "once", "/st", "23:59",
        "/f", "/rl", "HIGHEST",
    ])
    if not created:
        warn("schtasks create failed — needs Administrator rights")

    time.sleep(1)
    info("Deleting scheduled task → Event ID 4699")
    _run(["schtasks", "/delete", "/tn", TASK, "/f"])

    ok("Malicious scheduled task simulation complete (4698 → 4699)")
    info("The IDS should flag this as: PERSISTENCE / HIGH")


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 4 — Suspicious PowerShell Execution
# Mimics living-off-the-land / fileless malware techniques
# ══════════════════════════════════════════════════════════════════════════

def sim_suspicious_process():
    """
    Run PowerShell with flags commonly used by malware:
    -ExecutionPolicy Bypass, -WindowStyle Hidden, -EncodedCommand
    The actual command is harmless but the pattern is highly suspicious.
    """
    info("Running PowerShell with suspicious malware-style flags")

    commands = [
        # Encoded command (common evasion technique)
        ("Encoded command execution",
         ["powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
          "-EncodedCommand",
          base64.b64encode("Get-Process | Measure-Object".encode("utf-16-le")).decode()]),

        # Download cradle pattern (points to nothing harmful)
        ("Download cradle simulation",
         ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-NonInteractive",
          "-Command", "(New-Object Net.WebClient).DownloadString | Out-Null"]),

        # AMSI bypass pattern
        ("AMSI bypass pattern",
         ["powershell", "-Command",
          "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | Out-Null"]),
    ]

    for label, cmd in commands:
        info(f"  {label}")
        subprocess.run(cmd, capture_output=True, timeout=10)
        time.sleep(0.5)

    ok("Suspicious PowerShell patterns executed")
    info("The IDS should flag this as: SUSPICIOUS_PROCESS / MEDIUM-HIGH")


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 5 — Network Reconnaissance
# Mimics an attacker mapping the local network and system
# ══════════════════════════════════════════════════════════════════════════

def sim_network_recon():
    """
    Run a series of system/network enumeration commands in rapid succession —
    the same pattern an attacker uses immediately after gaining access.
    """
    info("Running network and system enumeration commands")

    commands = [
        (["netstat",  "-ano"],                          "Active connections (netstat -ano)"),
        (["arp",      "-a"],                             "ARP table (arp -a)"),
        (["net",      "user"],                           "Local user enumeration (net user)"),
        (["net",      "localgroup", "administrators"],   "Admin group members"),
        (["net",      "share"],                          "Network shares (net share)"),
        (["ipconfig", "/all"],                           "Full network config"),
        (["whoami",   "/all"],                           "Current user privileges"),
        (["tasklist", "/v"],                             "Running processes"),
        (["reg",      "query",
          r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"],
                                                        "OS registry query"),
        (["reg",      "query",
          r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"],
                                                        "Startup registry query"),
    ]

    for cmd, label in commands:
        info(f"  {label}")
        subprocess.run(cmd, capture_output=True, timeout=10)
        time.sleep(0.15)

    ok("Network reconnaissance simulation complete")
    info("The IDS should flag this as: RECON / MEDIUM")


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO 6 — Log Tampering
# Event ID 104 (System log): Application log cleared
# ══════════════════════════════════════════════════════════════════════════

def sim_log_tamper():
    """
    Clear the Application event log — the same first step
    an attacker takes to hide their tracks.
    Generates Event ID 104 in the System log.
    """
    info("Clearing Application event log → Event ID 104 in System log")

    cleared = _run(["wevtutil", "cl", "Application"])
    if cleared:
        ok("Application log cleared (Event ID 104)")
        info("The IDS should flag this as: LOG_TAMPER / HIGH")
    else:
        warn("Log clear failed — needs Administrator rights")


# ══════════════════════════════════════════════════════════════════════════
# SCENARIO REGISTRY
# ══════════════════════════════════════════════════════════════════════════

SCENARIOS = {
    "brute_force"     : (sim_brute_force,          "Multiple failed logons    → Event 4625 × 6"),
    "privilege_esc"   : (sim_privilege_escalation,  "Create/escalate user      → Events 4720, 4732, 4733, 4726"),
    "scheduled_task"  : (sim_scheduled_task,         "Malicious scheduled task  → Events 4698, 4699"),
    "suspicious_proc" : (sim_suspicious_process,     "Malware-style PowerShell  → Suspicious process pattern"),
    "network_recon"   : (sim_network_recon,          "Network enumeration       → Recon pattern"),
    "log_tamper"      : (sim_log_tamper,             "Clear event log           → Event 104"),
}


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Real Threat Simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scenario", "-s",
        default="all",
        choices=list(SCENARIOS.keys()) + ["all"],
        help="Scenario to run (default: all)",
    )
    parser.add_argument(
        "--delay", "-d",
        type=int, default=5,
        help="Seconds to wait between scenarios (default: 5)",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available scenarios and exit",
    )
    args = parser.parse_args()

    if args.list:
        print(f"\n{CYN}Available scenarios:{RST}\n")
        for name, (_, desc) in SCENARIOS.items():
            print(f"  {GRN}{name:<20}{RST} {desc}")
        print()
        return

    # ── Banner ─────────────────────────────────────────────────────────────
    print(f"""
{CYN}  +--------------------------------------------------+
  |   LOG  SENTINEL  AI  —  Threat Simulation       |
  +--------------------------------------------------+{RST}
""")

    # ── Admin check ────────────────────────────────────────────────────────
    if not is_admin():
        print(f"  {YEL}⚠  Not running as Administrator.{RST}")
        print(f"     Some scenarios need admin rights (privilege_esc, log_tamper).")
        print(f"     Right-click test_threat.py → Run as administrator for full results.\n")
    else:
        print(f"  {GRN}✓  Running as Administrator.{RST}\n")

    # ── Agent reminder ─────────────────────────────────────────────────────
    print(f"  {YEL}Make sure the agent (launcher.py / START.bat) is running!{RST}")
    print(f"  Events are written to Windows Event Log — the agent picks them up.")
    print(f"  Check the dashboard after each scenario.\n")
    print("  " + "─" * 50)

    # ── Run ────────────────────────────────────────────────────────────────
    to_run = list(SCENARIOS.items()) if args.scenario == "all" else [(args.scenario, SCENARIOS[args.scenario])]

    for i, (name, (fn, desc)) in enumerate(to_run):
        print(f"\n  {CYN}[{i+1}/{len(to_run)}] {name.upper()}{RST}")
        print(f"  {DIM}{desc}{RST}\n")
        try:
            fn()
        except KeyboardInterrupt:
            print(f"\n  {YEL}Skipped.{RST}")
        except Exception as e:
            err(f"Scenario failed: {e}")

        if i < len(to_run) - 1:
            print(f"\n  {DIM}Waiting {args.delay}s before next scenario...{RST}")
            try:
                time.sleep(args.delay)
            except KeyboardInterrupt:
                pass

    # ── Summary ────────────────────────────────────────────────────────────
    print(f"\n  {'─' * 50}")
    print(f"\n  {GRN}All simulations complete.{RST}")
    print(f"  → Open the dashboard and check for new alerts.")
    print(f"  → The agent sends logs every few seconds.")
    print(f"  → Allow 15–30 seconds for alerts to appear.\n")


if __name__ == "__main__":
    main()

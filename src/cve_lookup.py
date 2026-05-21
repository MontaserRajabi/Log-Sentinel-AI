"""
cve_lookup.py — Log Sentinel AI
=================================
Maps detected threat categories and Windows Event IDs to relevant CVE entries
from the NVD/MITRE database, plus a remediation tip for each threat type.

Two-layer approach:
  1. Static curated map  → always works, zero latency, offline-safe
  2. CIRCL CVE API       → optional online enrichment for real-time CVE details
                           (https://cve.circl.lu — free, no auth required)

Used by api.py when generating rule-based and ML alerts so every alert
includes actionable intelligence, not just a priority badge.
"""

import logging
import os

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static CVE / CWE / tip map  (one entry per threat category)
# Each entry contains:
#   cve_ids   : most relevant CVE IDs for this threat type
#   cwe       : CWE weakness classification
#   name      : human-readable vulnerability class
#   tip       : actionable remediation advice shown to the user
# ---------------------------------------------------------------------------

_CATEGORY_MAP: dict[str, dict] = {
    "brute_force": {
        "cve_ids": ["CVE-2019-0708", "CVE-2019-1182", "CVE-2022-21907"],
        "cwe"    : "CWE-307",
        "name"   : "Brute Force / Credential Attack",
        "description": (
            "Multiple failed logon attempts detected. CVE-2019-0708 (BlueKeep) and "
            "CVE-2019-1182 (DejaBlue) are critical RDP vulnerabilities exploited through "
            "repeated authentication attempts that can lead to remote code execution."
        ),
        "tip": (
            "1. Enable account lockout policy (lock after 5 failed attempts, 30-min lockout). "
            "2. Enforce multi-factor authentication (MFA) for all accounts. "
            "3. Restrict RDP access to known IPs via Windows Firewall. "
            "4. Rename the built-in Administrator account. "
            "5. Apply Windows security updates — patch CVE-2019-0708 immediately if unpatched."
        ),
    },

    "privilege_esc": {
        "cve_ids": ["CVE-2021-34527", "CVE-2020-1472", "CVE-2021-36934", "CVE-2022-37969"],
        "cwe"    : "CWE-269",
        "name"   : "Privilege Escalation",
        "description": (
            "Unauthorized elevation of privileges detected. CVE-2021-34527 (PrintNightmare) "
            "allows SYSTEM-level code execution via Print Spooler. CVE-2020-1472 (Zerologon) "
            "allows full domain compromise via Netlogon. CVE-2021-36934 (HiveNightmare) "
            "exposes SAM database to low-privilege users."
        ),
        "tip": (
            "1. Apply the principle of least privilege — audit and trim administrator group membership now. "
            "2. Install all pending Windows security patches immediately (patch PrintNightmare, Zerologon). "
            "3. Disable Print Spooler on Domain Controllers if not needed. "
            "4. Enable Windows Defender Credential Guard. "
            "5. Review all accounts added to Administrators group in the last 24 hours."
        ),
    },

    "startup": {
        "cve_ids": ["CVE-2019-1069", "CVE-2022-21999", "CVE-2023-21768"],
        "cwe"    : "CWE-693",
        "name"   : "Persistence / Scheduled Task Abuse",
        "description": (
            "Suspicious scheduled task or service creation detected. CVE-2019-1069 allows "
            "privilege escalation via Windows Task Scheduler. Attackers use scheduled tasks "
            "as a persistence mechanism to survive reboots and maintain access."
        ),
        "tip": (
            "1. Audit all scheduled tasks immediately: run 'schtasks /query /fo LIST /v' as admin. "
            "2. Delete any unrecognised tasks, especially those running PowerShell or encoded commands. "
            "3. Restrict who can create scheduled tasks via Group Policy "
            "   (Computer Configuration → Windows Settings → Security Settings → User Rights). "
            "4. Enable Task Scheduler event logging (Event ID 4698/4699). "
            "5. Use AppLocker or WDAC to prevent unauthorised executables from running."
        ),
    },

    "log_tamper": {
        "cve_ids": ["CVE-2021-31166", "CVE-2022-26809"],
        "cwe"    : "CWE-778",
        "name"   : "Log Tampering / Audit Trail Destruction",
        "description": (
            "Security event log was cleared (Event ID 1102/104). This is a classic attacker "
            "technique to erase evidence of compromise. Attackers clear logs immediately after "
            "gaining access to hide their activity from defenders."
        ),
        "tip": (
            "1. Forward all logs to a remote SIEM/log server immediately — "
            "   local log clearing cannot affect off-machine copies. "
            "2. Investigate what happened BEFORE the log was cleared using "
            "   remaining System/Application logs and network captures. "
            "3. Restrict 'Manage auditing and security log' user right to Administrators only "
            "   (secpol.msc → Local Policies → User Rights Assignment). "
            "4. Enable Windows Event Forwarding (WEF) to ship logs to a collector in real time. "
            "5. Treat log clearing as a confirmed breach indicator — begin incident response."
        ),
    },

    "suspicious_process": {
        "cve_ids": ["CVE-2022-30190", "CVE-2021-40444", "CVE-2021-26855"],
        "cwe"    : "CWE-78",
        "name"   : "Malicious Process / Living-off-the-Land Attack",
        "description": (
            "Suspicious PowerShell or process execution detected. CVE-2022-30190 (Follina) "
            "enables remote code execution via MSDT. CVE-2021-40444 exploits MSHTML "
            "via Office documents. Attackers use built-in tools (LOLBins) to evade AV detection."
        ),
        "tip": (
            "1. Enable PowerShell Script Block Logging and Transcription "
            "   (Group Policy → Administrative Templates → Windows Components → PowerShell). "
            "2. Set PowerShell Execution Policy to 'AllSigned' or 'RemoteSigned'. "
            "3. Enable AMSI (Antimalware Scan Interface) — ensure Windows Defender is active. "
            "4. Use AppLocker to block unsigned scripts and executables. "
            "5. Patch CVE-2022-30190 (Follina): disable MSDT URL protocol or apply KB5014699."
        ),
    },

    "dos": {
        "cve_ids": ["CVE-2021-31166", "CVE-2022-34691", "CVE-2022-26809"],
        "cwe"    : "CWE-400",
        "name"   : "Denial of Service / Resource Exhaustion",
        "description": (
            "Flood or resource exhaustion pattern detected. CVE-2021-31166 is a critical "
            "Windows HTTP Protocol Stack vulnerability exploitable for DoS and RCE. "
            "High connection rates can overwhelm services and cause system instability."
        ),
        "tip": (
            "1. Enable Windows Firewall rate limiting rules to block IPs with excessive connections. "
            "2. Apply CVE-2021-31166 patch (KB5003173) if IIS/HTTP.sys is exposed. "
            "3. Use a WAF or DDoS protection service (Azure DDoS Protection, Cloudflare) "
            "   in front of publicly exposed services. "
            "4. Configure IIS connection limits and request throttling. "
            "5. Monitor and alert on connections-per-second thresholds."
        ),
    },

    "network": {
        "cve_ids": ["CVE-2021-31166", "CVE-2022-26809", "CVE-2023-23397"],
        "cwe"    : "CWE-200",
        "name"   : "Network Reconnaissance / Lateral Movement",
        "description": (
            "Network scanning or enumeration activity detected. CVE-2023-23397 is a critical "
            "zero-click Outlook vulnerability used for credential theft via UNC paths. "
            "Reconnaissance is the first stage of a targeted attack."
        ),
        "tip": (
            "1. Implement network segmentation — isolate sensitive systems behind VLANs. "
            "2. Block outbound SMB (port 445) at the perimeter firewall. "
            "3. Patch CVE-2023-23397 (Outlook) — apply March 2023 security update. "
            "4. Deploy a Host-based IDS (e.g., Windows Defender for Endpoint) to detect "
            "   lateral movement patterns. "
            "5. Audit network shares (net share) and remove any unnecessary open shares."
        ),
    },

    "log_tamper": {
        "cve_ids": ["CVE-2021-31166", "CVE-2022-26809"],
        "cwe"    : "CWE-778",
        "name"   : "Log Tampering / Audit Trail Destruction",
        "description": (
            "Security event log was cleared (Event ID 1102/104). This is a classic attacker "
            "technique to erase evidence of compromise."
        ),
        "tip": (
            "1. Forward all logs to a remote SIEM/log server — local clearing cannot affect off-machine copies. "
            "2. Investigate what happened BEFORE the log was cleared. "
            "3. Restrict 'Manage auditing and security log' user right to Administrators only. "
            "4. Enable Windows Event Forwarding (WEF) to ship logs to a collector in real time. "
            "5. Treat log clearing as a confirmed breach indicator — begin incident response."
        ),
    },
}

# Per-EventID CVE enrichment for the new EXE (which includes EventID= in summaries)
_EVTID_MAP: dict[int, dict] = {
    4625: {
        "cve_ids"    : ["CVE-2019-0708", "CVE-2019-1182"],
        "cwe"        : "CWE-307",
        "name"       : "Failed Logon (Brute Force Attempt)",
        "description": "Windows failed logon. Repeated failures indicate a brute-force or password-spray attack.",
        "tip"        : "Enable account lockout, enforce MFA, restrict RDP to known IPs.",
    },
    4720: {
        "cve_ids"    : ["CVE-2020-1472", "CVE-2021-36934"],
        "cwe"        : "CWE-269",
        "name"       : "New User Account Created",
        "description": "A new local user account was created — possible attacker backdoor account.",
        "tip"        : "Verify the account is legitimate. Delete if unrecognised. Audit who has 'Create accounts' rights.",
    },
    4728: {
        "cve_ids"    : ["CVE-2021-34527", "CVE-2020-1472"],
        "cwe"        : "CWE-269",
        "name"       : "User Added to Security Group",
        "description": "A user was added to a privileged security group — possible privilege escalation.",
        "tip"        : "Verify the change is authorised. Remove if not. Review group membership policy.",
    },
    4732: {
        "cve_ids"    : ["CVE-2021-34527", "CVE-2022-37969"],
        "cwe"        : "CWE-269",
        "name"       : "User Added to Administrators Group",
        "description": "A user was added to the local Administrators group — high-severity privilege escalation.",
        "tip"        : "Remove the account immediately if not authorised. Rotate all admin credentials. Review UAC settings.",
    },
    4698: {
        "cve_ids"    : ["CVE-2019-1069", "CVE-2023-21768"],
        "cwe"        : "CWE-693",
        "name"       : "Scheduled Task Created (Persistence)",
        "description": "A new scheduled task was created — commonly used by malware for persistence.",
        "tip"        : "Review the task in Task Scheduler. Delete if unrecognised. Block task creation via Group Policy for non-admins.",
    },
    1102: {
        "cve_ids"    : [],
        "cwe"        : "CWE-778",
        "name"       : "Security Log Cleared",
        "description": "The Windows Security audit log was cleared — attackers do this to hide evidence.",
        "tip"        : "Treat as active breach. Enable log forwarding immediately. Investigate all activity before the clear event.",
    },
    4719: {
        "cve_ids"    : [],
        "cwe"        : "CWE-778",
        "name"       : "Audit Policy Modified",
        "description": "Windows audit policy was changed — attackers disable auditing to avoid detection.",
        "tip"        : "Restore audit policy via Group Policy. Investigate who changed it and when.",
    },
}

# ---------------------------------------------------------------------------
# CIRCL CVE API lookup (optional real-time enrichment)
# ---------------------------------------------------------------------------

_CIRCL_BASE   = "https://cve.circl.lu/api/cve/"
_CVE_CACHE: dict[str, dict] = {}   # simple in-process cache


def _fetch_cve_detail(cve_id: str, timeout: int = 3) -> dict | None:
    """
    Fetch CVE details from CIRCL's free CVE search API.
    Returns None silently on any error (offline, rate limit, etc.).
    Results are cached in-process to avoid duplicate requests.
    """
    if cve_id in _CVE_CACHE:
        return _CVE_CACHE[cve_id]
    try:
        import requests
        resp = requests.get(f"{_CIRCL_BASE}{cve_id}", timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            _CVE_CACHE[cve_id] = data
            return data
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_cve_info(
    threat_categories: list[str],
    event_id: int | None = None,
    enrich_online: bool | None = None,
) -> dict:
    """
    Return CVE information for a detected alert.

    Parameters
    ----------
    threat_categories : threat categories from the alert (e.g. ["brute_force"])
    event_id          : Windows EventID if available (enables per-event mapping)
    enrich_online     : fetch extra details from CIRCL CVE API if True.
                        Defaults to the CVE_ONLINE_LOOKUP env var (false by default).

    Returns a dict with keys:
        cve_ids, cwe, name, description, tip, cve_details (list of {id, summary, cvss})
    """
    if enrich_online is None:
        enrich_online = os.environ.get("CVE_ONLINE_LOOKUP", "false").lower() == "true"

    # 1. Try per-EventID mapping first (most specific)
    info = None
    if event_id and event_id in _EVTID_MAP:
        info = dict(_EVTID_MAP[event_id])

    # 2. Fall back to category mapping
    if info is None:
        for cat in (threat_categories or []):
            if cat in _CATEGORY_MAP:
                info = dict(_CATEGORY_MAP[cat])
                break

    # 3. Generic fallback
    if info is None:
        info = {
            "cve_ids"    : [],
            "cwe"        : "CWE-693",
            "name"       : "Security Anomaly Detected",
            "description": "An anomalous pattern was detected in system event logs.",
            "tip"        : (
                "Review recent system activity. Check Event Viewer for unusual entries. "
                "Ensure all Windows updates are applied. Run a full antivirus scan."
            ),
        }

    # 4. Optional online enrichment — fetch CIRCL details for the first CVE
    cve_details = []
    if enrich_online and info.get("cve_ids"):
        for cve_id in info["cve_ids"][:2]:   # limit to 2 lookups per alert
            detail = _fetch_cve_detail(cve_id)
            if detail:
                cve_details.append({
                    "id"     : cve_id,
                    "summary": detail.get("summary", "")[:300],
                    "cvss"   : detail.get("cvss"),
                    "cvss3"  : detail.get("cvss3"),
                    "published": detail.get("Published", ""),
                })
            else:
                cve_details.append({"id": cve_id, "summary": "", "cvss": None})

    # Always include static IDs even if online lookup is off
    if not cve_details:
        cve_details = [{"id": cid, "summary": "", "cvss": None}
                       for cid in info.get("cve_ids", [])]

    return {
        "cve_ids"    : info.get("cve_ids", []),
        "cwe"        : info.get("cwe", ""),
        "name"       : info.get("name", ""),
        "description": info.get("description", ""),
        "tip"        : info.get("tip", ""),
        "cve_details": cve_details,
    }

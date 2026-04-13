"""
detector.py
Log analysis engine for Log Sentinel AI.

Current implementation: rule-based keyword + template scoring.
This module is designed as a drop-in replacement — when your teammate
finishes the ML backend, they only need to replace `analyze_log()`.

Scoring logic (CVSS / CVE scale 0.0 – 10.0):
  - Base score starts at 0.0
  - Each matched attack keyword adds a weighted score
  - Template matches (admin-defined patterns) add bonus weight
  - Final score is clamped to [0.0, 10.0]
  - Score >= 9.0  → CRITICAL
  - Score >= 7.0  → HIGH
  - Score >= 4.0  → MEDIUM
  - Score >  0.0  → LOW
  - Score == 0.0  → NONE
"""

import re
from typing import Optional

from pathlib import Path as _Path
TEMPLATES_FILE = _Path(__file__).resolve().parent.parent / "templates.txt"
_templates_cache: Optional[list] = None

# ---------------------------------------------------------------------------
# Keyword registry  {keyword: weight}
# Higher weight = stronger signal of malicious activity
# ---------------------------------------------------------------------------
ATTACK_KEYWORDS: dict[str, float] = {
    # Authentication failures
    "failed login":        5.5,
    "authentication failed": 5.5,
    "invalid password":    5.0,
    "invalid credentials": 5.0,
    "login failed":        5.5,
    "failed":              2.5,

    # Access control
    "unauthorized":        6.0,
    "access denied":       6.0,
    "permission denied":   5.5,
    "forbidden":           5.0,
    "denied":              4.0,

    # Privilege / escalation
    "privilege escalation": 7.5,
    "sudo":                2.0,
    "root access":         6.5,
    "admin access":        5.0,

    # Injection / exploitation
    "sql injection":       8.5,
    "xss":                 8.0,
    "script injection":    8.0,
    "command injection":   8.5,
    "exploit":             7.5,
    "payload":             6.5,

    # Brute force
    "brute force":         8.0,
    "multiple failed":     7.0,
    "repeated attempts":   7.0,

    # Malware / tampering
    "malware":             9.0,
    "ransomware":          9.5,
    "trojan":              9.0,
    "log tamper":          8.5,
    "modified log":        8.5,

    # Network
    "port scan":           7.0,
    "intrusion":           7.5,
    "suspicious ip":       6.5,

    # General anomaly
    "error":               1.5,
    "attack":              7.0,
    "warning":             1.0,
}


# ---------------------------------------------------------------------------
# Template helpers
# ---------------------------------------------------------------------------

def load_templates() -> list:
    """
    Load admin-defined threat templates from disk.
    Each non-empty line is treated as a keyword/phrase template.
    Results are cached in memory until explicitly reloaded.
    """
    global _templates_cache
    try:
        with open(TEMPLATES_FILE, "r") as f:
            _templates_cache = [
                line.strip()
                for line in f
                if line.strip()
            ]
    except FileNotFoundError:
        _templates_cache = []
    except Exception as e:
        print(f"[Detector] Template load error: {e}")
        _templates_cache = []
    return _templates_cache


def save_templates(templates) -> None:
    """Persist a list/tuple of template strings to disk and update cache."""
    global _templates_cache
    try:
        with open(TEMPLATES_FILE, "w") as f:
            for t in templates:
                if t.strip():
                    f.write(t.strip() + "\n")
        _templates_cache = [t.strip() for t in templates if t.strip()]
    except Exception as e:
        print(f"[Detector] Template save error: {e}")


def reload_templates() -> list:
    """Force a fresh load from disk (clears cache)."""
    global _templates_cache
    _templates_cache = None
    return load_templates()


# ---------------------------------------------------------------------------
# Core scoring
# ---------------------------------------------------------------------------

def _keyword_score(log_lower: str) -> float:
    """
    Walk through ATTACK_KEYWORDS and accumulate weights for every match.
    Multi-word keywords are checked as substrings; single words use
    whole-word matching to avoid false positives (e.g. 'error' inside
    'authentication').
    """
    total = 0.0
    for keyword, weight in ATTACK_KEYWORDS.items():
        if " " in keyword:
            # Multi-word phrase — simple substring match
            if keyword in log_lower:
                total += weight
        else:
            # Single word — whole-word boundary match
            pattern = r"\b" + re.escape(keyword) + r"\b"
            if re.search(pattern, log_lower):
                total += weight
    return total


def _template_score(log_lower: str) -> float:
    """Return a bonus score if any admin template matches the log line."""
    global _templates_cache
    if _templates_cache is None:
        load_templates()
    bonus = 0.0
    for template in _templates_cache:
        if template.lower() in log_lower:
            bonus += 3.0
    return bonus


def analyze_log(log: str) -> float:
    """
    Main entry point for log threat scoring.

    Parameters
    ----------
    log : str
        A single raw log line (any format).

    Returns
    -------
    float
        Threat score in [0.0, 1.0].
        0.0  = completely normal
        1.0  = highly suspicious / confirmed threat indicator
    """
    if not log or not log.strip():
        return 0.0

    log_lower = log.lower()

    score = _keyword_score(log_lower) + _template_score(log_lower)

    # Clamp to [0, 10]
    score = min(score, 10.0)

    return round(score, 1)


def classify_score(score: float) -> str:
    """
    Convert a numeric score (CVE/CVSS scale 0.0–10.0) to a threat level.
    Used by the UI to colour-code rows.
    """
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"
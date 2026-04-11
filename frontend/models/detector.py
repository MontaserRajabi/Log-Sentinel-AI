"""
detector.py
Log analysis engine for Log Sentinel AI.

Current implementation: rule-based keyword + template scoring.
This module is designed as a drop-in replacement — when your teammate
finishes the ML backend, they only need to replace `analyze_log()`.

Scoring logic:
  - Base score starts at 0.0
  - Each matched attack keyword adds a weighted score
  - Template matches (admin-defined patterns) add bonus weight
  - Final score is clamped to [0.0, 1.0]
  - Score >= 0.7  → HIGH threat
  - Score >= 0.4  → MEDIUM threat
  - Score <  0.4  → LOW / normal
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
    "failed login":        0.55,
    "authentication failed": 0.55,
    "invalid password":    0.50,
    "invalid credentials": 0.50,
    "login failed":        0.55,
    "failed":              0.25,

    # Access control
    "unauthorized":        0.60,
    "access denied":       0.60,
    "permission denied":   0.55,
    "forbidden":           0.50,
    "denied":              0.40,

    # Privilege / escalation
    "privilege escalation": 0.75,
    "sudo":                0.20,
    "root access":         0.65,
    "admin access":        0.50,

    # Injection / exploitation
    "sql injection":       0.85,
    "xss":                 0.80,
    "script injection":    0.80,
    "command injection":   0.85,
    "exploit":             0.75,
    "payload":             0.65,

    # Brute force
    "brute force":         0.80,
    "multiple failed":     0.70,
    "repeated attempts":   0.70,

    # Malware / tampering
    "malware":             0.90,
    "ransomware":          0.95,
    "trojan":              0.90,
    "log tamper":          0.85,
    "modified log":        0.85,

    # Network
    "port scan":           0.70,
    "intrusion":           0.75,
    "suspicious ip":       0.65,

    # General anomaly
    "error":               0.15,
    "attack":              0.70,
    "warning":             0.10,
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
            bonus += 0.30
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

    # Clamp to [0, 1]
    score = min(score, 1.0)

    return round(score, 2)


def classify_score(score: float) -> str:
    """
    Convert a numeric score to a human-readable threat level.
    Used by the UI to colour-code rows.
    """
    if score >= 0.7:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    return "LOW"
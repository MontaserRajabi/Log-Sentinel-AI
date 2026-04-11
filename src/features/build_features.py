"""
build_features.py — Log Sentinel AI
=====================================
Extracts block-level and event-level features from parsed HDFS log events.

Feature engineering is designed to support the Isolation Forest anomaly
detection model (isoforest.pkl) and aligns with the threat scenarios
described in the system design:
  - Brute-force login attempts
  - Privilege escalation
  - DoS / flood activity
  - Log tampering (gaps, missing sequences)
  - Insider threats (unusual access patterns)
  - Suspicious startup / service activity

Input  : data/parsed/events_parsed.jsonl
Outputs: data/features/block_features.parquet
         data/features/event_features.parquet
"""

import json
import math
import logging
import argparse
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

import pandas as pd
import numpy as np

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Constants ──────────────────────────────────────────────────────────────────
DEFAULT_INPUT  = "data/parsed/events_parsed.jsonl"
DEFAULT_BLOCK  = "data/features/block_features.parquet"
DEFAULT_EVENT  = "data/features/event_features.parquet"

# Keywords mapped to threat categories (from threat model Table 3.1)
THREAT_KEYWORDS = {
    "brute_force"   : ["failed", "invalid", "wrong password", "authentication failure",
                       "login failed", "bad credentials"],
    "privilege_esc" : ["privilege", "escalation", "sudo", "root", "admin", "elevated",
                       "permission denied", "unauthorized"],
    "dos"           : ["flood", "overload", "too many requests", "rate limit",
                       "connection refused", "timeout"],
    "log_tamper"    : ["deleted", "modified", "cleared", "truncated", "log rotation"],
    "startup"       : ["startup", "boot", "init", "service start", "autorun",
                       "scheduled task", "cron"],
    "network"       : ["port scan", "ssh", "firewall", "connection attempt",
                       "remote", "intrusion"],
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_level(raw: str) -> str:
    """Classify a log line into ERROR / WARN / INFO based on keywords."""
    lower = raw.lower()
    if any(k in lower for k in ("error", "exception", "critical", "fatal")):
        return "ERROR"
    if any(k in lower for k in ("warn", "warning")):
        return "WARN"
    return "INFO"


def _parse_timestamp(raw: str) -> datetime | None:
    """
    Try several common timestamp formats found at the start of log lines.
    Returns a datetime object or None if no timestamp can be parsed.
    """
    formats = [
        ("%Y-%m-%dT%H:%M:%S", 19),   # ISO-8601 without ms
        ("%Y-%m-%d %H:%M:%S", 19),   # space-separated datetime
        ("%y/%m/%d %H:%M:%S", 17),   # short-year slash
        ("%Y-%m-%d",          10),   # date only
    ]
    token = raw.strip()
    for fmt, length in formats:
        try:
            return datetime.strptime(token[:length], fmt)
        except ValueError:
            continue
    return None


def _shannon_entropy(values: list) -> float:
    """Calculate Shannon entropy of a discrete distribution."""
    counts = Counter(values)
    total  = sum(counts.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _threat_flag_counts(events: list[dict]) -> dict:
    """
    Count how many log lines in a block match each threat-keyword category.
    Returns a dict like {"brute_force_hits": 3, "privilege_esc_hits": 0, ...}
    """
    counts = {f"{cat}_hits": 0 for cat in THREAT_KEYWORDS}
    for e in events:
        lower = e["raw"].lower()
        for cat, keywords in THREAT_KEYWORDS.items():
            if any(kw in lower for kw in keywords):
                counts[f"{cat}_hits"] += 1
    return counts


def _detect_sequence_gaps(events: list[dict]) -> int:
    """
    Count missing line numbers in a block's sequence.
    Large gaps may indicate log tampering (entries deleted).
    Requires events to have a 'line_id' field; returns 0 if unavailable.
    """
    line_ids = sorted(
        [e["line_id"] for e in events if "line_id" in e and e["line_id"] is not None]
    )
    if len(line_ids) < 2:
        return 0
    expected = set(range(line_ids[0], line_ids[-1] + 1))
    return len(expected - set(line_ids))


def _load_events(input_file: str) -> dict[str, list[dict]]:
    """
    Load events_parsed.jsonl and group them by block_id.
    Each JSON line must have at minimum: block_id, raw, template_id.
    """
    path = Path(input_file)
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path.resolve()}")

    blocks: dict[str, list[dict]] = defaultdict(list)
    total = 0
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("Skipping malformed JSON at line %d: %s", lineno, exc)
                continue

            # Validate required fields
            for field in ("block_id", "raw", "template_id"):
                if field not in event:
                    logger.warning("Line %d missing field '%s', skipping.", lineno, field)
                    break
            else:
                blocks[event["block_id"]].append(event)
                total += 1

    logger.info("Loaded %d events across %d blocks.", total, len(blocks))
    return blocks


# ── Block-level feature extraction ────────────────────────────────────────────

def build_block_features(
    input_file: str = DEFAULT_INPUT,
    output_file: str = DEFAULT_BLOCK,
) -> pd.DataFrame:
    """
    Build one feature row per block_id.

    Features
    --------
    Basic counts     : num_events, unique_templates, error/warn/info counts + ratios
    Message stats    : avg/max/min/std of raw message length
    Template entropy : Shannon entropy of template distribution (higher = more varied)
    Temporal         : block_duration_sec, events_per_second (burst indicator)
    Sequence gaps    : gap_count (potential log tampering signal)
    Threat hits      : per-category keyword match counts from threat model
    Repetition       : top_template_ratio (fraction of most-common template — DoS indicator)
    """
    blocks = _load_events(input_file)

    rows = []
    for block_id, events in blocks.items():
        msg_lens  = [len(e["raw"]) for e in events]
        templates = [e["template_id"] for e in events]
        levels    = [_parse_level(e["raw"]) for e in events]

        # ── Temporal features ──────────────────────────────────────────────────
        timestamps = [_parse_timestamp(e["raw"]) for e in events]
        timestamps = [ts for ts in timestamps if ts is not None]
        if len(timestamps) >= 2:
            block_duration = (max(timestamps) - min(timestamps)).total_seconds()
            events_per_sec = len(events) / block_duration if block_duration > 0 else float("inf")
        else:
            block_duration = 0.0
            events_per_sec = 0.0

        # ── Template distribution ──────────────────────────────────────────────
        template_counts = Counter(templates)
        top_template_ratio = (
            template_counts.most_common(1)[0][1] / len(templates)
            if templates else 0.0
        )

        # ── Threat keyword hits ────────────────────────────────────────────────
        threat_counts = _threat_flag_counts(events)

        # ── Sequence gap (log tampering) ───────────────────────────────────────
        gap_count = _detect_sequence_gaps(events)

        # ── Aggregate any numeric event-level fields ──────────────────────────
        row = {
            # Identifiers
            "block_id"           : block_id,
            # Event counts
            "num_events"         : len(events),
            "unique_templates"   : len(set(templates)),
            # Message length statistics
            "avg_msg_len"        : float(np.mean(msg_lens)),
            "std_msg_len"        : float(np.std(msg_lens)),
            "max_msg_len"        : max(msg_lens),
            "min_msg_len"        : min(msg_lens),
            # Log level counts and ratios
            "error_count"        : levels.count("ERROR"),
            "warn_count"         : levels.count("WARN"),
            "info_count"         : levels.count("INFO"),
            "error_ratio"        : levels.count("ERROR") / len(levels),
            "warn_ratio"         : levels.count("WARN")  / len(levels),
            # Template diversity
            "template_entropy"   : _shannon_entropy(templates),
            "top_template_ratio" : top_template_ratio,
            # Temporal
            "block_duration_sec" : block_duration,
            "events_per_sec"     : events_per_sec,
            # Anomaly signals
            "gap_count"          : gap_count,
        }
        row.update(threat_counts)
        rows.append(row)

    df = pd.DataFrame(rows)

    # Replace inf values (from division by zero on zero-duration bursts)
    df.replace([float("inf"), float("-inf")], -1, inplace=True)

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_file, index=False)
    logger.info("Block features saved → %s  (%d rows, %d cols)", output_file, len(df), len(df.columns))
    return df


# ── Event-level feature extraction ────────────────────────────────────────────

def build_event_features(
    input_file: str  = DEFAULT_INPUT,
    output_file: str = DEFAULT_EVENT,
) -> pd.DataFrame:
    """
    Build one feature row per individual log event.
    Useful for sequence-based anomaly detection (e.g., LSTM / DeepLog style).

    Features
    --------
    Identifiers  : block_id, event_index, template_id
    Text stats   : msg_len, word_count
    Level flags  : is_error, is_warn, is_info
    Threat flags : one binary column per threat category
    Timestamp    : has_timestamp (1/0)
    """
    blocks = _load_events(input_file)

    rows = []
    for block_id, events in blocks.items():
        for idx, e in enumerate(events):
            lower = e["raw"].lower()
            threat_flags = {
                f"{cat}_flag": int(any(kw in lower for kw in kws))
                for cat, kws in THREAT_KEYWORDS.items()
            }
            level = _parse_level(e["raw"])
            ts    = _parse_timestamp(e["raw"])

            row = {
                "block_id"      : block_id,
                "event_index"   : idx,
                "template_id"   : e["template_id"],
                "msg_len"       : len(e["raw"]),
                "word_count"    : len(e["raw"].split()),
                "is_error"      : int(level == "ERROR"),
                "is_warn"       : int(level == "WARN"),
                "is_info"       : int(level == "INFO"),
                "has_timestamp" : int(ts is not None),
            }
            row.update(threat_flags)
            rows.append(row)

    df = pd.DataFrame(rows)
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_file, index=False)
    logger.info("Event features saved → %s  (%d rows, %d cols)", output_file, len(df), len(df.columns))
    return df


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Feature Engineering Pipeline"
    )
    parser.add_argument("--input",       default=DEFAULT_INPUT,
                        help="Path to events_parsed.jsonl")
    parser.add_argument("--block-out",   default=DEFAULT_BLOCK,
                        help="Output path for block_features.parquet")
    parser.add_argument("--event-out",   default=DEFAULT_EVENT,
                        help="Output path for event_features.parquet")
    parser.add_argument("--block-only",  action="store_true",
                        help="Build block features only (skip event features)")
    parser.add_argument("--event-only",  action="store_true",
                        help="Build event features only (skip block features)")
    args = parser.parse_args()

    if not args.event_only:
        build_block_features(args.input, args.block_out)

    if not args.block_only:
        build_event_features(args.input, args.event_out)


if __name__ == "__main__":
    main()
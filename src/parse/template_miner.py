"""
template_miner.py — Log Sentinel AI
=====================================
Parses raw log lines into structured events with stable template IDs.

This is the first step in the pipeline:
    log_collector.py → events.jsonl
    template_miner.py → events_parsed.jsonl   ← this file
    build_features.py → block_features.parquet
    train_baseline.py → isoforest.pkl

Why this matters
----------------
build_features.py computes template_entropy and unique_templates per block.
For those features to be meaningful, similar log lines must get the SAME
template_id. The original version replaced only digits, giving nearly every
line a unique template — destroying all pattern signal.

This rewrite uses a proper log normalization approach:
  1. Strip timestamps and hostnames (they change every line)
  2. Normalize dynamic tokens: IPs, paths, hex strings, UUIDs, numbers
  3. Normalize Windows Event IDs to stable category strings
  4. Hash the normalized template to a stable integer ID
  5. Output structured events compatible with build_features.py

Also handles both sources:
  - data/staging/events.jsonl   (live from log_collector.py)
  - data/raw/hdfs/sample.log    (HDFS benchmark dataset)

Usage
-----
    python src/parse/template_miner.py
    python src/parse/template_miner.py --input data/staging/events.jsonl
    python src/parse/template_miner.py --input data/raw/hdfs/sample.log --hdfs
"""

import argparse
import json
import logging
import re
from datetime import datetime
from pathlib import Path

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── Defaults ───────────────────────────────────────────────────────────────────
DEFAULT_INPUT  = "data/staging/events.jsonl"
DEFAULT_OUTPUT = "data/parsed/events_parsed.jsonl"

# ── Normalization patterns (order matters — most specific first) ───────────────
# Each tuple: (compiled_regex, replacement_string)
NORMALIZE_PATTERNS = [
    # Timestamps ISO / syslog / Windows
    (re.compile(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
        "<TIMESTAMP>"),
    (re.compile(
        r"\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
        "<TIMESTAMP>"),
    # UUIDs
    (re.compile(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
        "<UUID>"),
    # IPv4 addresses (with optional port)
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{2,5})?\b"),
        "<IP>"),
    # IPv6 addresses
    (re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
        "<IPV6>"),
    # MAC addresses
    (re.compile(r"\b(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}\b"),
        "<MAC>"),
    # Windows registry / file paths
    (re.compile(r"[A-Za-z]:\\(?:[^\s\\/:*?\"<>|]+\\)*[^\s\\/:*?\"<>|]*"),
        "<PATH>"),
    # Unix file paths
    (re.compile(r"(?<!\w)/(?:[^\s/]+/)*[^\s/]+"),
        "<PATH>"),
    # Hex strings (0x... or standalone long hex)
    (re.compile(r"\b0x[0-9a-fA-F]+\b"),
        "<HEX>"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"),
        "<HEX>"),
    # URLs
    (re.compile(r"https?://\S+"),
        "<URL>"),
    # Email addresses
    (re.compile(r"\b[\w.+-]+@[\w.-]+\.\w{2,}\b"),
        "<EMAIL>"),
    # Windows SIDs
    (re.compile(r"\bS-\d-\d-\d{2,}-\d+-\d+-\d+\b"),
        "<SID>"),
    # Port numbers standalone  e.g. "port 8080"
    (re.compile(r"\bport\s+\d{2,5}\b", re.IGNORECASE),
        "port <PORT>"),
    # Standalone numbers (last — after everything else is replaced)
    (re.compile(r"\b\d+\b"),
        "<NUM>"),
    # Collapse multiple spaces
    (re.compile(r"\s{2,}"),
        " "),
]

# ── Windows Event ID → stable category string ─────────────────────────────────
# Gives a human-readable, stable template for Windows Security events
WINDOWS_EVENT_TEMPLATES = {
    4624 : "successful_logon",
    4625 : "failed_logon",
    4634 : "logoff",
    4648 : "explicit_credential_logon",
    4656 : "object_handle_request",
    4657 : "registry_value_modified",
    4663 : "object_access_attempt",
    4672 : "special_privilege_logon",
    4688 : "process_created",
    4698 : "scheduled_task_created",
    4702 : "scheduled_task_updated",
    4719 : "audit_policy_changed",
    4720 : "user_account_created",
    4722 : "user_account_enabled",
    4723 : "password_change_attempt",
    4724 : "password_reset",
    4725 : "user_account_disabled",
    4728 : "member_added_global_group",
    4732 : "member_added_local_group",
    4740 : "account_locked_out",
    4756 : "member_added_universal_group",
    4768 : "kerberos_tgt_request",
    4769 : "kerberos_service_request",
    4771 : "kerberos_preauth_failed",
    4776 : "credential_validation",
    4798 : "user_local_group_enumerated",
    4799 : "local_group_membership_enumerated",
    1102 : "audit_log_cleared",
    7034 : "service_crashed",
    7035 : "service_control_request",
    7045 : "new_service_installed",
}

# ── HDFS block ID extraction ───────────────────────────────────────────────────
_HDFS_BLOCK_RE = re.compile(r"(blk_[-\d]+)")


# ══════════════════════════════════════════════════════════════════════════════
# CORE NORMALIZATION
# ══════════════════════════════════════════════════════════════════════════════

def _strip_syslog_header(raw: str) -> str:
    """
    Remove syslog-style prefix: timestamp + hostname + process.
    Example: 'Mar 15 12:34:56 myhost sshd[1234]: ...' → 'sshd[<NUM>]: ...'
    """
    # Pattern: optional timestamp + optional hostname + rest
    m = re.match(
        r"^(?:\S+\s+\d+\s+\d+:\d+:\d+\s+)?(?:\S+\s+)?(.+)$",
        raw.strip(),
    )
    return m.group(1) if m else raw


def _extract_windows_event_id(raw: str) -> int | None:
    """Extract EventID from a Windows log line if present."""
    m = re.search(r"EventID=(\d+)", raw)
    if m:
        return int(m.group(1))
    return None


def normalize(raw: str) -> str:
    """
    Convert a raw log line into a stable, normalized template string.
    Dynamic values (IPs, timestamps, paths, numbers) are replaced with
    semantic tokens so that similar log lines produce identical templates.
    """
    # Windows Event Log: use the Event ID category as the template
    event_id = _extract_windows_event_id(raw)
    if event_id is not None:
        category = WINDOWS_EVENT_TEMPLATES.get(event_id, f"windows_event_{event_id}")
        # Keep the channel if present (Security / System / Application)
        channel_m = re.search(r"\[(Security|System|Application)\]", raw)
        channel   = channel_m.group(1) if channel_m else "Windows"
        return f"{channel} {category}"

    # Syslog / Linux: strip the dynamic header first
    text = _strip_syslog_header(raw)

    # Apply normalization patterns in order
    for pattern, replacement in NORMALIZE_PATTERNS:
        text = pattern.sub(replacement, text)

    return text.strip()


def template_id(template: str) -> int:
    """
    Produce a stable non-negative integer ID from a template string.
    Uses Python's built-in hash with a fixed seed (via hashlib) so IDs
    are consistent across runs — unlike Python's randomised hash().
    """
    import hashlib
    h = hashlib.md5(template.encode("utf-8"), usedforsecurity=False).hexdigest()
    return int(h[:8], 16) % 100_000   # 0 – 99999


# ══════════════════════════════════════════════════════════════════════════════
# INPUT PARSERS
# ══════════════════════════════════════════════════════════════════════════════

def _parse_jsonl_line(line: str, lineno: int) -> dict | None:
    """
    Parse one line from events.jsonl (output of log_collector.py).
    Expected fields: raw, block_id (optional: source, os, template_id, line_id)
    """
    try:
        event = json.loads(line)
    except json.JSONDecodeError as exc:
        logger.warning("Skipping malformed JSON at line %d: %s", lineno, exc)
        return None

    if "raw" not in event:
        logger.warning("Line %d missing 'raw' field — skipping.", lineno)
        return None

    return event


def _parse_hdfs_line(line: str, lineno: int) -> dict | None:
    """
    Parse one line from the HDFS benchmark log (data/raw/hdfs/sample.log).
    Format: <date> <time> <pid> <level> <component>: <message>
    Example: 081109 203518 143 INFO dfs.DataNode$DataXceiver: ...
    """
    line = line.strip()
    if not line:
        return None

    # Extract block_id from the message content
    block_ids = _HDFS_BLOCK_RE.findall(line)
    block_id  = block_ids[0] if block_ids else f"hdfs_line_{lineno}"

    return {
        "raw"       : line,
        "block_id"  : block_id,
        "source"    : "hdfs",
        "os"        : "linux",
        "line_id"   : lineno,
    }


# ══════════════════════════════════════════════════════════════════════════════
# MAIN PARSE PIPELINE
# ══════════════════════════════════════════════════════════════════════════════

def parse(
    input_file  : str  = DEFAULT_INPUT,
    output_file : str  = DEFAULT_OUTPUT,
    hdfs_mode   : bool = False,
    append      : bool = False,
) -> int:
    """
    Parse raw log events into structured, normalized events.

    Parameters
    ----------
    input_file  : path to events.jsonl (or HDFS log in hdfs_mode)
    output_file : path to write events_parsed.jsonl
    hdfs_mode   : True when parsing the raw HDFS benchmark log file
    append      : True to append to existing output (for incremental parsing)

    Returns
    -------
    Number of events written.
    """
    in_path  = Path(input_file)
    out_path = Path(output_file)

    if not in_path.exists():
        raise FileNotFoundError(
            f"Input file not found: {in_path.resolve()}\n"
            "Run log_collector.py first or provide the correct path."
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"

    written   = 0
    skipped   = 0
    templates_seen: dict[int, str] = {}   # tid → template string (for summary)

    logger.info("Parsing: %s → %s  (mode=%s, hdfs=%s)", in_path, out_path, mode, hdfs_mode)

    with in_path.open(encoding="utf-8", errors="replace") as infile, \
         out_path.open(mode, encoding="utf-8") as outfile:

        for lineno, raw_line in enumerate(infile, 1):
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            # Parse the input line into a base event dict
            if hdfs_mode:
                event = _parse_hdfs_line(raw_line, lineno)
            else:
                event = _parse_jsonl_line(raw_line, lineno)

            if event is None:
                skipped += 1
                continue

            raw = event["raw"]

            # Normalize and generate stable template ID
            tmpl    = normalize(raw)
            tid     = template_id(tmpl)

            templates_seen[tid] = tmpl

            out_event = {
                "template_id"  : tid,
                "template"     : tmpl,
                "raw"          : raw,
                "block_id"     : event.get("block_id", f"unknown_{lineno}"),
                "source"       : event.get("source", "unknown"),
                "os"           : event.get("os", "unknown"),
                "line_id"      : event.get("line_id", lineno),
                "collected_at" : event.get("collected_at",
                                    datetime.now().isoformat(timespec="seconds")),
            }
            outfile.write(json.dumps(out_event) + "\n")
            written += 1

    logger.info(
        "Done: %d events written, %d skipped, %d unique templates discovered.",
        written, skipped, len(templates_seen),
    )

    # Save a template catalog alongside the output (useful for dashboard /templates)
    _save_template_catalog(templates_seen, out_path.parent / "template_catalog.json")

    return written


def _save_template_catalog(templates: dict[int, str], catalog_path: Path) -> None:
    """
    Save a JSON catalog of {template_id: template_string} for inspection
    and for the /templates endpoint to serve to the frontend.
    """
    catalog = {str(k): v for k, v in sorted(templates.items())}
    with open(catalog_path, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2)
    logger.info("Template catalog saved → %s  (%d templates)", catalog_path, len(catalog))


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Log template miner and event parser"
    )
    parser.add_argument("--input",   default=DEFAULT_INPUT,
                        help="Input file: events.jsonl or raw HDFS log")
    parser.add_argument("--output",  default=DEFAULT_OUTPUT,
                        help="Output file: events_parsed.jsonl")
    parser.add_argument("--hdfs",    action="store_true",
                        help="Parse raw HDFS log format instead of events.jsonl")
    parser.add_argument("--append",  action="store_true",
                        help="Append to existing output instead of overwriting")
    args = parser.parse_args()

    try:
        n = parse(
            input_file  = args.input,
            output_file = args.output,
            hdfs_mode   = args.hdfs,
            append      = args.append,
        )
        logger.info("Pipeline ready: %d events in %s", n, args.output)
    except FileNotFoundError as exc:
        logger.error("%s", exc)


if __name__ == "__main__":
    main()
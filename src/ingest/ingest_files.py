"""
ingest_files.py — Log Sentinel AI
=====================================
Batch ingestion of existing log files into the pipeline.

Complements log_collector.py (which handles live OS logs) by allowing
existing log files to be fed into the same pipeline:

    ingest_files.py → data/staging/events.jsonl
    template_miner.py → data/parsed/events_parsed.jsonl
    build_features.py → data/features/block_features.parquet
    train_baseline.py → models/isoforest.pkl

Supported input formats (auto-detected):
    - HDFS log files       (.log)
    - Linux syslog files   (/var/log/*)
    - Windows Event exports (.evtx exported as .txt or .csv)
    - Generic text logs    (any .log or .txt file)
    - Compressed logs      (.gz)

Aligns with the report:
    - Section 1.7 Methodology: "Gather sample logs from various systems"
    - Section 3.1.1: OS log monitoring including file-based ingestion
    - Section 4.2: Implementation steps — log collection module

Place this file at:
    src/ingest/ingest_files.py

Usage
-----
    # Ingest a single file
    python src/ingest/ingest_files.py --input data/raw/hdfs/HDFS_sample.log

    # Ingest all .log files in a directory
    python src/ingest/ingest_files.py --input data/raw/ --recursive

    # Ingest and immediately run the full pipeline
    python src/ingest/ingest_files.py --input data/raw/hdfs/HDFS_sample.log --pipeline

    # Append to existing events.jsonl instead of overwriting
    python src/ingest/ingest_files.py --input data/raw/ --append
"""

import argparse
import csv
import gzip
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
DEFAULT_OUTPUT  = "data/staging/events.jsonl"
SUPPORTED_EXTS  = {".log", ".txt", ".csv", ".gz"}

# ── Block ID extraction patterns ───────────────────────────────────────────────
_HDFS_BLOCK_RE    = re.compile(r"blk_-?\d+")
_PID_RE           = re.compile(r"(\w+)\[(\d+)\]")
_WINLOG_RECORD_RE = re.compile(r"RecordNumber[=:\s]+(\d+)", re.IGNORECASE)


# ══════════════════════════════════════════════════════════════════════════════
# FORMAT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

def detect_format(path: Path) -> str:
    """
    Auto-detect the log format from the file name and first few lines.

    Returns one of:
        'hdfs'     — HDFS distributed filesystem logs
        'syslog'   — Linux syslog / auth.log / kern.log
        'winlog'   — Windows Event Log text/CSV export
        'generic'  — any other plain text log
    """
    name = path.name.lower()

    # Name-based hints
    if "hdfs" in name or "hadoop" in name:
        return "hdfs"
    if any(k in name for k in ("syslog", "auth", "kern", "messages", "secure")):
        return "syslog"
    if any(k in name for k in ("security", "system", "application", "winevt", "winlog")):
        return "winlog"

    # Content-based detection (peek at first 5 lines)
    try:
        opener = gzip.open if name.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as f:
            sample = [f.readline() for _ in range(5)]
        sample_text = " ".join(sample).lower()

        if "blk_" in sample_text or "namenode" in sample_text or "datanode" in sample_text:
            return "hdfs"
        if re.search(r"\b(sshd|sudo|su|pam|kernel)\b", sample_text):
            return "syslog"
        if "eventid" in sample_text or "logname" in sample_text:
            return "winlog"
    except Exception:
        pass

    return "generic"


# ══════════════════════════════════════════════════════════════════════════════
# BLOCK ID EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════

def _block_id_hdfs(line: str, lineno: int) -> str:
    """Extract HDFS block ID from a log line."""
    m = _HDFS_BLOCK_RE.search(line)
    return m.group(0) if m else f"hdfs_line_{lineno}"


def _block_id_syslog(line: str, lineno: int) -> str:
    """Group syslog lines by process name + PID."""
    m = _PID_RE.search(line)
    if m:
        return f"{m.group(1)}_{m.group(2)}"
    # Fallback: group by minute
    minute = datetime.now().strftime("%Y%m%d_%H%M")
    return f"syslog_{minute}"


def _block_id_winlog(line: str, lineno: int) -> str:
    """Extract Windows Event Log record number as block ID."""
    m = _WINLOG_RECORD_RE.search(line)
    if m:
        # Group by minute + event category for multi-event blocks
        minute = datetime.now().strftime("%Y%m%d_%H%M")
        return f"win_{m.group(1)}_{minute}"
    return f"win_line_{lineno}"


def _block_id_generic(line: str, lineno: int) -> str:
    """Generic block ID — group by minute window."""
    minute = datetime.now().strftime("%Y%m%d_%H%M")
    return f"generic_{minute}"


_BLOCK_ID_FN = {
    "hdfs"   : _block_id_hdfs,
    "syslog" : _block_id_syslog,
    "winlog" : _block_id_winlog,
    "generic": _block_id_generic,
}


# ══════════════════════════════════════════════════════════════════════════════
# FILE READERS
# ══════════════════════════════════════════════════════════════════════════════

def _open_file(path: Path):
    """Open a plain or gzip-compressed text file."""
    if path.suffix == ".gz" or path.name.endswith(".log.gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def _read_csv_winlog(path: Path):
    """
    Read a Windows Event Log exported as CSV.
    Expected columns: LevelDisplayName, TimeCreated, Id, Message (or similar).
    Yields raw string lines reconstructed from CSV rows.
    """
    with open(path, encoding="utf-8-sig", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Reconstruct a log-line-like string from CSV columns
            time    = row.get("TimeCreated", row.get("Date and Time", ""))
            level   = row.get("LevelDisplayName", row.get("Level", ""))
            evtid   = row.get("Id", row.get("Event ID", ""))
            message = row.get("Message", row.get("Description", ""))
            yield (
                f"{time} [{level}] EventID={evtid} "
                f"{message.replace(chr(10), ' ').replace(chr(13), ' ')}"
            )


def read_lines(path: Path, fmt: str):
    """
    Yield (lineno, raw_line) tuples from a log file.
    Handles plain text, gzip, and CSV formats.
    """
    if path.suffix == ".csv" and fmt == "winlog":
        for lineno, line in enumerate(_read_csv_winlog(path), 1):
            yield lineno, line
        return

    with _open_file(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.rstrip("\n\r")
            if line.strip():
                yield lineno, line


# ══════════════════════════════════════════════════════════════════════════════
# SINGLE FILE INGESTION
# ══════════════════════════════════════════════════════════════════════════════

def ingest_file(
    input_path  : Path,
    output_file : str  = DEFAULT_OUTPUT,
    fmt         : str  = "auto",
    append      : bool = False,
) -> int:
    """
    Ingest a single log file into events.jsonl.

    Parameters
    ----------
    input_path  : path to the log file
    output_file : path to write/append events.jsonl
    fmt         : log format ('auto', 'hdfs', 'syslog', 'winlog', 'generic')
    append      : append to existing output instead of overwriting

    Returns
    -------
    Number of events written.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path.resolve()}")

    # Detect format
    if fmt == "auto":
        fmt = detect_format(input_path)
        logger.info("Auto-detected format: %s → %s", input_path.name, fmt)

    block_id_fn = _BLOCK_ID_FN.get(fmt, _block_id_generic)
    out_path    = Path(output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    mode        = "a" if append else "w"

    written  = 0
    skipped  = 0

    logger.info(
        "Ingesting: %s  (format=%s, mode=%s)",
        input_path.name, fmt, mode,
    )

    with open(out_path, mode, encoding="utf-8") as outfile:
        for lineno, raw in read_lines(input_path, fmt):
            raw = raw.strip()
            if not raw:
                skipped += 1
                continue

            event = {
                "raw"          : raw,
                "block_id"     : block_id_fn(raw, lineno),
                "source"       : input_path.stem,
                "os"           : _infer_os(fmt),
                "format"       : fmt,
                "line_id"      : lineno,
                "collected_at" : datetime.now().isoformat(timespec="seconds"),
            }
            outfile.write(json.dumps(event) + "\n")
            written += 1

    logger.info(
        "Done: %d events written, %d skipped  →  %s",
        written, skipped, out_path,
    )
    return written


def _infer_os(fmt: str) -> str:
    """Infer the OS from the log format."""
    if fmt == "winlog":
        return "windows"
    if fmt in ("syslog", "hdfs"):
        return "linux"
    return "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# DIRECTORY INGESTION
# ══════════════════════════════════════════════════════════════════════════════

def ingest_directory(
    input_dir   : Path,
    output_file : str  = DEFAULT_OUTPUT,
    recursive   : bool = False,
    append      : bool = False,
) -> int:
    """
    Ingest all supported log files in a directory.

    Parameters
    ----------
    input_dir   : directory to scan
    output_file : path to write events.jsonl
    recursive   : also scan subdirectories
    append      : append to existing output

    Returns
    -------
    Total number of events written across all files.
    """
    if not input_dir.is_dir():
        raise NotADirectoryError(f"Not a directory: {input_dir.resolve()}")

    pattern  = "**/*" if recursive else "*"
    files    = [
        p for p in input_dir.glob(pattern)
        if p.is_file() and p.suffix in SUPPORTED_EXTS
    ]

    if not files:
        logger.warning(
            "No supported log files found in %s  "
            "(supported: %s)", input_dir, ", ".join(SUPPORTED_EXTS),
        )
        return 0

    logger.info("Found %d file(s) to ingest in %s", len(files), input_dir)

    total   = 0
    # First file: use the requested mode; subsequent files: always append
    for i, path in enumerate(sorted(files)):
        mode = append or (i > 0)
        try:
            total += ingest_file(path, output_file, fmt="auto", append=mode)
        except Exception as exc:
            logger.error("Failed to ingest %s: %s", path.name, exc)

    logger.info("Directory ingestion complete: %d total events written.", total)
    return total


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE RUNNER (optional --pipeline flag)
# ══════════════════════════════════════════════════════════════════════════════

def run_pipeline(output_file: str) -> None:
    """
    After ingestion, automatically run the full pipeline:
        template_miner → build_features → train_baseline
    Requires all modules to be importable from src/.
    """
    import sys
    from pathlib import Path as _Path

    project_root = _Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(project_root / "src"))

    logger.info("=" * 60)
    logger.info("Running full pipeline after ingestion...")
    logger.info("=" * 60)

    try:
        from parse.template_miner import parse
        logger.info("Step 1/3 — Parsing templates...")
        parse(input_file=output_file)
    except Exception as exc:
        logger.error("template_miner failed: %s", exc)
        return

    try:
        from features.build_features import build_block_features, build_event_features
        logger.info("Step 2/3 — Building features...")
        build_block_features()
        build_event_features()
    except Exception as exc:
        logger.error("build_features failed: %s", exc)
        return

    try:
        from models.train_baseline import train
        logger.info("Step 3/3 — Training model...")
        train()
    except Exception as exc:
        logger.error("train_baseline failed: %s", exc)
        return

    logger.info("=" * 60)
    logger.info("Pipeline complete. Model is ready.")
    logger.info("=" * 60)


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Log Sentinel AI — Batch log file ingestion"
    )
    parser.add_argument(
        "--input", "-i", required=True,
        help="Path to a log file or directory containing log files",
    )
    parser.add_argument(
        "--output", "-o", default=DEFAULT_OUTPUT,
        help=f"Output events.jsonl path (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--format", "-f", default="auto",
        choices=["auto", "hdfs", "syslog", "winlog", "generic"],
        help="Log format (default: auto-detect)",
    )
    parser.add_argument(
        "--recursive", "-r", action="store_true",
        help="Recursively scan subdirectories (directory mode only)",
    )
    parser.add_argument(
        "--append", "-a", action="store_true",
        help="Append to existing output instead of overwriting",
    )
    parser.add_argument(
        "--pipeline", "-p", action="store_true",
        help="After ingestion, automatically run template_miner → "
             "build_features → train_baseline",
    )
    args = parser.parse_args()

    input_path = Path(args.input)

    try:
        if input_path.is_dir():
            total = ingest_directory(
                input_dir   = input_path,
                output_file = args.output,
                recursive   = args.recursive,
                append      = args.append,
            )
        else:
            total = ingest_file(
                input_path  = input_path,
                output_file = args.output,
                fmt         = args.format,
                append      = args.append,
            )
    except (FileNotFoundError, NotADirectoryError) as exc:
        logger.error("%s", exc)
        return

    logger.info("Ingestion complete: %d events written to %s", total, args.output)

    if args.pipeline and total > 0:
        run_pipeline(args.output)
    elif args.pipeline and total == 0:
        logger.warning("No events ingested — skipping pipeline run.")


if __name__ == "__main__":
    main()
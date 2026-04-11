"""
build_windows_features.py — Log Sentinel AI
==============================================
Extracts block-level features from Windows log events stored in
data/staging/events.jsonl and saves them to
data/features/windows_block_features.parquet for use by train_baseline.py.

Reuses extract_realtime_features() from log_collector.py so the feature
schema is identical to what the live scorer uses — no train/serve skew.

Usage
-----
    python src/ingest/build_windows_features.py
    python src/ingest/build_windows_features.py --min-events 3
"""

import json
import logging
import argparse
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
EVENTS_FILE  = PROJECT_ROOT / "data" / "staging" / "events.jsonl"
OUTPUT_FILE  = PROJECT_ROOT / "data" / "features" / "windows_block_features.parquet"


def load_windows_events(events_file: Path) -> list[dict]:
    """Read events.jsonl and return only Windows events."""
    events = []
    skipped = 0
    with events_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if e.get("os") == "windows" or e.get("format") == "winlog":
                events.append(e)
    logger.info("Loaded %d Windows events (%d lines skipped)", len(events), skipped)
    return events


def build(
    events_file: Path = EVENTS_FILE,
    output_file: Path = OUTPUT_FILE,
    min_events: int   = 3,
):
    import sys
    sys.path.insert(0, str(PROJECT_ROOT / "src"))
    from ingest.log_collector import extract_realtime_features

    events = load_windows_events(Path(events_file))
    if not events:
        raise ValueError(
            "No Windows events found in events.jsonl.\n"
            "Start the collector (START button) and wait for events to arrive."
        )

    df = extract_realtime_features(events, min_events_per_block=min_events)
    if df.empty:
        raise ValueError(
            f"No valid blocks found (all blocks had < {min_events} events).\n"
            "Collect more data or lower --min-events."
        )

    # Drop priority_hits — it's a Windows-only metadata column, not a model feature
    df = df.drop(columns=["priority_hits"], errors="ignore")

    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_file, index=False)
    logger.info(
        "Windows block features saved → %s  (%d blocks × %d features)",
        output_file, len(df), len(df.columns) - 1,  # -1 for block_id
    )
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Build Windows block features from events.jsonl"
    )
    parser.add_argument("--events",     default=str(EVENTS_FILE),
                        help="Path to events.jsonl")
    parser.add_argument("--output",     default=str(OUTPUT_FILE),
                        help="Output parquet path")
    parser.add_argument("--min-events", type=int, default=3,
                        help="Min events per block (default: 3)")
    args = parser.parse_args()
    build(Path(args.events), Path(args.output), args.min_events)

"""
test_threat.py — Log Sentinel AI
==================================
Injects fake threat events directly through the collector's scoring
pipeline and writes alerts to alerts.jsonl.

No Windows admin rights needed — bypasses the Event Log entirely.

Usage:
    python test_threat.py                  # default: brute_force
    python test_threat.py --scenario all
    python test_threat.py --scenario privilege_esc
    python test_threat.py --scenario brute_force
    python test_threat.py --scenario network
    python test_threat.py --scenario dos
    python test_threat.py --scenario log_tamper
"""

import sys
import json
import random
import argparse
from pathlib import Path
from datetime import datetime

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

ALERTS_FILE = PROJECT_ROOT / "data" / "staging" / "alerts.jsonl"
EVENTS_FILE = PROJECT_ROOT / "data" / "staging" / "events.jsonl"
MODEL_FILE  = PROJECT_ROOT / "models" / "isoforest.pkl"
META_FILE   = PROJECT_ROOT / "models" / "feature_meta.json"


def _ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _port():
    return random.randint(1024, 65535)

def _rid():
    return random.randint(1000, 9999)


SCENARIOS = {
    "brute_force": {
        "template_id": "EVT_brute",
        "priority_threat": "brute_force",
        "messages": lambda: [
            f"[Application] EventID=4625 Authentication failure for user admin from {_ip()}",
            f"[Application] EventID=4625 Failed login attempt invalid credentials for user root from {_ip()}",
            f"[Application] EventID=4625 Login failed wrong password for user administrator [{_rid()}]",
            f"[Application] EventID=4625 Authentication failure bad credentials for user admin from {_ip()}",
            f"[Application] EventID=4625 Failed login attempt for user guest from {_ip()}",
            f"[Application] EventID=4625 Invalid user login authentication failure detected [{_rid()}]",
            f"[Application] EventID=4625 Login failed invalid password attempt {_rid()} from {_ip()}",
            f"[Application] EventID=4625 Bad credentials authentication failure user admin [{_rid()}]",
        ],
    },
    "privilege_esc": {
        "template_id": "EVT_priv",
        "priority_threat": "privilege_esc",
        "messages": lambda: [
            f"[Security] EventID=4720 Privilege escalation attempt detected for process cmd.exe [{_rid()}]",
            f"[Security] EventID=4728 Unauthorized access elevated privilege requested from {_ip()}",
            f"[Security] EventID=4732 Admin rights escalation attempt permission denied [{_rid()}]",
            f"[Security] EventID=4720 Privilege escalation sudo equivalent command executed [{_rid()}]",
            f"[Security] EventID=4728 Unauthorized admin access attempt from {_ip()}",
            f"[Security] EventID=4732 Root access attempt permission denied for user [{_rid()}]",
            f"[Security] EventID=4720 Elevated privilege request unauthorized from {_ip()}",
        ],
    },
    "network": {
        "template_id": "EVT_net",
        "priority_threat": "",
        "messages": lambda: [
            f"[Application] EventID=5152 Port scan detected from remote host {_ip()} on port {_port()}",
            f"[Application] EventID=5152 Firewall rule triggered intrusion attempt blocked from {_ip()}",
            f"[Application] EventID=5152 SSH connection attempt from unknown host {_ip()}",
            f"[Application] EventID=5152 Network intrusion detected connection attempt on port {_port()}",
            f"[Application] EventID=5152 Remote access attempt blocked by firewall from {_ip()}",
            f"[Application] EventID=5152 Port scan sweep detected from {_ip()} targeting port {_port()}",
            f"[Application] EventID=5152 Firewall blocked intrusion from remote host {_ip()}",
        ],
    },
    "dos": {
        "template_id": "EVT_dos",
        "priority_threat": "",
        "messages": lambda: [
            f"[Application] EventID=7031 Flood attack detected too many requests from {_ip()}",
            f"[Application] EventID=7031 Rate limit exceeded connection refused [{_rid()}]",
            f"[Application] EventID=7031 DoS detected system overload from {_ip()}",
            f"[Application] EventID=7031 Too many requests rate limit triggered [{_rid()}]",
            f"[Application] EventID=7031 Connection flood detected from {_ip()} on port {_port()}",
            f"[Application] EventID=7031 Service overload timeout from {_ip()} [{_rid()}]",
        ],
    },
    "log_tamper": {
        "template_id": "EVT_tamper",
        "priority_threat": "log_tamper",
        "messages": lambda: [
            f"[Security] EventID=1102 Security log cleared by unknown process [{_rid()}]",
            f"[Security] EventID=4719 Log file modified possible tamper detected [{_rid()}]",
            f"[Security] EventID=1102 Audit log truncated unexpectedly [{_rid()}]",
            f"[Security] EventID=4719 Log rotation triggered outside scheduled window [{_rid()}]",
            f"[Security] EventID=1102 Event log deleted forensic evidence may be lost [{_rid()}]",
            f"[Security] EventID=4719 Log file cleared by process at {_ip()} [{_rid()}]",
        ],
    },
}


def run_scenario(name: str):
    from ingest.log_collector import (
        extract_realtime_features, score_events,
        load_model_and_meta, emit_alert,
        ANOMALY_SCORE_THRESHOLD,
    )

    scenario = SCENARIOS[name]
    messages = scenario["messages"]()
    now      = datetime.now()
    minute   = now.strftime("%Y%m%d_%H%M")
    block_id = f"test_{name}_{minute}_{_rid()}"

    # Build fake events in the same format the collector produces
    events = [
        {
            "raw"           : msg,
            "block_id"      : block_id,
            "template_id"   : scenario["template_id"],
            "source"        : "TestSimulation",
            "os"            : "windows",
            "collected_at"  : now.isoformat(timespec="seconds"),
            "event_id"      : 9999,
            "priority_threat": scenario["priority_threat"],
        }
        for msg in messages
    ]

    print(f"\n[{name.upper()}] Injecting {len(events)} fake events -> block: {block_id}")

    # Save to events.jsonl so the dashboard Raw Events tab shows them
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(EVENTS_FILE, "a") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    # Run through the real scoring pipeline
    model, feature_cols = load_model_and_meta(MODEL_FILE, META_FILE)
    df = extract_realtime_features(events, min_events_per_block=1)

    if df.empty:
        print("  No features extracted — skipped.")
        return

    df = score_events(df, model, feature_cols, threshold=ANOMALY_SCORE_THRESHOLD)
    anomalies = df[df["is_anomaly"] == True]

    print(f"  Scored {len(df)} block(s). Anomalies found: {len(anomalies)}")

    for _, row in df.iterrows():
        score = round(float(row["anomaly_score"]), 4)
        is_anom = row["is_anomaly"]
        print(f"  Score: {score}  Threshold: {ANOMALY_SCORE_THRESHOLD}  Alert: {'YES ✓' if is_anom else 'NO (below threshold)'}")

        if is_anom:
            emit_alert(row, EVENTS_FILE, ALERTS_FILE)
            print(f"  Alert written to alerts.jsonl")
        else:
            # Force-write alert for testing even if above threshold
            print(f"  Score {score} is above threshold {ANOMALY_SCORE_THRESHOLD} — forcing alert for test...")
            row_copy = row.copy()
            row_copy["anomaly_score"] = ANOMALY_SCORE_THRESHOLD - 0.01
            row_copy["is_anomaly"]    = True
            emit_alert(row_copy, EVENTS_FILE, ALERTS_FILE)
            print(f"  Forced alert written.")


def main():
    parser = argparse.ArgumentParser(description="Inject fake threat events for testing")
    parser.add_argument(
        "--scenario",
        default="brute_force",
        choices=list(SCENARIOS.keys()) + ["all"],
        help="Threat scenario to simulate (default: brute_force)"
    )
    args = parser.parse_args()

    print("=" * 60)
    print("  Log Sentinel AI — Threat Simulation")
    print("  Injecting directly into scoring pipeline")
    print("=" * 60)

    if args.scenario == "all":
        for name in SCENARIOS:
            run_scenario(name)
    else:
        run_scenario(args.scenario)

    print("\nDone! Refresh the dashboard to see new alerts.")


if __name__ == "__main__":
    main()

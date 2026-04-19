"""
api.py — Log Sentinel AI
=====================================
REST API that bridges the backend pipeline to the HTML/CSS/JS frontend.

Built with FastAPI. Exposes everything the dashboard needs:
  - Collector start / stop / status
  - Real-time alert streaming (Server-Sent Events)
  - Alert history + labelling (false positive / confirmed threat)
  - Model evaluation metrics
  - Recent raw log events

Place this file at:
    src/api.py

Run with:
    uvicorn src.api:app --reload --host 0.0.0.0 --port 8000

Install dependencies (add to requirements.txt):
    fastapi
    uvicorn[standard]
    python-multipart

Endpoints
---------
GET  /                        → health check
GET  /status                  → collector running, uptime, OS, alert count
GET  /alerts                  → paginated alert history
GET  /alerts/stream           → Server-Sent Events real-time alert feed
POST /alerts/{block_id}/label → label an alert (false_positive / confirmed)
GET  /metrics                 → model evaluation report
GET  /events                  → recent raw log events
POST /collector/start         → start the log collector background thread
POST /collector/stop          → stop the log collector
GET  /collector/logs          → last N lines from the collector log
"""

import json
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel

# ── Project root (src/api.py → project root is one level up) ──────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ingest.log_collector import start_collector   # noqa: E402

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ── File paths (mirrors log_collector.py defaults) ─────────────────────────────
ALERTS_FILE   = PROJECT_ROOT / "data" / "staging" / "alerts.jsonl"
EVENTS_FILE   = PROJECT_ROOT / "data" / "staging" / "events.jsonl"
METRICS_FILE  = PROJECT_ROOT / "models" / "evaluation_report.json"
LABELS_FILE   = PROJECT_ROOT / "data" / "staging" / "alert_labels.json"
RETRAIN_FILE  = PROJECT_ROOT / "data" / "staging" / "retrain_log.jsonl"
MODEL_FILE    = PROJECT_ROOT / "models" / "isoforest.pkl"
META_FILE     = PROJECT_ROOT / "models" / "feature_meta.json"
FEATURES_FILE         = PROJECT_ROOT / "data" / "features" / "block_features.parquet"
WINDOWS_FEATURES_FILE = PROJECT_ROOT / "data" / "features" / "windows_block_features.parquet"

# ── Collector state ────────────────────────────────────────────────────────────
_collector_thread: threading.Thread | None = None
_collector_stop   = threading.Event()
_collector_start_time: float | None = None

# ── Shared model for inline ingest scoring ─────────────────────────────────────
_ingest_model        = None
_ingest_feature_cols = None

def _get_ingest_model():
    """Lazily load the trained model for scoring agent-submitted events."""
    global _ingest_model, _ingest_feature_cols
    if _ingest_model is None and MODEL_FILE.exists() and META_FILE.exists():
        try:
            from ingest.log_collector import load_model_and_meta
            _ingest_model, _ingest_feature_cols = load_model_and_meta(MODEL_FILE, META_FILE)
            logger.info("Ingest model loaded for inline scoring.")
        except Exception as e:
            logger.warning("Could not load ingest model: %s", e)
    return _ingest_model, _ingest_feature_cols


# ══════════════════════════════════════════════════════════════════════════════
# APP SETUP
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start background services on startup."""
    from notification import start_notifier
    notifier_thread = threading.Thread(
        target  = start_notifier,
        daemon  = True,
        name    = "notifier",
        kwargs  = {"alerts_file": ALERTS_FILE, "poll_interval": 2},
    )
    notifier_thread.start()
    logger.info("Notification service started.")
    yield


app = FastAPI(
    title       = "Log Sentinel AI",
    description = "Real-time log anomaly detection API",
    version     = "1.0.0",
    lifespan    = lifespan,
)

# Allow the HTML/CSS/JS frontend to call the API from any origin
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],   # tighten to specific origin in production
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _read_jsonl(path: Path, limit: int = 500) -> list[dict]:
    """Read the last `limit` lines from a JSONL file. Returns [] if missing."""
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    lines = [l for l in lines if l.strip()]
    parsed = []
    for line in lines[-limit:]:
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return parsed


def _load_labels() -> dict:
    """Load the alert labels dict from disk. Returns {} if missing."""
    if not LABELS_FILE.exists():
        return {}
    try:
        return json.loads(LABELS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_labels(labels: dict) -> None:
    """Persist alert labels to disk."""
    LABELS_FILE.parent.mkdir(parents=True, exist_ok=True)
    LABELS_FILE.write_text(json.dumps(labels, indent=2), encoding="utf-8")


def _alert_count() -> int:
    """Fast count of alerts without loading all into memory."""
    if not ALERTS_FILE.exists():
        return 0
    with open(ALERTS_FILE, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


# ══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS (request / response schemas)
# ══════════════════════════════════════════════════════════════════════════════

class LabelRequest(BaseModel):
    label: str          # "false_positive" | "confirmed" | "investigating"
    note: str = ""      # optional admin note


class CollectorStartRequest(BaseModel):
    interval  : int   = 5
    threshold : float = -0.10
    verbose   : bool  = False
    elevate   : bool  = False


# ══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════════════════

# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "service"   : "Log Sentinel AI",
        "status"    : "running",
        "timestamp" : datetime.now().isoformat(timespec="seconds"),
    }


# ── Rule-based alert emitter (bypasses ML; fires on known threat patterns) ────

# Thresholds: how many keyword hits in a block to fire each priority
_RULE_THRESHOLDS = {
    "brute_force"       : ("HIGH",     3),   # 3+ failed-logon indicators
    "privilege_esc"     : ("HIGH",     1),   # any privilege escalation indicator
    "startup"           : ("HIGH",     1),   # any persistence / scheduled task indicator
    "log_tamper"        : ("CRITICAL", 1),   # any log-clear indicator
    "suspicious_process": ("MEDIUM",   2),   # 2+ suspicious-process indicators
    "dos"               : ("MEDIUM",   5),
    "network"           : ("LOW",      5),
}

def _emit_rule_based_alerts(
    blocks: "dict[str, list[dict]]",
    alerts_out: "Path",
) -> "list[dict]":
    """
    Scan event blocks for threat keyword hits and emit alerts directly
    without going through the ML model.  Runs on every ingest batch.
    """
    from ingest.log_collector import THREAT_KEYWORDS
    emitted: list[dict] = []
    now_str = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for block_id, evts in blocks.items():
        hits: dict[str, int] = {cat: 0 for cat in THREAT_KEYWORDS}
        for e in evts:
            lower = e["raw"].lower()
            for cat, kws in THREAT_KEYWORDS.items():
                if any(kw in lower for kw in kws):
                    hits[cat] += 1

        for cat, (priority, min_hits) in _RULE_THRESHOLDS.items():
            if hits.get(cat, 0) < min_hits:
                continue

            source = evts[0].get("source_machine", "unknown")
            sig = f"{block_id}:{cat}"
            # Simple per-block dedup — don't re-emit same category for same block
            if not hasattr(_emit_rule_based_alerts, "_seen"):
                _emit_rule_based_alerts._seen = set()
            if sig in _emit_rule_based_alerts._seen:
                continue
            _emit_rule_based_alerts._seen.add(sig)

            alert = {
                "alert_at"          : now_str,
                "block_id"          : block_id,
                "source_machine"    : source,
                "anomaly_score"     : 0.0,
                "cvss_score"        : {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}.get(priority, 5.0),
                "num_events"        : len(evts),
                "error_count"       : 0,
                "threat_categories" : [cat],
                "priority"          : priority,
                "rule_based"        : True,
            }
            alerts_out.parent.mkdir(parents=True, exist_ok=True)
            with open(alerts_out, "a") as f:
                f.write(json.dumps(alert) + "\n")

            logger.warning(
                "🚨 RULE ALERT | block=%-38s | cat=%s | hits=%d | priority=%s",
                block_id, cat, hits[cat], priority,
            )
            emitted.append({
                "priority"   : priority,
                "description": f"{priority} threat detected — category: {cat.replace('_', ' ')} ({hits[cat]} indicator(s))",
                "cvss"       : alert["cvss_score"],
                "block_id"   : block_id,
            })

    return emitted


# ── Agent ingestion ───────────────────────────────────────────────────────────

@app.post("/ingest", status_code=201, tags=["Ingest"])
def ingest_logs(logs: list[dict]):
    """
    Receives log batches from agent.py (via server.py proxy).
    Each item must have at least a 'log' field (raw log line)
    and optionally a 'source' field (server name).

    The logs are appended to events.jsonl so log_collector.py
    and the template_miner can process them in the next cycle.
    """
    if not logs:
        return {"status": "ok", "received": 0}

    written = 0
    EVENTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    events_for_scoring: list[dict] = []

    # Import once for EventID → threat-category mapping
    from ingest.log_collector import WINDOWS_HIGH_PRIORITY_IDS as _HP_IDS
    _evtid_re = re.compile(r"EventID=(\d+)")

    with open(EVENTS_FILE, "a", encoding="utf-8") as f:
        for item in logs:
            raw    = item.get("log", "").strip()
            source = item.get("source", "agent")
            if not raw:
                continue

            # Detect high-priority Windows EventIDs in the raw summary line
            priority_threat = None
            m = _evtid_re.search(raw)
            if m:
                try:
                    priority_threat = _HP_IDS.get(int(m.group(1)))
                except ValueError:
                    pass

            event = {
                "raw"           : raw,
                "block_id"      : f"agent_{source}_{datetime.now().strftime('%Y%m%d_%H%M')}",
                "source"        : source,
                "source_machine": source,
                "os"            : "unknown",
                "collected_at"  : datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "template_id"   : "agent_generic",
                "priority_threat": priority_threat,
            }
            f.write(json.dumps(event) + "\n")
            events_for_scoring.append(event)
            written += 1

    # Group events by block for both rule-based and ML scoring
    from collections import defaultdict as _dd
    blocks: dict[str, list[dict]] = _dd(list)
    for e in events_for_scoring:
        blocks[e["block_id"]].append(e)

    # ── Rule-based alerts (always runs, no ML model needed) ───────────────────
    generated_alerts: list[dict] = _emit_rule_based_alerts(blocks, ALERTS_FILE)

    # ── ML-based alerts (additional layer on top of rule-based) ──────────────
    if events_for_scoring:
        try:
            model, feature_cols = _get_ingest_model()
            if model is not None:
                from ingest.log_collector import (
                    extract_realtime_features, score_events,
                    emit_alert, ANOMALY_SCORE_THRESHOLD,
                )
                df_feat = extract_realtime_features(events_for_scoring, min_events_per_block=1)
                if not df_feat.empty:
                    df_scored = score_events(df_feat, model, feature_cols, ANOMALY_SCORE_THRESHOLD)
                    for _, row in df_scored[df_scored["is_anomaly"]].iterrows():
                        alert = emit_alert(row, EVENTS_FILE, ALERTS_FILE)
                        if alert:
                            generated_alerts.append({
                                "priority"   : alert.get("priority", "MEDIUM"),
                                "description": f"{alert.get('priority','MEDIUM')} threat detected — score {alert.get('anomaly_score',0):.4f} | categories: {', '.join(alert.get('threat_categories') or ['unknown'])}",
                                "cvss"       : alert.get("cvss_score"),
                                "block_id"   : alert.get("block_id"),
                            })
        except Exception as _e:
            logger.warning("Ingest scoring error: %s", _e)

    logger.info("Ingested %d log line(s) from agent, %d alert(s) generated.", written, len(generated_alerts))
    return {"status": "ok", "received": written, "alerts": generated_alerts}


# ── System status ─────────────────────────────────────────────────────────────

@app.get("/status", tags=["System"])
def get_status():
    """
    Returns the current system status:
      - whether the log collector is running
      - uptime in seconds
      - total alert count
      - model file presence
    """
    global _collector_thread, _collector_start_time

    running = (
        _collector_thread is not None
        and _collector_thread.is_alive()
    )
    uptime = (
        round(time.time() - _collector_start_time)
        if _collector_start_time and running
        else 0
    )

    import platform
    return {
        "collector_running" : running,
        "uptime_sec"        : uptime,
        "os"                : platform.system(),
        "total_alerts"      : _alert_count(),
        "model_loaded"      : MODEL_FILE.exists(),
        "timestamp"         : datetime.now().isoformat(timespec="seconds"),
    }


# ── Alerts ────────────────────────────────────────────────────────────────────

@app.get("/alerts/machines", tags=["Alerts"])
def get_machines():
    """Return sorted list of unique source_machine values seen in alerts."""
    alerts = _read_jsonl(ALERTS_FILE, limit=2000)
    machines = sorted({a.get("source_machine", "") for a in alerts if a.get("source_machine")})
    return {"machines": machines}


@app.get("/alerts", tags=["Alerts"])
def get_alerts(
    limit    : int   = Query(100, ge=1, le=1000, description="Max alerts to return"),
    priority : str   = Query("all", description="Filter: all | CRITICAL | HIGH | MEDIUM | LOW"),
    threat   : str   = Query("",    description="Filter by threat category e.g. brute_force"),
    labelled : str   = Query("all", description="Filter: all | labelled | unlabelled"),
    machine  : str   = Query("",    description="Filter by source machine hostname"),
):
    """
    Returns paginated alert history with optional filters.
    Labels (false_positive / confirmed) are merged in from alert_labels.json.
    """
    alerts = _read_jsonl(ALERTS_FILE, limit=limit)
    labels = _load_labels()

    # Merge labels into alerts
    for a in alerts:
        bid = a.get("block_id", "")
        if bid in labels:
            a["label"] = labels[bid]["label"]
            a["note"]  = labels[bid].get("note", "")
        else:
            a["label"] = None
            a["note"]  = ""

    # Apply filters
    if priority != "all":
        alerts = [a for a in alerts if a.get("priority") == priority]

    if threat:
        alerts = [
            a for a in alerts
            if threat in a.get("threat_categories", [])
        ]

    if labelled == "labelled":
        alerts = [a for a in alerts if a["label"] is not None]
    elif labelled == "unlabelled":
        alerts = [a for a in alerts if a["label"] is None]

    if machine:
        alerts = [a for a in alerts if a.get("source_machine", "") == machine]

    return {
        "total"  : len(alerts),
        "alerts" : list(reversed(alerts)),   # newest first
    }


@app.post("/alerts/{block_id}/label", tags=["Alerts"])
def label_alert(block_id: str, body: LabelRequest):
    """
    Label an alert as 'false_positive', 'confirmed', or 'investigating'.
    Labels are stored in data/staging/alert_labels.json and merged
    into GET /alerts responses. This feeds the model's adaptive learning loop.
    """
    valid_labels = {"true_positive", "false_positive", "true_negative", "false_negative"}
    if body.label not in valid_labels:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid label '{body.label}'. Must be one of: {valid_labels}",
        )

    labels = _load_labels()
    labels[block_id] = {
        "label"      : body.label,
        "note"       : body.note,
        "labelled_at": datetime.now().isoformat(timespec="seconds"),
    }
    _save_labels(labels)

    logger.info("Alert labelled: block_id=%s label=%s", block_id, body.label)
    return {"block_id": block_id, "label": body.label, "status": "saved"}


# ── Real-time alert stream (Server-Sent Events) ────────────────────────────────

@app.get("/alerts/stream", tags=["Alerts"])
async def stream_alerts():
    """
    Server-Sent Events endpoint. The frontend connects once and receives
    new alerts pushed in real time as they are written to alerts.jsonl.

    JavaScript usage:
        const es = new EventSource('http://localhost:8000/alerts/stream');
        es.onmessage = (e) => {
            const alert = JSON.parse(e.data);
            console.log(alert);
        };
    """
    async def event_generator() -> AsyncGenerator[str, None]:
        # Send a heartbeat immediately so the browser knows the connection is alive
        yield "event: connected\ndata: {\"status\": \"connected\"}\n\n"

        last_size = ALERTS_FILE.stat().st_size if ALERTS_FILE.exists() else 0

        while True:
            await __import__("asyncio").sleep(1)

            if not ALERTS_FILE.exists():
                yield f"event: heartbeat\ndata: {{}}\n\n"
                continue

            current_size = ALERTS_FILE.stat().st_size
            if current_size <= last_size:
                # No new data — send heartbeat to keep connection open
                yield f"event: heartbeat\ndata: {{}}\n\n"
                continue

            # Read only the new bytes
            with open(ALERTS_FILE, "rb") as f:
                f.seek(last_size)
                new_bytes = f.read()
            last_size = current_size

            for line in new_bytes.decode("utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    json.loads(line)       # validate it's proper JSON
                    yield f"data: {line}\n\n"
                except json.JSONDecodeError:
                    continue

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control" : "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )


# ── Model metrics ─────────────────────────────────────────────────────────────

@app.get("/metrics", tags=["Model"])
def get_metrics():
    """
    Returns the evaluation report generated by evaluate.py.
    Used by the frontend dashboard to display accuracy, F1, ROC-AUC etc.
    """
    if not METRICS_FILE.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "Evaluation report not found. "
                "Run evaluate.py first to generate it."
            ),
        )
    try:
        return json.loads(METRICS_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"Corrupt metrics file: {exc}")


# ── Raw events ────────────────────────────────────────────────────────────────

@app.get("/events", tags=["Events"])
def get_events(
    limit  : int = Query(200, ge=1, le=2000),
    source : str = Query("",  description="Filter by source e.g. Security, syslog"),
    machine: str = Query("",  description="Filter by source machine hostname"),
):
    """
    Returns recent raw log events collected by log_collector.py.
    Useful for the 'Live Logs' panel in the dashboard.
    """
    events = _read_jsonl(EVENTS_FILE, limit=limit)

    if source:
        events = [e for e in events if e.get("source") == source]
    if machine:
        events = [e for e in events if e.get("source_machine", "") == machine]

    return {
        "total"  : len(events),
        "events" : list(reversed(events)),   # newest first
    }


# ── Collector control ─────────────────────────────────────────────────────────

@app.post("/collector/start", tags=["Collector"])
def collector_start(body: CollectorStartRequest = CollectorStartRequest()):
    """
    Start the log collector in a background daemon thread.
    If it is already running, returns 200 with a note.
    """
    global _collector_thread, _collector_stop, _collector_start_time

    if _collector_thread is not None and _collector_thread.is_alive():
        return {"status": "already_running", "uptime_sec": round(time.time() - _collector_start_time)}

    # Reset the stop event and clear the alert deduplication cache for a fresh start
    _collector_stop = threading.Event()
    try:
        from ingest.log_collector import _alert_cache
        _alert_cache.clear()
        logger.info("Alert deduplication cache cleared.")
    except Exception:
        pass

    def _run():
        try:
            start_collector(
                model_path   = MODEL_FILE,
                meta_path    = META_FILE,
                alerts_out   = ALERTS_FILE,
                events_out   = EVENTS_FILE,
                interval     = body.interval,
                threshold    = body.threshold,
                verbose      = body.verbose,
                auto_elevate = body.elevate,
                stop_event   = _collector_stop,
            )
        except Exception as exc:
            logger.error("Collector thread crashed: %s", exc, exc_info=True)

    _collector_thread     = threading.Thread(target=_run, daemon=True, name="log-collector")
    _collector_start_time = time.time()
    _collector_thread.start()

    logger.info(
        "Collector started (interval=%ds, threshold=%.2f).",
        body.interval, body.threshold,
    )
    return {
        "status"    : "started",
        "interval"  : body.interval,
        "threshold" : body.threshold,
    }


@app.post("/collector/stop", tags=["Collector"])
def collector_stop():
    """
    Signal the log collector background thread to stop.
    The thread finishes its current cycle then exits cleanly.
    """
    global _collector_thread, _collector_stop, _collector_start_time

    if _collector_thread is None or not _collector_thread.is_alive():
        return {"status": "not_running"}

    _collector_stop.set()
    _collector_thread.join(timeout=15)

    if _collector_thread.is_alive():
        logger.warning("Collector thread did not stop within 15s.")
        return {"status": "stop_requested", "note": "Thread is still shutting down."}

    _collector_thread     = None
    _collector_start_time = None
    logger.info("Collector stopped cleanly.")
    return {"status": "stopped"}


@app.get("/collector/logs", tags=["Collector"])
def collector_logs(lines: int = Query(50, ge=1, le=500)):
    """
    Returns the last N lines from the application log.
    Useful for showing live collector activity in the dashboard.
    """
    log_file = PROJECT_ROOT / "collector.log"
    if not log_file.exists():
        return {"lines": [], "note": "No log file found. Logs appear in the terminal."}

    all_lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
    return {"lines": all_lines[-lines:]}


# ── Retrain state ──────────────────────────────────────────────────────────────
_retrain_thread: threading.Thread | None = None
_retrain_status: dict = {"status": "idle", "started_at": None, "finished_at": None, "error": None}


# ══════════════════════════════════════════════════════════════════════════════
# TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/templates", tags=["Templates"])
def get_templates():
    """
    Returns the threat keyword templates used by the AI analyzer.
    These are the patterns the model uses to detect threats — NOT the same
    as alert labels. Templates are defined in build_features.py / log_collector.py.

    The frontend displays these next to the Update Model / Submit Feedback buttons
    so admins understand what the model is looking for.
    """
    templates = {
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
    return {
        "total_categories" : len(templates),
        "templates"        : templates,
        "label_options"    : ["true_positive", "false_positive", "true_negative", "false_negative"],
        "description"      : (
            "Templates are keyword patterns the AI uses to classify threats. "
            "Labels are admin verdicts on individual alerts used to retrain the model."
        ),
    }


# ══════════════════════════════════════════════════════════════════════════════
# FEEDBACK + MODEL RETRAINING
# ══════════════════════════════════════════════════════════════════════════════

@app.post("/feedback", tags=["Model"])
def submit_feedback(body: LabelRequest, block_id: str = "batch"):
    """
    Submit feedback on one or more alerts.
    This is a convenience alias for labelling — the frontend 'Submit Feedback'
    button calls this endpoint with the currently selected alert's block_id
    passed as a query param:

        POST /feedback?block_id=win_Security_20260328_0130_brute_force

    The label is saved to alert_labels.json and will be used on the next
    model retrain to improve detection accuracy.
    """
    valid_labels = {"true_positive", "false_positive", "true_negative", "false_negative"}
    if body.label not in valid_labels:
        raise HTTPException(
            status_code = 400,
            detail      = f"Invalid label '{body.label}'. Must be one of: {valid_labels}",
        )

    labels = _load_labels()
    labels[block_id] = {
        "label"      : body.label,
        "note"       : body.note,
        "labelled_at": datetime.now().isoformat(timespec="seconds"),
    }
    _save_labels(labels)

    # Log the feedback event for audit trail
    RETRAIN_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(RETRAIN_FILE, "a") as f:
        f.write(json.dumps({
            "event"     : "feedback_submitted",
            "block_id"  : block_id,
            "label"     : body.label,
            "note"      : body.note,
            "timestamp" : datetime.now().isoformat(timespec="seconds"),
        }) + "\n")

    logger.info("Feedback submitted: block_id=%s  label=%s", block_id, body.label)
    return {
        "status"   : "saved",
        "block_id" : block_id,
        "label"    : body.label,
        "message"  : "Feedback saved. Run POST /model/retrain to update the model.",
    }


@app.post("/model/retrain", tags=["Model"])
def retrain_model():
    """
    Trigger a full model retrain in a background thread using the current
    block_features.parquet and the labelled feedback from alert_labels.json.

    The retrain runs asynchronously — the endpoint returns immediately with
    status='started'. Poll GET /model/retrain/status to check progress.

    Flow:
      1. Load block_features.parquet
      2. Load alert_labels.json — inject labels as a 'label' column
      3. Re-run train_baseline.py pipeline (contamination auto-adjusted
         based on confirmed anomaly ratio in labelled data)
      4. Overwrite models/isoforest.pkl and feature_meta.json
      5. Save retrain record to retrain_log.jsonl
    """
    global _retrain_thread, _retrain_status

    if _retrain_thread is not None and _retrain_thread.is_alive():
        return {
            "status"     : "already_running",
            "started_at" : _retrain_status.get("started_at"),
            "message"    : "Retrain already in progress. Poll GET /model/retrain/status.",
        }

    if not FEATURES_FILE.exists():
        raise HTTPException(
            status_code = 404,
            detail      = (
                "block_features.parquet not found. "
                "Run build_features.py first to generate features."
            ),
        )

    def _run_retrain():
        global _retrain_status
        _retrain_status = {
            "status"      : "running",
            "started_at"  : datetime.now().isoformat(timespec="seconds"),
            "finished_at" : None,
            "error"       : None,
        }
        try:
            import pandas as pd
            sys.path.insert(0, str(PROJECT_ROOT / "src"))
            from models.train_baseline import train
            from ingest.build_windows_features import build as build_windows_features

            # Rebuild Windows block features from latest collected events
            try:
                build_windows_features()
                features_path = WINDOWS_FEATURES_FILE
                logger.info("Retrain: using Windows features from events.jsonl")
            except Exception as win_err:
                logger.warning(
                    "Could not build Windows features (%s) — falling back to HDFS features.",
                    win_err,
                )
                features_path = FEATURES_FILE

            # Load features
            df = pd.read_parquet(features_path)

            # Inject labels from feedback if available
            labels = _load_labels()
            if labels:
                label_map = {
                    "true_positive"  : -1,   # confirmed anomaly
                    "false_positive" :  1,   # actually normal
                    "true_negative"  :  1,   # confirmed normal
                    "false_negative" : -1,   # missed anomaly
                }
                df["feedback_label"] = df["block_id"].map(
                    {k: label_map.get(v["label"]) for k, v in labels.items()}
                )
                # Auto-adjust contamination based on confirmed anomaly ratio
                n_labelled  = df["feedback_label"].notna().sum()
                n_anomalies = (df["feedback_label"] == -1).sum()
                contamination = max(0.01, min(0.5, float(n_anomalies / len(df))))
                logger.info(
                    "Retrain: %d labelled samples, %d confirmed anomalies → contamination=%.4f",
                    n_labelled, n_anomalies, contamination,
                )
            else:
                contamination = 0.01
                logger.info("No feedback labels found — using default contamination=0.01")

            # Run training pipeline
            train(
                features_file = str(features_path),
                model_file    = str(MODEL_FILE),
                meta_file     = str(META_FILE),
                contamination = contamination,
            )

            # Log the retrain event
            with open(RETRAIN_FILE, "a") as f:
                f.write(json.dumps({
                    "event"         : "model_retrained",
                    "timestamp"     : datetime.now().isoformat(timespec="seconds"),
                    "contamination" : contamination,
                    "n_labels_used" : len(labels),
                }) + "\n")

            _retrain_status["status"]      = "completed"
            _retrain_status["finished_at"] = datetime.now().isoformat(timespec="seconds")
            logger.info("Model retrain completed successfully.")

        except Exception as exc:
            _retrain_status["status"]      = "failed"
            _retrain_status["error"]       = str(exc)
            _retrain_status["finished_at"] = datetime.now().isoformat(timespec="seconds")
            logger.error("Model retrain failed: %s", exc, exc_info=True)

    _retrain_thread = threading.Thread(target=_run_retrain, daemon=True, name="retrain")
    _retrain_thread.start()

    logger.info("Model retrain started in background thread.")
    return {
        "status"     : "started",
        "started_at" : _retrain_status["started_at"],
        "message"    : "Retraining in background. Poll GET /model/retrain/status for progress.",
    }


@app.get("/model/retrain/status", tags=["Model"])
def retrain_status():
    """
    Poll this endpoint to check whether a retrain triggered by
    POST /model/retrain is still running, completed, or failed.
    """
    return _retrain_status




# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api:app",
        host    = "0.0.0.0",
        port    = 8000,
        # reload=True spawns a reloader process that re-imports the module,
        # causing background threads (notifier, collector) to start multiple
        # times. Disable it in production; use reload only during development
        # by running:  uvicorn src.api:app --reload  from the terminal instead.
        reload  = False,
        workers = 1,    # must be 1 — collector + notifier threads are in-process
    )
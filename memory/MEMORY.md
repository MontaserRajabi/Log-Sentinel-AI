# Log Sentinel AI — Project Memory
> This file is read by Claude Code to understand the full project context.
> Last updated: 2026-03-29

---

## Project Overview
AI-powered intrusion detection system that monitors OS log files, detects anomalies using Isolation Forest, and alerts administrators in real time.

**University:** Palestine Polytechnic University (PPU)  
**Students:** Montaser Rajabi, Ibrahim Al-sharif  
**Supervisor:** Dr. Eng. Mousa Farajalla  
**Submitted:** June 2025  

---

## Architecture

```
Monitored Machine          Frontend Server           ML Backend
─────────────────          ───────────────           ──────────
agent.py              →    frontend/server.py    →   src/api.py
log_collector.py      →    (proxies all calls)   →   AI Model
                                                      alerts.jsonl
```

**Backend runs on:** `http://localhost:8000` (FastAPI)  
**Frontend runs on:** `http://localhost:5000` (Flask)  
**Docker:** `docker compose up --build`

---

## File Structure

```
Log-Sentinel-Ai/
├── src/
│   ├── api.py                    ← FastAPI REST API (main backend entry point)
│   ├── notification.py           ← Alert notifications (desktop + email)
│   ├── features/
│   │   └── build_features.py     ← Feature engineering from parsed events
│   ├── ingest/
│   │   ├── log_collector.py      ← Real-time OS log collection (Windows/Linux)
│   │   └── ingest_files.py       ← Batch ingestion of existing log files
│   ├── models/
│   │   ├── train_baseline.py     ← Train Isolation Forest model
│   │   ├── evaluate.py           ← Evaluate model against HDFS labels
│   │   ├── test_model.py         ← Unit tests (26 tests — all passing)
│   │   └── test.py               ← Integration tests (36 tests — all passing)
│   └── parse/
│       └── template_miner.py     ← Parse raw logs into structured events
├── frontend/
│   ├── server.py                 ← Flask frontend server + proxy to backend
│   ├── agent.py                  ← Log collection agent for remote machines
│   ├── requirements.txt          ← flask, requests, watchdog, python-dotenv
│   ├── admins.txt                ← Hashed admin credentials (SHA-256)
│   ├── templates.txt             ← Admin-defined threat keyword templates
│   ├── models/
│   │   ├── admin_manager.py      ← Admin account CRUD + SHA-256 auth
│   │   └── detector.py           ← Rule-based keyword scorer (fallback)
│   └── templates/
│       ├── login.html            ← Login page (cyberpunk aesthetic)
│       └── dashboard.html        ← Main dashboard (Chart.js + SSE alerts)
├── data/
│   ├── raw/hdfs/
│   │   ├── HDFS_sample.log       ← 400k lines used for training
│   │   └── anomaly_label.csv     ← Ground truth labels (BlockId, Label)
│   ├── staging/
│   │   ├── events.jsonl          ← Raw collected events
│   │   ├── alerts.jsonl          ← Generated alerts (read by dashboard SSE)
│   │   ├── alert_labels.json     ← Admin feedback labels
│   │   ├── collector_cursor.json ← Resume position for log collector
│   │   └── retrain_log.jsonl     ← Model retrain audit log
│   ├── parsed/
│   │   ├── events_parsed.jsonl   ← Normalized events with template IDs
│   │   └── template_catalog.json ← {template_id: template_string} catalog
│   └── features/
│       ├── block_features.parquet ← Block-level features (one row per block)
│       └── event_features.parquet ← Event-level features (one row per event)
├── models/
│   ├── isoforest.pkl             ← Trained Pipeline (StandardScaler + IsolationForest)
│   ├── feature_meta.json         ← List of 22 feature columns used at training
│   ├── training_report.json      ← Training config + evaluation metrics
│   └── evaluation_report.json    ← Full evaluation results
├── docker/
│   ├── Dockerfile.backend        ← Backend Docker image
│   └── Dockerfile.frontend       ← Frontend Docker image
├── docker-compose.yml            ← Full system orchestration
├── .dockerignore                 ← Excludes large files from build context
├── .env                          ← Environment variables (never commit)
└── requirements.txt              ← Backend Python dependencies
```

---

## Pipeline (in order)

```bash
# 1. Collect logs (live OS logs)
python src/ingest/log_collector.py --once

# 2. OR ingest existing log files
python src/ingest/ingest_files.py --input data/raw/hdfs/HDFS_sample.log

# 3. Parse raw logs into structured events
python src/parse/template_miner.py

# 4. Build features
python src/features/build_features.py

# 5. Train model
python src/models/train_baseline.py

# 6. Evaluate
python src/models/evaluate.py

# 7. Run backend API
python src/api.py

# 8. Run frontend (separate terminal)
cd frontend && python server.py
```

---

## API Endpoints (src/api.py — port 8000)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Health check |
| GET | `/status` | Collector status, alert count, uptime |
| GET | `/alerts` | Alert history (paginated, filterable) |
| GET | `/alerts/stream` | SSE real-time alert feed |
| POST | `/alerts/{block_id}/label` | Label alert (true_positive etc.) |
| GET | `/events` | Recent raw log events |
| GET | `/metrics` | Model evaluation report |
| GET | `/templates` | Threat keyword templates |
| POST | `/feedback?block_id=X` | Submit feedback for alert |
| POST | `/model/retrain` | Trigger model retraining |
| GET | `/model/retrain/status` | Poll retraining progress |
| POST | `/collector/start` | Start log collector |
| POST | `/collector/stop` | Stop log collector |
| GET | `/collector/logs` | Last N lines from collector log |
| POST | `/ingest` | Receive logs from agent.py |

---

## Frontend Endpoints (frontend/server.py — port 5000)

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Dashboard (login required) |
| GET/POST | `/login` | Login page |
| GET | `/logout` | Logout |
| GET | `/proxy/*` | Proxy all above API endpoints |
| POST | `/api/logs` | Receive logs from agent.py |
| GET/POST | `/api/templates` | Local template management |
| GET/POST/DELETE | `/api/admins` | Admin account management |

---

## Model Details

- **Algorithm:** Isolation Forest (unsupervised anomaly detection)
- **Pipeline:** StandardScaler → IsolationForest
- **Training data:** HDFS_1.log (400k lines = 31,026 blocks)
- **Features:** 22 numeric features per block
- **Contamination:** 0.01 (1% expected anomaly rate)
- **n_estimators:** 100 trees

### Evaluation Results (400k sample, report Chapter 5)
| Metric | Value |
|--------|-------|
| Accuracy | 96.1% |
| Precision (Anomaly) | 90.6% |
| Recall (Anomaly) | 19.1% |
| F1-Score | 31.5% |
| ROC-AUC | 71.6% |

---

## Feature Columns (22 total — from feature_meta.json)
```
num_events, unique_templates, avg_msg_len, std_msg_len, max_msg_len,
min_msg_len, error_count, warn_count, info_count, error_ratio, warn_ratio,
template_entropy, top_template_ratio, block_duration_sec, events_per_sec,
gap_count, brute_force_hits, privilege_esc_hits, dos_hits, log_tamper_hits,
startup_hits, network_hits
```

---

## Threat Categories (Table 3.1 from report)
```python
THREAT_KEYWORDS = {
    "brute_force"  : ["failed", "invalid", "wrong password", "authentication failure", ...],
    "privilege_esc": ["privilege", "escalation", "sudo", "root", "admin", ...],
    "dos"          : ["flood", "overload", "too many requests", "rate limit", ...],
    "log_tamper"   : ["deleted", "modified", "cleared", "truncated", ...],
    "startup"      : ["startup", "boot", "init", "service start", "autorun", ...],
    "network"      : ["port scan", "ssh", "firewall", "connection attempt", ...],
}
```

---

## Key Design Decisions

### log_collector.py
- **Cursor system:** Saves last read position to `collector_cursor.json` — resumes after restart
- **First run:** Initializes cursor to CURRENT end of log (skips history) — prevents dumping 30k+ events
- **Block grouping:** Windows events grouped by `channel + 1-minute window + threat category` (not per-record)
- **Alert deduplication:** Same alert signature suppressed for 60 seconds (`ALERT_COOLDOWN_SEC`)
- **Default interval:** 30 seconds
- **Anomaly threshold:** -0.10 (decision_function score below this → alert)
- **Min events per block:** 3 (single-event blocks skipped — no feature variance)

### template_miner.py
- Uses `hashlib.md5` for stable template IDs (NOT Python's random `hash()`)
- Normalizes: timestamps, IPs, UUIDs, paths, hex strings, Windows Event IDs
- Windows events mapped to stable category strings (e.g. `Security failed_logon`)

### evaluate.py
- `_reconcile_columns()` handles column name mismatches between train and eval
- Known rename: `block_duration` → `block_duration_sec`
- Model's `n_features_in_` used to validate feature count

### api.py
- `@app.on_event("startup")` starts notifier — prevents triple-start with uvicorn reload
- `reload=False` in `__main__` — reload breaks in-process threads
- Run with: `python src/api.py` (NOT `uvicorn src.api:app --reload`)

### notification.py
- Watches `alerts.jsonl` by file size (tail approach — works on Windows + Linux)
- Cooldown: same block_id suppressed for `COOLDOWN_SEC` seconds
- Email uses SMTP with STARTTLS — credentials from `.env`

---

## .env Keys
```env
# Model training
CONTAMINATION=0.01
RANDOM_STATE=42
N_ESTIMATORS=100
TEST_SIZE=0.2

# Log collector
NOTIFY_MIN_PRIORITY=MEDIUM
NOTIFY_COOLDOWN_SEC=60
NOTIFY_SOUND=true

# Email notifications (optional)
NOTIFY_EMAIL_ENABLED=false
NOTIFY_EMAIL_FROM=
NOTIFY_EMAIL_TO=
NOTIFY_EMAIL_HOST=smtp.gmail.com
NOTIFY_EMAIL_PORT=587
NOTIFY_EMAIL_USER=
NOTIFY_EMAIL_PASS=

# Agent authentication
AGENT_API_KEY=sentinel-secret-key

# Docker / production
SECRET_KEY=sentinel-change-this-in-production
BACKEND_URL=http://localhost:8000
```

---

## Tests
```bash
# Model unit tests (26 tests)
python -m pytest src/models/test_model.py -v

# Pipeline integration tests (36 tests)
python -m pytest src/models/test.py -v

# All tests
python -m pytest src/models/ -v
```
**Result: 62/62 passing**

---

## Known Issues & Fixes Applied

| Issue | Fix |
|-------|-----|
| Windows Security channel needs admin | `_probe_winlog_channel()` skips inaccessible channels gracefully |
| First run dumps entire event log history | Cursor initialized to current end on first run |
| `block_duration` → `block_duration_sec` rename | `_reconcile_columns()` in evaluate.py handles renames |
| Notifier starting 3x with uvicorn reload | Moved to `@app.on_event("startup")`, set `reload=False` |
| Dashboard chart Y axis 0-1 wrong range | Fixed to `-0.2 to 0.4` (actual anomaly score range) |
| Dashboard normalise() wrong field names | Fixed: `anomaly_score`, `alert_at`, `priority`, `threat_categories` |
| triggerRetrain() treats POST as final | Now polls `/model/retrain/status` every 2s |
| openTemplates() expected flat array | Now flattens `{cat: [keywords]}` dict |
| updateStats() wrong metrics path | Fixed to `metrics.metrics?.accuracy` |
| admin_manager.py relative path issue | Fixed with `Path(__file__).resolve().parent.parent` |
| 11M events processed for hours | Use `head -n 400000 HDFS_1.log > HDFS_sample.log` |

---

## Docker
```bash
# Build and run everything
docker compose up --build

# Background mode
docker compose up --build -d

# Logs
docker compose logs -f backend
docker compose logs -f frontend

# Stop
docker compose down
```

**Files:**
- `docker/Dockerfile.backend` — ML backend image
- `docker/Dockerfile.frontend` — Flask frontend image
- `docker-compose.yml` — orchestration (backend:8000, frontend:5000)
- `.dockerignore` — excludes large HDFS files, .venv, .git

**Important:** In Docker, frontend uses `BACKEND_URL=http://backend:8000` (Docker service name, not localhost). `server.py` reads this from `os.environ.get("BACKEND_URL")`.

---

## Default Admin Credentials
- **Username:** `admin`
- **Password:** `admin123`
- Change immediately after first login via the Admins button in the dashboard.

---

## What's Complete
- [x] src/features/build_features.py
- [x] src/models/train_baseline.py
- [x] src/models/evaluate.py
- [x] src/models/test_model.py (26/26 tests passing)
- [x] src/models/test.py (36/36 tests passing)
- [x] src/ingest/log_collector.py
- [x] src/ingest/ingest_files.py
- [x] src/parse/template_miner.py
- [x] src/api.py
- [x] src/notification.py
- [x] frontend/server.py
- [x] frontend/agent.py (no changes needed)
- [x] frontend/models/admin_manager.py
- [x] frontend/models/detector.py
- [x] frontend/templates/login.html (no changes needed)
- [x] frontend/templates/dashboard.html (6 bugs fixed)
- [x] docker/Dockerfile.backend
- [x] docker/Dockerfile.frontend
- [x] docker-compose.yml
- [x] .dockerignore

## What's Remaining
- [ ] Report: Chapter 4 (Implementation) — use code from this session
- [ ] Report: Chapter 5 (Results) — use evaluation numbers above
- [ ] Azure deployment (optional — deploy api.py as Azure Web App)
- [ ] Change default admin password

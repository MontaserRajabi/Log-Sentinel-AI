"""
server.py  —  Log Sentinel AI  |  Frontend Flask Server
Serves the web dashboard and proxies requests to the ML backend.

Run:
    python server.py

Set BACKEND_URL to your teammate's backend IP:port.
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
import requests as req
import os

from models.admin_manager import (
    check_admin, load_admins, add_admin,
    delete_admin, ensure_default_admin
)
from models.detector import load_templates, save_templates

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "sentinel-change-this-in-production")
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ── Point this to your teammate's ML backend ─────────────────────────────────
BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000")
TIMEOUT     = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_backend_url():
    """Return the backend URL for the current user session."""
    return session.get("backend_url", BACKEND_URL).rstrip("/")

def _backend(path: str, method="GET", **kwargs):
    """Forward a request to the ML backend. Returns (data, status_code)."""
    base = _get_backend_url()
    url  = base + path
    try:
        resp = req.request(method, url, timeout=TIMEOUT, **kwargs)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
        return data, resp.status_code
    except req.ConnectionError:
        return {"error": f"Cannot reach backend at {base}"}, 502
    except req.Timeout:
        return {"error": "Backend request timed out"}, 504
    except Exception as e:
        return {"error": str(e)}, 500


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", backend_url=_get_backend_url())


@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = ""
    if request.method == "POST":
        username    = request.form.get("username", "").strip()
        password    = request.form.get("password", "")
        backend_url = request.form.get("backend_url", "").strip() or BACKEND_URL

        # Basic validation — must start with http
        if not backend_url.startswith("http"):
            error = "Backend URL must start with http:// or https://"
        elif check_admin(username, password):
            session["admin"]       = username
            session["backend_url"] = backend_url.rstrip("/")
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error, default_backend=BACKEND_URL)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ---------------------------------------------------------------------------
# Proxy endpoints — forward to teammate's ML backend
# ---------------------------------------------------------------------------

@app.route("/proxy/status")
@login_required
def proxy_status():
    data, code = _backend("/status")
    return jsonify(data), code


@app.route("/proxy/alerts")
@login_required
def proxy_alerts():
    data, code = _backend("/alerts")
    return jsonify(data), code


@app.route("/proxy/events")
@login_required
def proxy_events():
    data, code = _backend("/events")
    return jsonify(data), code


@app.route("/proxy/metrics")
@login_required
def proxy_metrics():
    data, code = _backend("/metrics")
    return jsonify(data), code


@app.route("/proxy/alerts/<block_id>/label", methods=["POST"])
@login_required
def proxy_label(block_id):
    body = request.get_json(silent=True) or {}
    data, code = _backend(f"/alerts/{block_id}/label", method="POST", json=body)
    return jsonify(data), code


@app.route("/proxy/feedback", methods=["POST"])
@login_required
def proxy_feedback():
    """Submit feedback for a specific alert (used by Submit Feedback button)."""
    body     = request.get_json(silent=True) or {}
    block_id = request.args.get("block_id", "batch")
    data, code = _backend(
        f"/feedback?block_id={block_id}", method="POST", json=body
    )
    return jsonify(data), code


@app.route("/proxy/model/retrain/status", methods=["GET"])
@login_required
def proxy_retrain_status():
    """Poll retraining progress (used by Update Model button)."""
    data, code = _backend("/model/retrain/status")
    return jsonify(data), code


@app.route("/proxy/collector/start", methods=["POST"])
@login_required
def proxy_collector_start():
    data, code = _backend("/collector/start", method="POST")
    return jsonify(data), code


@app.route("/proxy/collector/stop", methods=["POST"])
@login_required
def proxy_collector_stop():
    data, code = _backend("/collector/stop", method="POST")
    return jsonify(data), code


# ---------------------------------------------------------------------------
# Agent ingestion endpoint  (called by agent.py running on remote machines)
# ---------------------------------------------------------------------------

AGENT_API_KEY = os.environ.get("AGENT_API_KEY", "sentinel-secret-key")


@app.route("/api/logs", methods=["POST"])
def receive_agent_logs():
    """
    Receives log batches from agent.py running on monitored machines.
    Validates the API key then forwards to the ML backend /ingest endpoint.
    No login_required — agents authenticate via X-API-Key header instead.
    """
    key = request.headers.get("X-API-Key", "")
    if key != AGENT_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    payload = request.get_json(silent=True)
    if not payload or not isinstance(payload, list):
        return jsonify({"error": "Expected a JSON array of log lines"}), 400

    # Forward to backend /ingest
    data, code = _backend("/ingest", method="POST", json=payload)
    return jsonify(data), code


@app.route("/proxy/model/retrain", methods=["POST"])
@login_required
def proxy_model_retrain():
    """Trigger ML model retraining on the backend."""
    data, code = _backend("/model/retrain", method="POST")
    return jsonify(data), code


@app.route("/proxy/templates", methods=["GET"])
@login_required
def proxy_get_templates():
    """Get templates (THREAT_KEYWORDS) from the ML backend."""
    data, code = _backend("/templates")
    return jsonify(data), code


# ---------------------------------------------------------------------------
# Our own admin + template management
# ---------------------------------------------------------------------------

@app.route("/api/templates", methods=["GET"])
@login_required
def get_templates():
    return jsonify(load_templates())


@app.route("/api/templates", methods=["POST"])
@login_required
def update_templates():
    data = request.get_json(silent=True)
    if not isinstance(data, list):
        return jsonify({"error": "Expected a JSON array"}), 400
    save_templates(data)
    return jsonify({"saved": len(data)})


@app.route("/api/admins", methods=["GET"])
@login_required
def get_admins():
    return jsonify(list(load_admins().keys()))


@app.route("/api/admins", methods=["POST"])
@login_required
def create_admin():
    data = request.get_json(silent=True) or {}
    u, p = data.get("username", "").strip(), data.get("password", "")
    if not u or not p:
        return jsonify({"error": "username and password required"}), 400
    if not add_admin(u, p):
        return jsonify({"error": "Admin already exists"}), 409
    return jsonify({"created": u}), 201


@app.route("/api/admins/<username>", methods=["DELETE"])
@login_required
def remove_admin(username):
    if not delete_admin(username):
        return jsonify({"error": "Admin not found"}), 404
    return jsonify({"deleted": username})


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    ensure_default_admin()
    print(f"\n  Log Sentinel AI  |  Frontend Server")
    print(f"  Dashboard  ->  http://localhost:5000")
    print(f"  ML Backend ->  {BACKEND_URL}\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
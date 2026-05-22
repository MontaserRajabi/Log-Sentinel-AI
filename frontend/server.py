"""
server.py  —  Log Sentinel AI  |  Frontend Flask Server
Serves the web dashboard and proxies requests to the ML backend.

Run:
    python server.py

Set BACKEND_URL to your teammate's backend IP:port.
"""

import subprocess
import sys

# Auto-install dependencies if missing (Azure deployment without Oryx build step)
try:
    import flask, requests as _r, dotenv
except ImportError:
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        "flask", "requests", "python-dotenv",
        "--quiet", "--disable-pip-version-check"
    ])

import traceback
import logging
logging.basicConfig(level=logging.INFO)

from dotenv import load_dotenv
load_dotenv()   # loads .env from the current working directory

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from functools import wraps
import requests as req
import os

try:
    from models.admin_manager import (
        check_admin, load_admins, add_admin,
        delete_admin, ensure_default_admin,
        get_admin_backend_url, get_admin_os, update_admin_os,
        get_admin_email, update_admin_email,
        update_admin_password, find_admin_by_email,
        get_user_role, update_user_role,
        get_user_machine, update_user_machine,
        is_verified, mark_verified,
    )
    from models.detector import load_templates, save_templates
    _import_error = None
except Exception as _e:
    _import_error = traceback.format_exc()
    logging.error(f"Import error: {_import_error}")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "sentinel-change-this-in-production")
app.config["TEMPLATES_AUTO_RELOAD"] = True

# ── Point this to your teammate's ML backend ─────────────────────────────────
BACKEND_URL        = os.environ.get("BACKEND_URL", "http://localhost:8000")
TIMEOUT            = 10
SUPERADMIN_USER    = os.environ.get("SUPERADMIN_USERNAME", "")
SUPERADMIN_PASS    = os.environ.get("SUPERADMIN_PASSWORD", "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_backend_url():
    """Return the backend URL for the current user session."""
    return session.get("backend_url", BACKEND_URL).rstrip("/")


import re as _re

def _validate_password(password: str) -> str | None:
    """Return an error string if password is too weak, else None."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if not _re.search(r'\d', password):
        return "Password must contain at least one number (0–9)."
    if not _re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>/?\\|`~]', password):
        return "Password must contain at least one symbol (!@#$%^&* etc.)."
    return None

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


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login_page"))
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    role = session.get("role", "user")
    username = session.get("admin", "")
    profile_email = get_admin_email(username) or ""
    if role == "admin":
        return render_template("dashboard.html", backend_url=_get_backend_url(),
                               profile_email=profile_email)
    return render_template("user_dashboard.html",
                           username=username,
                           backend_url=_get_backend_url(),
                           user_machine=session.get("source_machine", ""),
                           profile_email=profile_email)


@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Check superadmin credentials first (always admin, bypasses DB)
        is_superadmin = (
            SUPERADMIN_USER and SUPERADMIN_PASS
            and username == SUPERADMIN_USER
            and password == SUPERADMIN_PASS
        )

        if is_superadmin or check_admin(username, password):
            # Block access until email is verified (superadmin bypasses this)
            if not is_superadmin and not is_verified(username):
                return render_template("login.html", error="",
                                       unverified_username=username)
            stored_url  = get_admin_backend_url(username) if not is_superadmin else ""
            backend_url = (stored_url or BACKEND_URL).rstrip("/")
            os_type = request.form.get("os_type", "").strip()
            if os_type and not is_superadmin:
                update_admin_os(username, os_type)
            else:
                os_type = get_admin_os(username) if not is_superadmin else "auto"

            pending_session = {
                "admin":          username,
                "backend_url":    backend_url,
                "os_type":        os_type or "auto",
                "role":           "admin" if is_superadmin else get_user_role(username),
                "source_machine": "" if is_superadmin else get_user_machine(username),
            }

            # Superadmin skips MFA (no email in DB)
            if is_superadmin:
                for k, v in pending_session.items():
                    session[k] = v
                return redirect(url_for("dashboard"))

            # Regular user → send MFA code
            user_email = get_admin_email(username)
            if not user_email:
                # No email stored → skip MFA gracefully
                for k, v in pending_session.items():
                    session[k] = v
                return redirect(url_for("dashboard"))

            # Generate OTP and store state
            otp   = "".join(str(secrets.randbelow(10)) for _ in range(6))
            token = secrets.token_hex(32)
            now   = datetime.now(timezone.utc).replace(tzinfo=None)
            # Clean up any previous MFA token for this session
            old = session.pop("_mfa_token", None)
            if old and old in _mfa_codes:
                del _mfa_codes[old]
            _mfa_codes[token] = {
                "otp":             otp,
                "username":        username,
                "email":           user_email,
                "expires_at":      now + timedelta(minutes=10),
                "attempts":        0,
                "pending_session": pending_session,
            }

            if _send_mfa_email(user_email, username, otp):
                session["_mfa_token"] = token
                return redirect(url_for("mfa_verify"))
            else:
                # Email unavailable → complete login without MFA
                del _mfa_codes[token]
                for k, v in pending_session.items():
                    session[k] = v
                logging.warning("MFA email failed for %s — completing login without MFA", username)
                return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error, unverified_username="")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ---------------------------------------------------------------------------
# MFA — Email OTP verification
# ---------------------------------------------------------------------------

@app.route("/mfa", methods=["GET", "POST"])
def mfa_verify():
    token = session.get("_mfa_token")
    if not token or token not in _mfa_codes:
        return redirect(url_for("login_page"))

    entry = _mfa_codes[token]
    now   = datetime.now(timezone.utc).replace(tzinfo=None)

    # Expired
    if now > entry["expires_at"]:
        del _mfa_codes[token]
        session.pop("_mfa_token", None)
        return render_template("mfa.html", error="Code expired. Please sign in again.",
                               email_hint="", expired=True)

    error = ""
    if request.method == "POST":
        # Too many attempts
        if entry["attempts"] >= 5:
            del _mfa_codes[token]
            session.pop("_mfa_token", None)
            return redirect(url_for("login_page"))

        otp_input = "".join(request.form.get("otp", "").split())  # strip spaces

        entry["attempts"] += 1

        if otp_input == entry["otp"]:
            # ✓ Correct — complete login
            for k, v in entry["pending_session"].items():
                session[k] = v
            session.pop("_mfa_token", None)
            del _mfa_codes[token]
            return redirect(url_for("dashboard"))
        else:
            remaining = 5 - entry["attempts"]
            if remaining <= 0:
                del _mfa_codes[token]
                session.pop("_mfa_token", None)
                return render_template("mfa.html",
                                       error="Too many incorrect attempts. Please sign in again.",
                                       email_hint="", expired=True)
            error = f"Incorrect code — {remaining} attempt{'s' if remaining != 1 else ''} remaining."

    email_hint = _mask_email(entry.get("email", ""))
    return render_template("mfa.html", error=error, email_hint=email_hint, expired=False)


@app.route("/mfa/resend", methods=["POST"])
def mfa_resend():
    token = session.get("_mfa_token")
    if not token or token not in _mfa_codes:
        return redirect(url_for("login_page"))

    entry = _mfa_codes[token]
    otp   = "".join(str(secrets.randbelow(10)) for _ in range(6))
    now   = datetime.now(timezone.utc).replace(tzinfo=None)
    entry["otp"]        = otp
    entry["expires_at"] = now + timedelta(minutes=10)
    entry["attempts"]   = 0
    _send_mfa_email(entry["email"], entry["username"], otp)
    return redirect(url_for("mfa_verify"))


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("admin"):
        return redirect(url_for("dashboard"))

    error         = ""
    form_username = ""
    form_email    = ""
    pending       = False

    # Handle redirect-back from verify_email on error
    if request.method == "GET":
        if request.args.get("expired") == "1":
            error = "Verification link expired. Please register again."
        elif request.args.get("taken") == "1":
            error = "That username was taken while waiting for verification. Please choose another."
        # Show "check your email" screen after a successful POST redirect
        if request.args.get("pending") == "1":
            pending    = True
            form_email = session.pop("_reg_pending_email", "")

    if request.method == "POST":
        username         = request.form.get("username", "").strip()
        email            = request.form.get("email", "").strip().lower()
        password         = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        import re
        if not re.match(r'^[A-Za-z0-9_\-]{3,32}$', username):
            error = "Username must be 3–32 characters (letters, numbers, _ -)."
        elif "@" not in email or "." not in email.split("@")[-1]:
            error = "Enter a valid email address."
        elif pw_err := _validate_password(password):
            error = pw_err
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            smtp_ready = all([
                os.getenv("NOTIFY_EMAIL_FROM"),
                os.getenv("NOTIFY_EMAIL_USER"),
                os.getenv("NOTIFY_EMAIL_PASS"),
            ])
            if not smtp_ready:
                error = ("Email verification is required but email sending is not configured on this server. "
                         "Please ask your administrator to create an account for you.")
            elif username.lower() in {u.lower() for u in load_admins()}:
                error = "Username already taken. Please choose another."
            elif find_admin_by_email(email):
                error = "An account with that email address already exists."
            else:
                # Create account immediately as unverified so the username is reserved
                if not add_admin(username, password, email=email, verified=False):
                    error = "Username already taken. Please choose another."
                else:
                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    # Prune stale tokens for this user before creating a new one
                    for t in [t for t, v in _pending_registrations.items()
                               if now > v["expires_at"] or v.get("username") == username]:
                        del _pending_registrations[t]
                    token = secrets.token_urlsafe(32)
                    _pending_registrations[token] = {
                        "username"  : username,
                        "expires_at": now + timedelta(hours=24),
                    }
                    if _send_verification_email(email, username, token):
                        session["_reg_pending_email"] = email
                        return redirect(url_for("register", pending="1"))
                    else:
                        # Roll back — delete the unverified account
                        delete_admin(username)
                        del _pending_registrations[token]
                        error = "Could not send the verification email. Please try again later."

        form_username = username
        form_email    = email

    return render_template("register.html",
                           error=error,
                           form_username=form_username,
                           form_email=form_email,
                           pending=pending)


@app.route("/verify-email")
def verify_email():
    """User clicks the link in the verification email; account is marked verified here."""
    token  = request.args.get("token", "")
    record = _pending_registrations.get(token)
    now    = datetime.now(timezone.utc).replace(tzinfo=None)

    if not record or now > record["expires_at"]:
        return redirect(url_for("register", expired="1"))

    username = record["username"]
    del _pending_registrations[token]

    if not mark_verified(username):
        # Account was deleted in the meantime (edge case)
        return redirect(url_for("register", expired="1"))

    logging.info("Email verified for user: %s", username)

    session["admin"]       = username
    session["backend_url"] = BACKEND_URL
    session["os_type"]     = "auto"
    session["role"]        = get_user_role(username)
    session["source_machine"] = get_user_machine(username)
    return redirect(url_for("dashboard"))


@app.route("/resend-verification", methods=["POST"])
def resend_verification():
    """Resend the verification email to an unverified user."""
    username = request.form.get("username", "").strip()
    if not username or is_verified(username):
        return redirect(url_for("login_page"))

    email = get_admin_email(username)
    if not email:
        return render_template("login.html", error="No email on file — contact your administrator.",
                               unverified_username="")

    smtp_ready = all([
        os.getenv("NOTIFY_EMAIL_FROM"),
        os.getenv("NOTIFY_EMAIL_USER"),
        os.getenv("NOTIFY_EMAIL_PASS"),
    ])
    if not smtp_ready:
        return render_template("login.html",
                               error="Email sending is not configured on this server.",
                               unverified_username="")

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Remove any old tokens for this user
    for t in [t for t, v in _pending_registrations.items() if v.get("username") == username]:
        del _pending_registrations[t]

    token = secrets.token_urlsafe(32)
    _pending_registrations[token] = {
        "username"  : username,
        "expires_at": now + timedelta(hours=24),
    }
    if _send_verification_email(email, username, token):
        session["_reg_pending_email"] = email
        return redirect(url_for("register", pending="1"))
    else:
        del _pending_registrations[token]
        return render_template("login.html",
                               error="Could not send verification email. Try again later.",
                               unverified_username=username)


# ---------------------------------------------------------------------------
# Profile — view username, change password, update email
# ---------------------------------------------------------------------------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    username = session["admin"]
    success  = ""
    error    = ""
    if request.method == "POST":
        action = request.form.get("action")

        if action == "change_password":
            current  = request.form.get("current_password", "")
            new_pw   = request.form.get("new_password", "")
            confirm  = request.form.get("confirm_password", "")
            if not check_admin(username, current):
                error = "Current password is incorrect."
            elif pw_err := _validate_password(new_pw):
                error = pw_err
            elif new_pw != confirm:
                error = "New passwords do not match."
            else:
                update_admin_password(username, new_pw)
                success = "Password updated successfully."

        elif action == "update_email":
            email = request.form.get("email", "").strip()
            if email and ("@" not in email or "." not in email.split("@")[-1]):
                error = "Enter a valid email address."
            else:
                result = update_admin_email(username, email)
                if result == "email_taken":
                    error = "That email address is already in use by another account."
                else:
                    success = "Email updated successfully."

        elif action == "update_machine":
            machine = request.form.get("source_machine", "").strip()
            update_user_machine(username, machine)
            session["source_machine"] = machine
            success = "Machine updated successfully."

    current_email   = get_admin_email(username)
    current_machine = get_user_machine(username)
    return render_template("profile.html",
                           username=username,
                           email=current_email,
                           source_machine=current_machine,
                           success=success,
                           error=error)


# ---------------------------------------------------------------------------
# Forgot / Reset password
# ---------------------------------------------------------------------------

import secrets
from datetime import datetime, timedelta, timezone
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

_reset_tokens:            dict[str, dict] = {}  # token → {username, expires_at}
_pending_pairs:           dict[str, dict] = {}  # code  → {machine, expires_at}
_health_cache:            dict[str, dict] = {}  # machine → latest health snapshot
_pending_registrations:   dict[str, dict] = {}  # token → {username, password, email, expires_at}
_mfa_codes:               dict[str, dict] = {}  # token → {otp, username, email, expires_at, attempts, pending_session}


def _mask_email(email: str) -> str:
    """Return a partially masked email: m***@gmail.com"""
    if not email or "@" not in email:
        return "your registered email"
    local, domain = email.split("@", 1)
    masked = local[0] + "***" if len(local) > 1 else "***"
    return f"{masked}@{domain}"


def _send_mfa_email(to_email: str, username: str, otp: str) -> bool:
    """Send a 6-digit OTP verification code to the user."""
    email_from = os.getenv("NOTIFY_EMAIL_FROM", "")
    email_user = os.getenv("NOTIFY_EMAIL_USER", "")
    email_pass = os.getenv("NOTIFY_EMAIL_PASS", "")
    email_host = os.getenv("NOTIFY_EMAIL_HOST", "smtp.gmail.com")
    email_port = int(os.getenv("NOTIFY_EMAIL_PORT", 587))

    if not all([email_from, email_user, email_pass, to_email]):
        return False

    import uuid as _uuid
    body_html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#f3f4f6;font-family:'Segoe UI',Arial,sans-serif;">
<div style="max-width:480px;margin:32px auto;background:#fff;border-radius:10px;
            overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.10);">
  <div style="background:#0d1117;padding:28px 32px 22px;">
    <p style="margin:0 0 4px;color:#8b949e;font-size:11px;letter-spacing:1.5px;text-transform:uppercase;">
      Log Sentinel AI
    </p>
    <h1 style="margin:0;color:#e6edf3;font-size:20px;font-weight:700;">
      Verification Code
    </h1>
  </div>
  <div style="padding:32px;">
    <p style="margin:0 0 24px;color:#374151;font-size:14px;line-height:1.6;">
      Hi <strong>{username}</strong>, use the code below to complete your sign-in.
      It expires in <strong>10 minutes</strong>.
    </p>
    <div style="text-align:center;margin:0 0 28px;">
      <div style="display:inline-block;background:#0d1117;border-radius:10px;
                  padding:18px 36px;letter-spacing:12px;
                  font-family:'Courier New',monospace;font-size:32px;
                  font-weight:700;color:#17c3d8;border:1px solid #30363d;">
        {otp}
      </div>
    </div>
    <p style="margin:0;color:#9ca3af;font-size:12px;line-height:1.6;text-align:center;">
      If you didn't try to sign in, ignore this email.<br>
      Your account is safe — no action needed.
    </p>
  </div>
  <div style="background:#f9fafb;padding:14px 32px;border-top:1px solid #e5e7eb;text-align:center;">
    <p style="margin:0;color:#9ca3af;font-size:11px;">Log Sentinel AI Security Platform</p>
  </div>
</div>
</body></html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[Log Sentinel AI] Your sign-in code: {otp}"
        msg["From"]    = email_from
        msg["To"]      = to_email
        msg["Message-ID"] = f"<mfa-{_uuid.uuid4().hex}@logsentinel>"
        msg.attach(MIMEText(body_html, "html", "utf-8"))
        with smtplib.SMTP(email_host, email_port, timeout=10) as s:
            s.ehlo(); s.starttls(); s.login(email_user, email_pass)
            s.sendmail(email_from, to_email, msg.as_string())
        logging.info("MFA code sent to %s", to_email)
        return True
    except Exception as exc:
        logging.error("MFA email failed: %s", exc)
        return False


def _send_reset_email(to_email: str, username: str, token: str) -> bool:
    """Send a password reset link using the same SMTP config as notification.py."""
    email_from = os.getenv("NOTIFY_EMAIL_FROM", "")
    email_user = os.getenv("NOTIFY_EMAIL_USER", "")
    email_pass = os.getenv("NOTIFY_EMAIL_PASS", "")
    email_host = os.getenv("NOTIFY_EMAIL_HOST", "smtp.gmail.com")
    email_port = int(os.getenv("NOTIFY_EMAIL_PORT", 587))

    if not all([email_from, email_user, email_pass]):
        logging.warning("Reset email: SMTP credentials not configured in .env")
        return False

    reset_url = url_for("reset_password", token=token, _external=True)

    body = f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
    <h2 style="color:#0066ff;">Log Sentinel AI — Password Reset</h2>
    <p>Hi <strong>{username}</strong>,</p>
    <p>You requested a password reset. Click the link below to set a new password.</p>
    <p style="margin:24px 0;">
        <a href="{reset_url}"
           style="background:#0066ff;color:#fff;padding:12px 24px;
                  text-decoration:none;border-radius:4px;font-weight:bold;">
           Reset My Password
        </a>
    </p>
    <p style="color:#888;font-size:12px;">
        This link expires in 30 minutes.<br>
        If you did not request this, ignore this email.
    </p>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Log Sentinel AI — Password Reset"
    msg["From"]    = email_from
    msg["To"]      = to_email
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(email_host, email_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(email_user, email_pass)
            server.sendmail(email_from, to_email, msg.as_string())
        return True
    except Exception as e:
        logging.error("Reset email failed: %s", e)
        return False


def _send_verification_email(to_email: str, username: str, token: str) -> bool:
    """Send an email address verification link to a newly registered user."""
    email_from = os.getenv("NOTIFY_EMAIL_FROM", "")
    email_user = os.getenv("NOTIFY_EMAIL_USER", "")
    email_pass = os.getenv("NOTIFY_EMAIL_PASS", "")
    email_host = os.getenv("NOTIFY_EMAIL_HOST", "smtp.gmail.com")
    email_port = int(os.getenv("NOTIFY_EMAIL_PORT", 587))

    if not all([email_from, email_user, email_pass]):
        logging.warning("Verification email: SMTP credentials not configured in .env")
        return False

    verify_url = url_for("verify_email", token=token, _external=True)

    body = f"""
    <html><body style="font-family:Arial,sans-serif;color:#222;">
    <h2 style="color:#0066ff;">Log Sentinel AI — Verify Your Email</h2>
    <p>Hi <strong>{username}</strong>,</p>
    <p>Thanks for registering! Click the button below to verify your email and activate your account.</p>
    <p style="margin:24px 0;">
        <a href="{verify_url}"
           style="background:#0066ff;color:#fff;padding:12px 24px;
                  text-decoration:none;border-radius:4px;font-weight:bold;">
           Verify Email Address
        </a>
    </p>
    <p style="color:#888;font-size:12px;">
        This link expires in 24 hours.<br>
        If you did not create this account, you can safely ignore this email.
    </p>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Log Sentinel AI — Verify Your Email"
    msg["From"]    = email_from
    msg["To"]      = to_email
    msg.attach(MIMEText(body, "html"))

    try:
        with smtplib.SMTP(email_host, email_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(email_user, email_pass)
            server.sendmail(email_from, to_email, msg.as_string())
        return True
    except Exception as e:
        logging.error("Verification email failed: %s", e)
        return False


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = ""
    error   = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        username = find_admin_by_email(email)
        # Always show same message — don't reveal whether email exists
        message = "If that email is registered, a reset link has been sent."
        if username:
            token = secrets.token_urlsafe(32)
            _reset_tokens[token] = {
                "username"  : username,
                "expires_at": datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=30),
            }
            if not _send_reset_email(email, username, token):
                error = ("Could not send email — SMTP not configured. "
                         "Ask your administrator to reset your password manually.")
                message = ""
    return render_template("forgot_password.html", message=message, error=error)


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    token = request.args.get("token", "")
    error = ""

    # Validate token
    record = _reset_tokens.get(token)
    if not record or datetime.now(timezone.utc).replace(tzinfo=None) > record["expires_at"]:
        return render_template("reset_password.html",
                               token=token, expired=True, error="", success="")

    if request.method == "POST":
        new_pw  = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if pw_err := _validate_password(new_pw):
            error = pw_err
        elif new_pw != confirm:
            error = "Passwords do not match."
        else:
            update_admin_password(record["username"], new_pw)
            del _reset_tokens[token]   # one-time use
            return render_template("reset_password.html",
                                   token="", expired=False, error="",
                                   success="Password reset! You can now log in.")

    return render_template("reset_password.html",
                           token=token, expired=False, error=error, success="")


# ---------------------------------------------------------------------------
# Proxy endpoints — forward to teammate's ML backend
# ---------------------------------------------------------------------------

@app.route("/proxy/status")
@login_required
def proxy_status():
    data, code = _backend("/status")
    return jsonify(data), code


@app.route("/proxy/alerts/machines")
@login_required
def proxy_alert_machines():
    if session.get("role") != "admin":
        # Users only see their own machine
        machine = session.get("source_machine", "")
        return jsonify({"machines": [machine] if machine else []}), 200
    data, code = _backend("/alerts/machines")
    return jsonify(data), code


@app.route("/proxy/alerts")
@login_required
def proxy_alerts():
    params = dict(request.args)
    # Non-admin users: force filter to their paired machine only
    if session.get("role") != "admin":
        machine = session.get("source_machine", "").lower()
        if machine:
            params["machine"] = machine
        else:
            # No machine paired yet — return empty
            return jsonify({"alerts": [], "total": 0}), 200
    data, code = _backend("/alerts", params=params)
    return jsonify(data), code


@app.route("/proxy/events")
@login_required
def proxy_events():
    params = dict(request.args)
    # Non-admin users: force filter to their paired machine only
    if session.get("role") != "admin":
        machine = session.get("source_machine", "").lower()
        if machine:
            params["machine"] = machine
        else:
            return jsonify([]), 200
    data, code = _backend("/events", params=params)
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
# Machine pairing endpoints
# ---------------------------------------------------------------------------

@app.route("/api/pair/register", methods=["POST"])
def pair_register():
    """
    Called by the agent on startup — stores a one-time pairing code.
    No user login required; authenticates via X-API-Key.
    """
    key = request.headers.get("X-API-Key", "")
    if key != AGENT_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data    = request.get_json(silent=True) or {}
    machine = data.get("machine", "").strip()
    code    = data.get("code", "").strip().upper()

    if not machine or not code:
        return jsonify({"error": "machine and code required"}), 400

    # Prune expired entries
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for c in [c for c, v in _pending_pairs.items() if now > v["expires_at"]]:
        del _pending_pairs[c]

    _pending_pairs[code] = {
        "machine":    machine,
        "expires_at": now + timedelta(minutes=10),
    }
    logging.info("Pairing code registered: %s → %s", code, machine)
    return jsonify({"status": "ok", "code": code}), 200


@app.route("/api/pair/claim", methods=["POST"])
@login_required
def pair_claim():
    """
    Called by a logged-in user — validates the pairing code and
    links their account to the machine.
    """
    data = request.get_json(silent=True) or {}
    code = data.get("code", "").strip().upper()

    if not code:
        return jsonify({"error": "code required"}), 400

    # Prune expired
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    for c in [c for c, v in _pending_pairs.items() if now > v["expires_at"]]:
        del _pending_pairs[c]

    pair = _pending_pairs.get(code)
    if not pair:
        return jsonify({"error": "Invalid or expired code. Make sure the agent is running and try again."}), 404

    machine  = pair["machine"].lower()
    username = session["admin"]

    update_user_machine(username, machine)
    session["source_machine"] = machine
    del _pending_pairs[code]   # one-time use

    logging.info("Machine paired: %s → user %s", machine, username)
    return jsonify({"status": "ok", "machine": machine})


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
@admin_required
def create_admin():
    data = request.get_json(silent=True) or {}
    u = data.get("username", "").strip()
    p = data.get("password", "")
    r = data.get("role", "user")
    if not u or not p:
        return jsonify({"error": "username and password required"}), 400
    if not add_admin(u, p, role=r):
        return jsonify({"error": "User already exists"}), 409
    return jsonify({"created": u, "role": r}), 201


@app.route("/api/admins/<username>", methods=["DELETE"])
@admin_required
def remove_admin(username):
    if not delete_admin(username):
        return jsonify({"error": "Admin not found"}), 404
    return jsonify({"deleted": username})


@app.route("/api/admins/<username>/os", methods=["GET", "POST"])
@login_required
def admin_os(username):
    if request.method == "POST":
        data    = request.get_json(silent=True) or {}
        os_type = data.get("os_type", "auto")
        if not update_admin_os(username, os_type):
            return jsonify({"error": "Admin not found"}), 404
        if session.get("admin") == username:
            session["os_type"] = os_type
        return jsonify({"username": username, "os_type": os_type})
    return jsonify({"username": username, "os_type": get_admin_os(username)})


@app.route("/api/admins/<username>/role", methods=["POST"])
@admin_required
def set_user_role_api(username):
    data = request.get_json(silent=True) or {}
    role = data.get("role", "user")
    if not update_user_role(username, role):
        return jsonify({"error": "User not found"}), 404
    return jsonify({"username": username, "role": role})


@app.route("/api/admins/list", methods=["GET"])
@admin_required
def get_admins_full():
    """Return users with their roles."""
    admins = load_admins()
    return jsonify([
        {"username": u, "role": r.get("role", "user")}
        for u, r in admins.items()
    ])


# ---------------------------------------------------------------------------
# System health API  (agent POSTs metrics; dashboard GETs them)
# ---------------------------------------------------------------------------

@app.route("/api/health", methods=["POST"])
def receive_health():
    """Agent POSTs CPU/RAM/disk metrics here every ~10 s."""
    key = request.headers.get("X-API-Key", "")
    if key != AGENT_API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    machine = data.get("machine", "").strip().lower()
    if machine:
        _health_cache[machine] = {**data, "updated_at": datetime.now(timezone.utc).isoformat()}
    return jsonify({"ok": True})


@app.route("/api/health", methods=["GET"])
@login_required
def get_health():
    """Dashboard polls this for the user's machine health."""
    machine = request.args.get("machine", "").strip().lower()
    if not machine:
        return jsonify({}), 200
    if session.get("role") != "admin":
        if machine != session.get("source_machine", "").lower():
            return jsonify({"error": "Unauthorized"}), 403
    return jsonify(_health_cache.get(machine, {}))


@app.route("/api/health/machines", methods=["GET"])
@admin_required
def get_health_machines():
    """Admin: returns last-seen times for all machines from health cache."""
    from datetime import datetime as _dt, timezone as _tz
    now = _dt.now(_tz.utc)
    THRESHOLD = 15 * 60  # 15 minutes in seconds
    result = {}
    for machine, data in _health_cache.items():
        updated = data.get("updated_at", "")
        try:
            updated_dt = _dt.fromisoformat(updated)
            if updated_dt.tzinfo is None:
                updated_dt = updated_dt.replace(tzinfo=_tz.utc)
            delta = (now - updated_dt).total_seconds()
            result[machine] = {"online": delta < THRESHOLD, "last_seen": updated, "os": data.get("os", "")}
        except Exception:
            result[machine] = {"online": False, "last_seen": updated}
    return jsonify(result)


# ---------------------------------------------------------------------------
# Health check (used by Azure App Service)
# ---------------------------------------------------------------------------

@app.route("/health")
def health():
    if _import_error:
        return f"<pre>{_import_error}</pre>", 500
    return "OK", 200


@app.route("/debug")
def debug():
    if _import_error:
        return f"<pre>IMPORT ERROR:\n{_import_error}</pre>", 500
    return "<pre>No import errors. App loaded OK.</pre>", 200


# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

_initialized = False

@app.before_request
def _startup():
    global _initialized
    if not _initialized:
        _initialized = True
        if _import_error is None:
            try:
                ensure_default_admin()
            except Exception:
                logging.error("ensure_default_admin failed", exc_info=True)

if __name__ == "__main__":
    print(f"\n  Log Sentinel AI  |  Frontend Server")
    print(f"  Dashboard  ->  http://localhost:5000")
    print(f"  ML Backend ->  {BACKEND_URL}\n")
    app.run(host="0.0.0.0", port=5000, debug=False)

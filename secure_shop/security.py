"""Security helpers: password hashing, CSRF, rate limiting, input validation,
security headers, and the audit log. Defences are built into the application
(not left to the environment or to "hidden" pages).
"""
import functools
import hashlib
import hmac
import re
import time

import bcrypt
from flask import abort, current_app, request, session, g

from .db import execute, query


# --------------------------------------------------------------------------- #
# Password hashing: peppered bcrypt (per-user salt is built into bcrypt).
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    pepper = current_app.config["PASSWORD_PEPPER"]
    # HMAC-SHA256 acts as the "pepper" and keeps the bcrypt input at 32 bytes.
    peppered = hmac.new(pepper.encode(), password.encode(), hashlib.sha256).digest()
    return bcrypt.hashpw(peppered, bcrypt.gensalt(rounds=12)).decode("ascii")


def verify_password(password: str, stored_hash: str) -> bool:
    pepper = current_app.config["PASSWORD_PEPPER"]
    peppered = hmac.new(pepper.encode(), password.encode(), hashlib.sha256).digest()
    try:
        return bcrypt.checkpw(peppered, stored_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# Input validation (whitelist / strict formats).
# --------------------------------------------------------------------------- #
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
COUPON_RE = re.compile(r"^[A-Za-z0-9-]{3,24}$")
NAME_RE = re.compile(r"^[A-Za-z0-9 .'-]{1,80}$")
SAFE_TEXT_MAX = 2000


def valid_username(s):
    return bool(s) and USERNAME_RE.match(s) is not None


def valid_email(s):
    return bool(s) and len(s) <= 254 and EMAIL_RE.match(s) is not None


def valid_coupon_code(s):
    return bool(s) and COUPON_RE.match(s) is not None


def valid_price(value, minimum=0.01, maximum=1_000_000.0):
    try:
        f = float(value)
    except (TypeError, ValueError):
        return False
    return minimum <= f <= maximum


def clean_int(value, default=0, minimum=0, maximum=10_000):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, n))


# --------------------------------------------------------------------------- #
# CSRF protection (synchroniser token, constant-time comparison).
# --------------------------------------------------------------------------- #
def get_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        import secrets
        token = secrets.token_urlsafe(current_app.config["CSRF_TOKEN_BYTES"])
        session["_csrf_token"] = token
    return token


def csrf_protect(view):
    """Decorator enforcing a valid CSRF token on unsafe methods."""
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            sent = request.form.get("_csrf_token") or request.headers.get("X-CSRF-Token", "")
            real = session.get("_csrf_token", "")
            if not real or not sent or not hmac.compare_digest(real, sent):
                audit("csrf_failure", detail="missing or invalid CSRF token")
                abort(400, description="Invalid or missing CSRF token.")
        return view(*args, **kwargs)
    return wrapped


# --------------------------------------------------------------------------- #
# Login rate limiting & account lockout.
# --------------------------------------------------------------------------- #
def _now():
    return int(time.time())


def record_login_failure(identifier, username=None):
    now = _now()
    row = query("SELECT * FROM login_throttle WHERE identifier = ?", (identifier,), one=True)
    if row is None:
        execute(
            "INSERT INTO login_throttle (identifier, failed_count, first_failed_at, locked_until)"
            " VALUES (?, 1, ?, NULL)",
            (identifier, now),
        )
    else:
        execute(
            "UPDATE login_throttle SET failed_count = failed_count + 1, first_failed_at = ?"
            " WHERE identifier = ?",
            (now, identifier),
        )
    # Account-level lockout.
    if username:
        u = query("SELECT id, failed_logins FROM users WHERE username = ?", (username,), one=True)
        if u is not None:
            fails = u["failed_logins"] + 1
            locked = _now() + current_app.config["LOCKOUT_SECONDS"] \
                if fails >= current_app.config["MAX_LOGIN_FAILURES"] else None
            execute(
                "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                (fails, locked, u["id"]),
            )


def reset_login_failures(identifier, username=None):
    execute("DELETE FROM login_throttle WHERE identifier = ?", (identifier,))
    if username:
        execute(
            "UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username = ?",
            (username,),
        )


def is_throttled(identifier, username=None):
    now = _now()
    # IP-based rate limit.
    row = query(
        "SELECT failed_count, first_failed_at, locked_until FROM login_throttle WHERE identifier = ?",
        (identifier,),
        one=True,
    )
    if row is not None and row["failed_count"] >= current_app.config["LOGIN_RATE_LIMIT"]:
        if row["first_failed_at"] and (now - row["first_failed_at"]) < current_app.config["LOGIN_RATE_WINDOW"]:
            return True
    # Account-level lockout.
    if username:
        u = query("SELECT locked_until FROM users WHERE username = ?", (username,), one=True)
        if u is not None and u["locked_until"] and now < u["locked_until"]:
            return True
    return False


def client_ip():
    # Only trust a real proxy chain if configured; otherwise use the socket peer.
    return request.remote_addr or "unknown"


# --------------------------------------------------------------------------- #
# Audit log (accountability / non-repudiation).
# --------------------------------------------------------------------------- #
def audit(event_type, username=None, detail=""):
    try:
        execute(
            "INSERT INTO audit_log (event_type, username, ip, detail) VALUES (?, ?, ?, ?)",
            (event_type, username, client_ip(), str(detail)[:500]),
        )
    except Exception:
        # Never let logging break the request path.
        current_app.logger.exception("audit log write failed")


# --------------------------------------------------------------------------- #
# Security headers (defence in depth at the HTTP layer).
# --------------------------------------------------------------------------- #
CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


def apply_security_headers(response):
    response.headers.setdefault("X-After", "runs")
    response.headers.setdefault("Content-Security-Policy", CSP_POLICY)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store")
    # HSTS only makes sense over HTTPS.
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


# --------------------------------------------------------------------------- #
# Authorization helpers.
# --------------------------------------------------------------------------- #
def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return query("SELECT * FROM users WHERE id = ? AND active = 1", (uid,), one=True)


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return abort(401)
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        u = current_user()
        if u is None:
            return abort(401)
        if u["role"] != "admin":
            audit("access_denied", username=u["username"], detail="non-admin hit an admin route")
            return abort(403)
        return view(*args, **kwargs)
    return wrapped

"""Authentication: registration, email confirmation, login/logout, account
lockout, and optional TOTP two-factor authentication.
"""
import secrets
import time
import urllib.parse

from flask import (
    Blueprint, abort, current_app, flash, g, redirect, render_template,
    request, session, url_for,
)

from .db import execute, query
from .security import (
    audit, clean_int, client_ip, csrf_protect, current_user,
    hash_password, is_throttled, record_login_failure, reset_login_failures,
    valid_email, valid_username, verify_password,
)
from .totp import current_code, generate_secret, verify as totp_verify
from . import behavior
from .risk import time_allowed

bp = Blueprint("auth", __name__)

GENERIC_LOGIN_ERROR = "Invalid username or password."


def _regenerate_session():
    """Prevent session fixation: keep only a fresh CSRF token on privilege change."""
    session.clear()
    import secrets as _s
    session["_csrf_token"] = _s.token_urlsafe(32)


def _validated_password(pw):
    # NIST-style: prefer length; require a minimum and reject only whitespace.
    if not isinstance(pw, str):
        return False
    if len(pw) < 12:
        return False
    return True


def _record_and_score_behavior(u):
    """Lab 4 pipeline: record this successful login's features, then compare the
    new login against the user's history with the z-score anomaly detector.

    Returns (anomaly_score, is_anomaly). Gracefully skips when the browser did
    not send keystroke timing (no typing_speed/gap_mean), using only the hour.
    """
    import time as _time
    hour = _time.localtime().tm_hour

    ts_raw = request.form.get("typing_speed")
    gm_raw = request.form.get("gap_mean")
    typing_speed = None
    gap_mean = None
    if ts_raw:
        try:
            v = float(ts_raw)
            if 0.05 <= v <= 200.0:      # reject absurd client values
                typing_speed = v
        except ValueError:
            pass
    if gm_raw:
        try:
            v = float(gm_raw)
            if 0.001 <= v <= 5.0:
                gap_mean = v
        except ValueError:
            pass

    # Record the (successful) login for future comparisons.
    execute(
        "INSERT INTO login_behavior (user_id, hour, typing_speed, gap_mean) VALUES (?, ?, ?, ?)",
        (u["id"], hour, typing_speed, gap_mean),
    )

    history = query(
        "SELECT hour, typing_speed, gap_mean FROM login_behavior WHERE user_id = ?"
        " AND id < (SELECT MAX(id) FROM login_behavior WHERE user_id = ?) ORDER BY id",
        (u["id"], u["id"]),
    )
    if len(history) < current_app.config["BEHAVIOR_MIN_HISTORY"]:
        return None, False

    profile = behavior.build_profile([dict(r) for r in history])
    login = {"typing_speed": typing_speed, "gap_mean": gap_mean, "hour": hour}
    score = behavior.anomaly_score(login, profile)
    flagged = behavior.decide(score, current_app.config["BEHAVIOR_THRESHOLD"])
    if flagged:
        audit("login_anomaly", username=u["username"],
              detail=f"behavior anomaly score={score:.2f}")
    return score, flagged


@bp.route("/register", methods=("GET", "POST"))
@csrf_protect
def register():
    if current_user():
        return redirect(url_for("shop.index"))
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        full_name = (request.form.get("full_name") or "").strip()
        password = request.form.get("password") or ""

        errors = []
        if not valid_username(username):
            errors.append("Username must be 3-32 letters, numbers or underscores.")
        if not valid_email(email):
            errors.append("Enter a valid email address.")
        if not _validated_password(password):
            errors.append("Password must be at least 12 characters.")
        if full_name and len(full_name) > 80:
            errors.append("Name is too long.")

        if not errors:
            if query("SELECT id FROM users WHERE username = ?", (username,), one=True):
                errors.append("That username is already taken.")
            if query("SELECT id FROM users WHERE email = ?", (email,), one=True):
                errors.append("That email is already registered.")
            # Rate-limit account creation to slow mass signups.
            if is_throttled("register:" + client_ip()):
                errors.append("Too many registrations. Try again later.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email, full_name=full_name), 400

        confirm_token = secrets.token_urlsafe(32)
        execute(
            "INSERT INTO users (username, email, full_name, password_hash, email_confirm_token)"
            " VALUES (?, ?, ?, ?, ?)",
            (username, email, full_name, hash_password(password), confirm_token),
        )
        record_login_failure("register:" + client_ip())
        audit("register", username=username, detail="new account created")

        confirm_url = url_for("auth.confirm", token=confirm_token, _external=True)
        if g.get("DEV_CONFIRM_LINKS"):
            flash("Account created. Confirm your email to log in.", "info")
            flash(f"DEV confirmation link: {confirm_url}", "dev")
        else:
            flash("Account created. Check your email to confirm your address.", "info")
        return redirect(url_for("auth.login"))

    return render_template("register.html")


@bp.route("/confirm/<token>")
def confirm(token):
    u = query("SELECT * FROM users WHERE email_confirm_token = ?", (token,), one=True)
    if u is None:
        abort(404)
    execute("UPDATE users SET email_confirmed = 1, email_confirm_token = NULL WHERE id = ?", (u["id"],))
    audit("email_confirmed", username=u["username"])
    flash("Email confirmed. You can now log in.", "success")
    return redirect(url_for("auth.login"))


@bp.route("/login", methods=("GET", "POST"))
@csrf_protect
def login():
    if current_user():
        return redirect(url_for("shop.index"))

    if request.method == "POST":
        identifier = "login:" + client_ip()
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if is_throttled(identifier, username):
            audit("login_locked", username=username or None, detail="rate limit/lockout triggered")
            flash("Too many failed attempts. Account temporarily locked.", "error")
            return render_template("login.html", username=username), 429

        u = query("SELECT * FROM users WHERE username = ?", (username,), one=True)
        # Always verify against a dummy hash to keep timing uniform whether or
        # not the account exists (defeats username enumeration).
        dummy = hash_password("dummy-password-not-a-real-account")
        stored = u["password_hash"] if u else dummy
        ok = verify_password(password, stored)

        if not (u and ok and u["active"] and u["email_confirmed"]):
            record_login_failure(identifier, username if u else None)
            audit("login_failed", username=username or None)
            flash(GENERIC_LOGIN_ERROR, "error")
            return render_template("login.html", username=username), 401

        # Password accepted. Run the Lab 5 time-window policy and the Lab 4
        # behavioural anomaly detector before finalising the login.
        if current_app.config["ENFORCE_LOGIN_HOURS"]:
            import time as _time
            hour = _time.localtime().tm_hour
            if not time_allowed(hour, current_app.config["LOGIN_WINDOW_START"],
                                current_app.config["LOGIN_WINDOW_END"]):
                audit("login_outside_window", username=username, detail=f"hour={hour}")
                flash("Logins are not allowed for this account at the current time.", "error")
                return render_template("login.html", username=username), 403

        score, flagged = _record_and_score_behavior(u)

        # If 2FA is enabled, stage the user and ask for a code.
        if u["totp_secret"]:
            session["_pending_2fa_user"] = u["id"]
            session["_2fa_ts"] = int(time.time())
            audit("login_password_ok_2fa_pending", username=username)
            return redirect(url_for("auth.verify_2fa"))

        if flagged:
            # Anomalous behaviour with no MFA enrolled: allow but make it loud in
            # the audit log (a production system would force a step-up here).
            flash("Unusual sign-in pattern detected. Review your recent activity.", "warning")

        _regenerate_session()
        session["user_id"] = u["id"]
        session.permanent = True
        reset_login_failures(identifier, username)
        audit("login", username=username)
        flash("Logged in successfully.", "success")
        return redirect(url_for("shop.index"))

    return render_template("login.html")


@bp.route("/login/2fa", methods=("GET", "POST"))
@csrf_protect
def verify_2fa():
    uid = session.get("_pending_2fa_user")
    if not uid:
        return redirect(url_for("auth.login"))
    u = query("SELECT * FROM users WHERE id = ?", (uid,), one=True)
    if u is None or not u["totp_secret"]:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        ok, step = totp_verify(u["totp_secret"], code, window=1,
                               last_counter=u["last_totp_counter"])
        if ok:
            execute("UPDATE users SET last_totp_counter = ? WHERE id = ?", (step, u["id"]))
            _regenerate_session()
            session["user_id"] = u["id"]
            session.permanent = True
            reset_login_failures("login:" + client_ip(), u["username"])
            audit("login_2fa", username=u["username"])
            flash("Logged in successfully.", "success")
            return redirect(url_for("shop.index"))
        audit("login_2fa_failed", username=u["username"])
        flash("Invalid or expired one-time code.", "error")
        return render_template("verify_2fa.html"), 401

    return render_template("verify_2fa.html")


@bp.route("/logout", methods=("POST",))
@csrf_protect
def logout():
    u = current_user()
    if u:
        audit("logout", username=u["username"])
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("shop.index"))


# --------------------------------------------------------------------------- #
# Two-factor enrollment (self-service, opt-in).
# --------------------------------------------------------------------------- #
@bp.route("/account/2fa", methods=("GET", "POST"))
@csrf_protect
def setup_2fa():
    u = current_user()
    if u is None:
        return abort(401)

    if request.method == "POST":
        action = request.form.get("action")
        if action == "disable":
            execute("UPDATE users SET totp_secret = NULL, last_totp_counter = NULL WHERE id = ?", (u["id"],))
            audit("2fa_disabled", username=u["username"])
            flash("Two-factor authentication disabled.", "success")
            return redirect(url_for("shop.account"))

        secret = session.get("_pending_totp_secret")
        code = (request.form.get("code") or "").strip()
        if not secret:
            flash("Start over: enable two-factor authentication again.", "error")
            return redirect(url_for("auth.setup_2fa"))
        ok, _ = totp_verify(secret, code, window=1)
        if ok:
            execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, u["id"]))
            session.pop("_pending_totp_secret", None)
            audit("2fa_enabled", username=u["username"])
            flash("Two-factor authentication enabled.", "success")
            return redirect(url_for("shop.account"))
        flash("Invalid code. Try again.", "error")

    # GET or failed POST: issue a fresh secret.
    secret = generate_secret()
    session["_pending_totp_secret"] = secret
    otpauth = (
        "otpauth://totp/SecureShop:{user}?secret={secret}&issuer=SecureShop"
        .format(user=urllib.parse.quote(u["username"]), secret=secret)
    )
    return render_template("setup_2fa.html", secret=secret, otpauth=otpauth)

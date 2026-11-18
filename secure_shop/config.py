"""SecureShop configuration.

Every secret is read from the environment or from a per-installation secret
file that is generated on first run and excluded from version control. Nothing
secret is hard-coded (Cryptographic Failures / Security Misconfiguration).
"""
import os
import secrets


class Config:
    # ---- Application ----
    APP_NAME = "SecureShop"
    DATABASE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance", "secureshop.db")

    # ---- Secrets (never hard-coded) ----
    # SECURESHOP_SECRET_KEY overrides the auto-generated instance secret.
    SECRET_KEY = os.environ.get("SECURESHOP_SECRET_KEY", "")
    # Server-side "pepper" mixed into every password before bcrypt.
    PASSWORD_PEPPER = os.environ.get("SECURESHOP_PEPPER", "")

    # ---- Sessions ----
    PERMANENT_SESSION_LIFETIME = 1800            # 30 minutes idle timeout (seconds)
    SESSION_COOKIE_HTTPONLY = True               # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE = "Lax"              # CSRF hardening
    SESSION_COOKIE_SECURE = os.environ.get("SECURESHOP_HTTPS", "") == "1"  # True behind HTTPS
    SESSION_REFRESH_EACH_REQUEST = True

    # ---- Security policy ----
    MAX_LOGIN_FAILURES = 5                       # lock an account after N bad attempts
    LOCKOUT_SECONDS = 15 * 60                    # 15 minutes
    LOGIN_RATE_LIMIT = 20                        # max attempts per IP per window
    LOGIN_RATE_WINDOW = 15 * 60                  # window in seconds
    CSRF_TOKEN_BYTES = 32
    PASSWORD_MIN_LENGTH = 12
    TOTP_ISSUER = "SecureShop"
    TOTP_WINDOW = 1                              # +-30 s clock drift tolerance

    # ---- Lab 4: behavioural anomaly detection ----
    BEHAVIOR_THRESHOLD = 3.0                     # average z-score that flags an anomaly
    BEHAVIOR_MIN_HISTORY = 3                     # logins needed before a profile is trusted

    # ---- Lab 5: location & time window policy ----
    # The access window is a demo policy (off by default so the app can be
    # demonstrated at any hour). Set SECURESHOP_ENFORCE_HOURS=1 to require the
    # login to fall inside LOGIN_WINDOW_START..END (server local time).
    ENFORCE_LOGIN_HOURS = os.environ.get("SECURESHOP_ENFORCE_HOURS", "") == "1"
    LOGIN_WINDOW_START = 8                       # 08:00
    LOGIN_WINDOW_END = 22                        # up to but not including 22:00
    LOCATION_RADIUS_KM = 50.0                    # enrolled-home radius

    # ---- Demo / development convenience ----
    # When True, account-confirmation and password-reset links are shown in the
    # UI and written to the console because no real mail server is configured.
    # Set to False and wire a real mailer before going to production.
    SHOW_CONFIRM_LINKS = os.environ.get("SECURESHOP_MAIL_DEV", "") != "0"

    # ---- Misc ----
    WTF_CSRF_ENABLED = False  # we use our own CSRF implementation

    def ensure_secrets(self):
        """Create the instance secret file on first run and use it to seed the
        Flask secret key and the password pepper. Returns the loaded secret."""
        inst = os.path.join(os.path.dirname(os.path.dirname(__file__)), "instance")
        os.makedirs(inst, exist_ok=True)
        secret_file = os.path.join(inst, ".secret_key")
        if os.path.exists(secret_file):
            with open(secret_file, "r", encoding="utf-8") as f:
                stored = f.read().strip()
        else:
            stored = secrets.token_urlsafe(48)
            with open(secret_file, "w", encoding="utf-8") as f:
                f.write(stored)
        if not self.SECRET_KEY:
            self.SECRET_KEY = stored
        if not self.PASSWORD_PEPPER:
            # Derive a stable pepper from the secret key instead of storing a
            # second file; keep it out of the database.
            import hashlib
            self.PASSWORD_PEPPER = hashlib.sha256(("pepper:" + self.SECRET_KEY).encode()).hexdigest()
        return stored

"""RFC 6238 TOTP (time-based one-time password) — dependency-free.

Implements the standard so the demo does not require any external library and
so the logic is transparent for review. HOTP is RFC 4226; TOTP builds on it.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time

DIGITS = 6
PERIOD = 30  # seconds


def _hotp(secret_bytes: bytes, counter: int, digits: int = DIGITS) -> str:
    counter_bytes = struct.pack(">Q", counter)
    digest = hmac.new(secret_bytes, counter_bytes, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % (10 ** digits)).zfill(digits)


def generate_secret(length: int = 20) -> str:
    """Return a base32 secret for enrollment (160 bits by default)."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii").rstrip("=")


def current_code(secret_b32: str, for_time: float = None) -> str:
    """Compute the TOTP code for a base32 secret at a given unix time."""
    secret_bytes = base64.b32decode(_pad_b32(secret_b32))
    t = int((for_time if for_time is not None else time.time()) // PERIOD)
    return _hotp(secret_bytes, t)


def _pad_b32(s: str) -> str:
    return s.upper() + "=" * ((8 - len(s) % 8) % 8)


def verify(secret_b32: str, code: str, window: int = 1, last_counter: int = None):
    """Verify a code with ±window steps of clock drift and optional replay
    protection. Returns (ok, counter) where counter is the accepted step."""
    if not code or len(code) != DIGITS or not code.isdigit():
        return False, None
    secret_bytes = base64.b32decode(_pad_b32(secret_b32))
    counter = int(time.time() // PERIOD)
    # Constant-time compare to avoid timing attacks on the code check.
    for step in range(counter - window, counter + window + 1):
        if last_counter is not None and step <= last_counter:
            continue  # already used -> reject replay
        if hmac.compare_digest(_hotp(secret_bytes, step), code):
            return True, step
    return False, None

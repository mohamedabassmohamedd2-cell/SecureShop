# Security Coverage Matrix — SecureShop

The project requires a matrix with **one row per topic**: the attack scenario in
SecureShop, the root cause, the defence implemented, where it lives in the code,
and the evidence. This matrix is kept up to date throughout the project.

Legend for "Where in the code": paths are relative to the repository root
(`secure_shop/…`).

---

## A. OWASP Top 10 (2021) coverage

### A1 — Broken Access Control
| Field | Detail |
|---|---|
| **Attack scenario** | A logged-in customer guesses `/admin/`, or requests another user's order by changing the `order_ref` in the URL (IDOR). |
| **Root cause** | Trusting the client to self-police, or only hiding admin links in the UI instead of enforcing authorization on the server. |
| **Defence** | Server-side role check on every admin route (`admin_required`); order lookups are always scoped to the session user's `id`; deactivated users can't act. |
| **Where in the code** | `security.py::admin_required`, `admin.py` (all routes), `shop.py::order_confirmation` (`WHERE order_ref = ? AND user_id = ?`). |
| **Evidence** | `tests/test_security.py` checks 5 (non-admin → 403) and 6 (cross-user order → 404). |

### A2 — Security Misconfiguration
| Field | Detail |
|---|---|
| **Attack scenario** | Attacker exploits default/debug settings, or frames the site / injects scripts because no hardening headers are present. |
| **Root cause** | Default configs, `debug=True`, missing security headers. |
| **Defence** | `debug=False`; strict CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store`; HSTS behind TLS. |
| **Where in the code** | `security.py::apply_security_headers` (registered in `__init__.py` as `after_request`), `run.py`. |
| **Evidence** | Self-test check 1; `curl -I` shows the headers on every response. |

### A3 — Software & Data Integrity Failures (Supply Chain)
| Field | Detail |
|---|---|
| **Attack scenario** | A vulnerable or backdoored dependency is pulled in and exploited. |
| **Root cause** | Unpinned/unaudited dependencies, or deserializing/evaluating untrusted data. |
| **Defence** | Dependencies pinned with exact versions; no `pickle`/`eval`/`yaml.unsafe_load` anywhere; no third-party data is interpreted as code. |
| **Where in the code** | `requirements.txt` (pinned), `shop.py`/`admin.py` (no unsafe deserialization). |
| **Evidence** | `requirements.txt` review; no dynamic code evaluation in the codebase. |

### A4 — Cryptographic Failures
| Field | Detail |
|---|---|
| **Attack scenario** | The user table is stolen and passwords are cracked (plaintext / fast hash / missing salt). |
| **Root cause** | Weak or missing crypto for secrets at rest. |
| **Defence** | Passwords stored as **peppered bcrypt** (per-user salt built into bcrypt, server-side pepper via HMAC-SHA256); constant-time comparison; session cookie `HttpOnly`/`SameSite`. |
| **Where in the code** | `security.py::hash_password` / `verify_password`. |
| **Evidence** | Self-test check 7 (hash starts with `$2b$`, plaintext absent). |

### A5 — Injection (SQL, Command, Path Traversal)
| Field | Detail |
|---|---|
| **Attack scenario** | `' OR '1'='1` in search/login, or a payload that tries to run a shell command / read a file. |
| **Root cause** | String-concatenating user input into SQL or commands, or using user input in file paths. |
| **Defence** | **Parameterised SQL everywhere** (`?` placeholders); no `os.system`/`subprocess`; no file paths derived from user input; sort/category columns from a strict whitelist. |
| **Where in the code** | `db.py::query/execute` (only API for SQL), `shop.py::index` (whitelisted sort), all routes. |
| **Evidence** | Self-test check 2 (4 SQLi payloads in search + login all blocked). |

### A6 — Insecure Design
| Field | Detail |
|---|---|
| **Attack scenario** | The client supplies a price/quantity that the server accepts (business-logic abuse), e.g. buying a $129 item for $1. |
| **Root cause** | Designing trust in the client rather than validating at a trust boundary. |
| **Defence** | Threat model + "no client trust" principle: prices, totals, stock and ownership are always re-derived server-side; defence in depth (see Design Report). |
| **Where in the code** | `shop.py::checkout` (re-reads DB prices and stock), `shop.py::_cart_lines`. |
| **Evidence** | Self-test check 11 (order price equals DB price, not any client value). |

### A7 — Authentication Failures
| Field | Detail |
|---|---|
| **Attack scenario** | Credential stuffing/brute force; username enumeration via distinct error messages; session fixation; cookie theft. |
| **Root cause** | No rate-limiting, revealing errors, weak session handling. |
| **Defence** | Account lockout after 5 failures + per-IP rate limit; identical generic error for unknown user vs wrong password; session regenerated on login; `HttpOnly`/`SameSite` cookies; optional TOTP MFA. |
| **Where in the code** | `security.py` (throttle/lockout, `csrf` session), `auth.py::login`, `totp.py`. |
| **Evidence** | Self-test checks 8 (2FA), 9 (lockout), 10 (no user enumeration). |

### A8 — Software & Data Integrity Failures
| Field | Detail |
|---|---|
| **Attack scenario** | Attacker tampers with the shopping cart (stored in the session cookie) to change a price or quantity. |
| **Root cause** | Trusting client-supplied state for integrity-sensitive values. |
| **Defence** | Session cookie is cryptographically signed by Flask (tamper → invalid session); cart stores only `product_id`+`quantity`; quantity is clamped to stock and prices re-derived. |
| **Where in the code** | `shop.py::_cart_lines`, `shop.py::checkout`, Flask signed sessions. |
| **Evidence** | Self-test check 11; attempt to submit an arbitrary `quantity` is clamped to stock. |

### A9 — Security Logging & Monitoring Failures
| Field | Detail |
|---|---|
| **Attack scenario** | An attacker brute-forces or tampers and the incident goes unnoticed (no record of who did what). |
| **Root cause** | No audit trail. |
| **Defence** | Structured `audit_log` table records security events (login success/failure, lockout, admin actions, CSRF failures, order placement) with timestamp, user, IP and detail; visible in the admin dashboard. |
| **Where in the code** | `security.py::audit`, `db.py` (`audit_log` table), `admin.py::dashboard`. |
| **Evidence** | Admin panel "Recent security events"; events written by every `audit(...)` call. |

### A10 — Mishandling of Exceptional Conditions
| Field | Detail |
|---|---|
| **Attack scenario** | Attacker triggers a 404/500 to read a stack trace with DB paths or internals. |
| **Root cause** | Exposing exception details to the client. |
| **Defence** | Custom generic error pages (400/401/403/404/405/500) with no traceback; the exception is logged server-side only. |
| **Where in the code** | `__init__.py` error handlers, `templates/errors/*.html`. |
| **Evidence** | Self-test check 12 (404 body contains no "Traceback"). |

---

## B. Authentication topics (Lectures 4–5)

| Topic | Attack scenario | Root cause | Defence | Where | Evidence |
|---|---|---|---|---|---|
| **Weak password storage** | Stolen DB → passwords cracked | Fast/unsalted hash | Peppered bcrypt (salt built-in) | `security.py` | test 7 |
| **Brute force / stuffing** | Repeated login guesses | No throttle | Lockout (5) + IP rate-limit | `security.py` | test 9 |
| **User enumeration** | Distinct "no such user" error | Revealing errors | Single generic message | `auth.py::login` | test 10 |
| **Session fixation** | Attacker fixes a session id then victim logs in | Reusing pre-login session | `session.clear()` + fresh token on login | `auth.py::_regenerate_session` | code review |
| **Cookie theft (XSS → session)** | Stolen session cookie replayed | Cookie readable by JS | `HttpOnly` + `SameSite` + CSP | `config.py`, `security.py` | headers (test 1) |
| **Missing MFA** | Password alone is enough | Single factor | Optional TOTP (RFC 6238) with replay prevention | `totp.py`, `auth.py` | test 8 |
| **TOTP replay** | Sniffed code reused within window | No one-time enforcement | `last_totp_counter` rejects reuse | `totp.py::verify` | code review |

---

## C. Software security principles (Lectures 2–3)

| Principle | How SecureShop applies it | Where |
|---|---|---|
| **Least privilege** | Users have `role='user'`; admin actions require `role='admin'`; DB connection has no exposed admin path | `security.py::admin_required`, `admin.py` |
| **Separation of duties** | Admin "user management" vs "order placement" are distinct flows; a customer cannot manage products | `admin.py` vs `shop.py` |
| **Minimize common mechanism** | No shared super-account; per-user sessions and per-user CSRF tokens | `security.py` |
| **Defence in depth** | Validation → parameterised SQL → output encoding → headers → CSRF → logging, all layered | `shop.py`, `security.py` |
| **Fail secure** | Generic error pages, lockout on failure, abort on invalid input | `__init__.py`, `security.py` |
| **Open design** | No security-through-obscurity; algorithm choices documented; only keys are secret | `config.py`, README |
| **Psychological acceptability** | Clear nav, helpful messages, optional (not forced) 2FA, reasonable password rules | templates, `config.py` |

---

## D. Web attacks exercised in self-test

| Attack | Payload / action | Result |
|---|---|---|
| SQL injection (search) | `' OR '1'='1`, `' UNION SELECT 1--`, `" OR 1=1--`, `'; DROP TABLE users;--` | No rows leaked, no error, normal page |
| SQL injection (login) | `admin' OR '1'='1` | 401, generic error |
| Reflected XSS (search) | `<script>alert(1)</script>` | HTML-encoded, script not executed |
| CSRF | state-changing POST without token | 400, action not performed |
| Broken access control | non-admin → `/admin/` | 403 |
| IDOR | read another user's order | 404 |
| Price tampering | place order | server re-derives price from DB |
| Brute force | 6 wrong passwords | account locked (429) |

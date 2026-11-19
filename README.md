# SecureShop

A secure e-commerce web application built with Flask and hardened against the
OWASP Top 10 and modern authentication attacks.

- **Application**: Flask (Python)
- **Database**: SQLite (single-file, zero-config) — see "Database" below
- **Deployment**: see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)

---

## 1. Setup

### Prerequisites
- Python 3.12+ (with `pip`)

### Install & run

```bash
# 1) (recommended) create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 2) install pinned dependencies
pip install -r requirements.txt

# 3) run the application
python run.py
```

Then open **http://127.0.0.1:5000** in a browser.

### Database

SecureShop uses **SQLite** by default — a single-file, serverless database stored
at `instance/secureshop.db`. It requires no database server, which makes local
development simple.

For production, set the `DATABASE_URL` environment variable to a
`postgresql://…` connection string (e.g. a free **Neon** database) and the app
automatically switches to **PostgreSQL**. The parameterised query layer is
identical for both backends, so no application code changes are needed.

The database and the auto-generated secret key are created inside the `instance/`
folder on first run (both are git-ignored).

### Configuration (environment variables)

| Variable                 | Purpose                                            |
|--------------------------|----------------------------------------------------|
| `SECURESHOP_SECRET_KEY`  | Override the auto-generated Flask session key      |
| `SECURESHOP_PEPPER`      | Override the server-side password pepper           |
| `SECURESHOP_HTTPS=1`     | Enable `Secure` cookies + HSTS (use behind TLS)    |
| `SECURESHOP_TRUST_PROXY=1` | Trust reverse-proxy headers (set behind nginx/Render) |
| `SECURESHOP_HOST`/`PORT` | Bind address/port (default `127.0.0.1:5000`)       |
| `SECURESHOP_MAIL_DEV=0`  | Hide in-page confirmation/reset links (no mailer)  |
| `SECURESHOP_ENFORCE_HOURS=1` | Enforce the 08:00–22:00 login window (Lab 5)  |

### Default accounts

| Role  | Username | Password                 | Notes                       |
|-------|----------|--------------------------|-----------------------------|
| Admin | `admin`  | `Admin@SecureShop2026!`  | Full admin panel access     |
| User  | `alice`  | `Alice@SecureShop2026!`  | Normal customer             |
| User  | `bob`    | `Bob@SecureShop2026!`    | Normal customer             |

> Change these passwords (or delete the seeded accounts) before going live.
> Account-confirmation links appear on screen (and in the console) unless you
> configure a real mail server (`SECURESHOP_MAIL_DEV=0`).

---

## 2. One-page architecture overview

```
                 +------------------------------------------------------+
  Browser  <---->|  Flask application (secure_shop package)             |
  (TLS in        |                                                      |
   production)   |  auth.py      registration, login/logout, lockout,   |
                 |                email confirm, optional TOTP 2FA      |
                 |  shop.py      catalogue, cart, coupons/newsletter,   |
                 |                checkout, orders, account             |
                 |  admin.py     admin-only user/product/coupon mgmt    |
                 |  security.py  CSRF, rate-limit, validation, headers, |
                 |                peppered-bcrypt, audit log            |
                 |  totp.py      RFC 6238 one-time passwords            |
                 |  db.py        parameterised SQL access layer         |
                 +------------------------------------------------------+
                                  |
                                  v
                        +--------------------+
                        |  SQLite database  |   (instance/secureshop.db)
                        +--------------------+
```

**Trust boundaries** (from the threat model):

1. **Internet → Web app** — every request is hostile until validated. Handled by
   input validation, output encoding, CSRF tokens, and security headers.
2. **Web app → Database** — all SQL is parameterised; the database is never
   exposed to the client.
3. **User role → Admin role** — every admin route re-checks authorization
   server-side (RBAC + least privilege); no client-side "hidden" admin pages.

**Key design decisions**

- **No client trust.** Prices, totals, stock, and ownership are always
  re-derived server-side. The session cookie only stores `product_id` +
  `quantity`, never a price.
- **Defence in depth.** Multiple independent controls (parameterised SQL +
  validation + encoding + headers + CSRF + rate-limiting + logging) so a single
  failure does not expose the application.
- **Fail secure.** All errors return generic pages; no stack traces or internal
  details leak to the client.
- **Secrets never hard-coded.** The session key and password pepper are generated
  per installation (or supplied via environment).

---

## 3. Security coverage (summary)

The site defends against the full OWASP Top 10 and the authentication topics of
the course. See:

- **[docs/Security_Coverage_Matrix.md](docs/Security_Coverage_Matrix.md)** —
  one row per topic: attack scenario, root cause, defence, where in the code,
  evidence.
- **[docs/Security_Design_Report.md](docs/Security_Design_Report.md)** — threat
  model (STRIDE), assets, entry points, attackers, and the security design.
- **[docs/Attack_Evidence_Report.md](docs/Attack_Evidence_Report.md)** — how each
  attack was attempted and why it fails.
- **[docs/Red_Team_Penetration_Test_Report.md](docs/Red_Team_Penetration_Test_Report.md)** —
  Red Team testing methodology and findings.

| Topic                               | Defence in SecureShop |
|-------------------------------------|-----------------------|
| Broken Access Control               | Server-side RBAC on every admin route + ownership checks on orders |
| Security Misconfiguration           | Strict CSP + security headers, `debug=False`, secrets from env |
| Supply Chain Failures               | Pinned dependencies, no eval of untrusted data |
| Cryptographic Failures              | Peppered bcrypt for passwords, TLS-ready cookie flags |
| Injection (SQL/Command)             | Parameterised SQL everywhere, no shell use, no user file paths |
| Insecure Design                     | Threat model + defence in depth + "no client trust" |
| Authentication Failures             | Lockout, rate-limit, generic errors, optional TOTP MFA |
| Integrity Failures                  | Signed session cookie, server-side price/stock revalidation |
| Logging & Alerting Failures         | Structured `audit_log` of security events (admin view) |
| Mishandling of Exceptional Conditions | Generic error pages, no traceback leakage |

The hands-on **labs** are also covered and mapped in
**[docs/Security_Coverage_Matrix.md](docs/Security_Coverage_Matrix.md#e-lab-topics-labs-1-5)**:

| Lab | Topic | Where in SecureShop |
|---|---|---|
| Lab 1–2 | Business-logic vulnerabilities | `shop.py` (server-side price/stock/coupon/workflow) |
| Lab 3 | 2FA broken logic | `auth.py` (2FA identity bound to the signed session) |
| Lab 4 | Behavioural anomaly detection | `behavior.py` + `static/typing.js` (z-score) |
| Lab 5 | Location, time, passkeys | `risk.py` (haversine, time window) + `passkey.py` (Ed25519) |

---

## 4. Run the security self-tests

Two self-test suites simulate attacks against the application and assert they
fail (this is the "Step 1 — test it the way an attacker would" evidence).

```bash
python tests/test_security.py   # OWASP Top 10 + authentication attacks (22 checks)
python tests/test_labs.py       # Lab 1-5 topics: business logic, 2FA, anomaly, location/time/passkey (21 checks)
```

Expected output: `All security checks passed.` / `All lab-topic checks passed.`

---

## 5. Repository layout

```
SecureShop/
├── run.py                     # development entry point
├── wsgi.py                    # production WSGI entry point
├── render.yaml                # Render (free) one-click deployment blueprint
├── requirements.txt           # pinned application dependencies
├── requirements-prod.txt      # production WSGI server (gunicorn/waitress)
├── secure_shop/               # application package
│   ├── __init__.py            # app factory, error handlers, headers
│   ├── config.py              # configuration & secret handling
│   ├── db.py                  # parameterised SQL access layer + schema
│   ├── security.py            # hashing, CSRF, rate-limit, validation, audit
│   ├── totp.py                # RFC 6238 TOTP
│   ├── behavior.py            # Lab 4: z-score behavioural anomaly detection
│   ├── risk.py                # Lab 5: haversine location + time window
│   ├── passkey.py             # Lab 5: Ed25519 passkey (FIDO2 concept)
│   ├── auth.py                # authentication blueprint
│   ├── shop.py                # customer-facing shop blueprint
│   ├── admin.py               # admin blueprint
│   ├── templates/             # Jinja templates (auto-escaped)
│   └── static/                # CSS + typing.js (keystroke timing) + theme.js (dark/light)
├── tests/
│   ├── test_security.py       # OWASP + auth attack self-tests
│   └── test_labs.py           # Lab 1-5 topic self-tests
└── docs/                      # reports, coverage matrix, deployment & free-hosting guides
```

---

## 6. Deployment

**Want a free host with HTTPS?** See
**[docs/FREE_HOSTING.md](docs/FREE_HOSTING.md)** (Render or PythonAnywhere,
both with automatic HTTPS). Render can be deployed straight from this repo via
[`render.yaml`](render.yaml).

Full self-managed instructions are in
**[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**:

- Production WSGI server (gunicorn on Linux / waitress on Windows)
- Reverse proxy (nginx) + TLS certificate (Let's Encrypt)
- Pointing a domain name at your server
- Environment configuration for production (`SECURESHOP_HTTPS=1`, secrets, mail)

Quick start (production server on the machine):

```bash
pip install -r requirements-prod.txt
# Linux / macOS:
gunicorn -w 3 -b 0.0.0.0:8000 wsgi:app
# Windows:
waitress-serve --listen=0.0.0.0:8000 wsgi:app
```

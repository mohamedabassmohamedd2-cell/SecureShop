# SecureShop — CET431 Software Security Project

A small e-commerce web application designed, built, and hardened to **resist the
vulnerabilities and attacks covered in CET431 Software Security**. Both the
features and the security of the site are graded.

- **Application**: Flask (Python) + SQLite
- **Team**: 3 Red Team members (attack) + 3 Blue Team members (build & defend)

> ⚠️ This is a **teaching/demo** store. There are no real payments and no real
> users. All accounts and products are seeded demo data.

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

The SQLite database and the auto-generated secret key are created inside the
`instance/` folder on first run (both are git-ignored).

### Configuration (environment variables)

| Variable                 | Purpose                                            |
|--------------------------|----------------------------------------------------|
| `SECURESHOP_SECRET_KEY`  | Override the auto-generated Flask session key      |
| `SECURESHOP_PEPPER`      | Override the server-side password pepper           |
| `SECURESHOP_HTTPS=1`     | Enable `Secure` cookies + HSTS (use behind TLS)    |
| `SECURESHOP_HOST`/`PORT` | Bind address/port (default `127.0.0.1:5000`)       |
| `SECURESHOP_MAIL_DEV=0`  | Hide in-page confirmation/reset links (no mailer)  |

### Test accounts

| Role  | Username | Password                 | Notes                       |
|-------|----------|--------------------------|-----------------------------|
| Admin | `admin`  | `Admin@SecureShop2026!`  | Full admin panel access     |
| User  | `alice`  | `Alice@SecureShop2026!`  | Normal customer             |
| User  | `bob`    | `Bob@SecureShop2026!`    | Normal customer             |

> Replace these with your own team accounts before the live demo. Demo
> confirmation links appear on screen (and in the console) because no real mail
> server is configured.

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

---

## 4. Run the security self-tests

The self-test suite simulates attacks against the application and asserts they
fail (this is the "Step 1 — test it the way an attacker would" evidence).

```bash
python tests/test_security.py
```

Expected output: `22 passed, 0 failed`.

---

## 5. Repository layout

```
SecureShop/
├── run.py                     # entry point
├── requirements.txt           # pinned dependencies
├── secure_shop/               # application package
│   ├── __init__.py            # app factory, error handlers, headers
│   ├── config.py              # configuration & secret handling
│   ├── db.py                  # parameterised SQL access layer + schema
│   ├── security.py            # hashing, CSRF, rate-limit, validation, audit
│   ├── totp.py                # RFC 6238 TOTP
│   ├── auth.py                # authentication blueprint
│   ├── shop.py                # customer-facing shop blueprint
│   ├── admin.py               # admin blueprint
│   ├── templates/             # Jinja templates (auto-escaped)
│   └── static/                # CSS
├── tests/
│   └── test_security.py       # attack self-tests
└── docs/                      # reports & coverage matrix
```

---

## 6. Notes for the team

- **Commit history**: each feature/defence is committed under the responsible
  team member's identity (3 Blue Team builders + 3 Red Team testers). Replace
  the placeholder names/emails with your real ones.
- **Live demo**: plan a 10–15 minute walkthrough (features → security → attack
  attempts that fail → admin panel → audit log). Every member should be able to
  explain their own part during Q&A.

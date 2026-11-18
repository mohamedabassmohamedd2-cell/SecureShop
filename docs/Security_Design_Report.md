# Security Design Report — SecureShop

**Course:** CET431 Software Security · Fall 2026
**Application:** SecureShop (small e-commerce website)
**Team:** 3 Red Team + 3 Blue Team members

---

## 1. Scope & purpose

This report describes the security design of **SecureShop**, a small e-commerce
web application built for the CET431 project. SecureShop lets users register and
log in, browse and search a product catalogue, manage a shopping cart, apply
coupon codes, subscribe to a newsletter, check out using store credit, view
their order history, and (for administrators) manage users, products and
coupons.

The site must be **resilient to the vulnerabilities and attacks covered in the
course**. This report presents:

1. the **threat model** — assets, entry points, and attackers;
2. the **security requirements** derived from those threats;
3. the **security architecture** and the controls that satisfy each requirement;
4. the **Security Coverage Matrix** (kept in a separate file, referenced here).

---

## 2. Assets

The starting point for any security discussion is an inventory of what we must
protect.

| Asset | Type | Confidentiality | Integrity | Availability |
|---|---|---|---|---|
| User accounts (credentials) | Data | High — password hashes must never leak or be crackable | High — must not be altered | High |
| Personal data (email, name) | Data | Medium-high | High | Medium |
| Order history & store credit | Data | High — a customer's orders are private | High — credit must not be forged | High |
| Product catalogue & pricing | Data | Low (public) | **High** — prices must not be tampered with | High |
| Coupon codes | Data | Medium | High — discounts must not be forged | Medium |
| Admin functions | Function | High | High | High |
| The application itself | Service | — | High | High (no DoS from trivial input) |
| Audit log | Data | Medium | **High** — must be tamper-evident for accountability | Medium |

---

## 3. Entry points (attack surface)

Every point where an attacker can send input or trigger an action:

| # | Entry point | Inputs | Attack relevance |
|---|---|---|---|
| 1 | `/register` | username, email, full name, password | Mass signup, injection, weak-password | 
| 2 | `/login` | username, password (then TOTP code) | Brute force, enumeration, SQLi |
| 3 | `/` (search & filter) | `q`, `category`, `sort`, `order` | SQLi, reflected XSS |
| 4 | `/cart/add`, `/cart/update` | `product_id`, `quantity` | Business-logic, CSRF |
| 5 | `/checkout` | `coupon_code` | Coupon abuse, price tampering, CSRF |
| 6 | `/newsletter` | `email` | Spam/abuse, stored XSS via admin view |
| 7 | `/account` | `full_name`, `email` | Stored XSS, email enumeration |
| 8 | `/account/2fa` | TOTP code, enable/disable | Replay, logic abuse |
| 9 | `/admin/*` (users, products, coupons) | many | Privilege escalation, CSRF, injection |
| 10 | Every HTTP request (headers) | URL, headers | Clickjacking, header-based attacks |

The design principle applied at **every** entry point: *data crossing a trust
boundary is hostile until validated*.

---

## 4. Attackers

| Attacker | Motivation | Capability |
|---|---|---|
| Script kiddie | Deface / fun | Uses public tools and payloads; low skill |
| Malicious customer | Get free items / steal credit | Logged-in user; can tamper with their own requests |
| Competitor / criminal | Steal customer data | Automated attacks, credential stuffing, targeted phishing |
| Insider (mistaken admin) | Accidental / opportunistic | Has some legitimate access |

The strongest assumed adversary in this exercise is a **malicious customer with
full control of their own browser and traffic** (they can modify any request).
SecureShop therefore never trusts the client for prices, totals, quantities,
roles, or ownership.

---

## 5. Threat model (STRIDE)

STRIDE is used to *identify* threats by category. For each we state the threat in
SecureShop and the countering control.

| STRIDE | Violated property | Threat in SecureShop | Control |
|---|---|---|---|
| **S**poofing | Authentication | Attacker logs in as admin or another user (credential stuffing / session hijack) | Peppered bcrypt, account lockout, rate limiting, session regeneration, optional TOTP MFA, `HttpOnly` cookies |
| **T**ampering | Integrity | Attacker changes a price/quantity in the cart or a request | Server re-derives prices/stock; signed session; parameterised SQL |
| **R**epudiation | Non-repudiation | Attacker (or insider) denies an action | Structured audit log of security events with user/IP/time |
| **I**nformation Disclosure | Confidentiality | Attacker reads another user's order or internal error details | Ownership checks (no IDOR), generic error pages, no stack traces |
| **D**enial of Service | Availability | Attacker floods login or abuses endpoints to break the store | Rate limiting/lockout, input length limits, stock clamps |
| **E**levation of Privilege | Authorization | Customer reaches admin functions | Server-side `admin_required` on every admin route |

The continuous iterative cycle used for each threat:

1. **Plan** — decompose the system (routes + data flows above).
2. **Model** — apply STRIDE per element.
3. **Mitigate** — choose *Mitigate* (most), *Eliminate* (remove risky features),
   or *Accept* (e.g., low-impact public catalogue info).
4. **Validate** — the `tests/test_security.py` suite re-checks each control.

---

## 6. Security requirements → design controls

### 6.1 Authentication & session management (AAL1 + optional AAL2)

- **Passwords** are stored as **peppered bcrypt**: the password is first
  HMAC-SHA256'd with a server-side pepper (kept out of the database), then
  hashed with bcrypt (which adds a per-user salt and is intentionally slow).
  Verification uses a constant-time `bcrypt.checkpw`.
- **Lockout & rate limiting**: after **5 failed attempts** an account is locked
  for 15 minutes; a per-IP throttle caps login attempts; a separate throttle
  caps registrations.
- **User enumeration resistance**: a single generic message
  ("Invalid username or password.") is returned whether the user is unknown, the
  password is wrong, or the account is disabled. A dummy bcrypt hash is verified
  when the user does not exist so response timing does not leak existence.
- **Session fixation**: `_regenerate_session()` clears the session and issues a
  fresh CSRF token whenever the privilege level changes (login, 2FA, logout).
- **Session cookies**: `HttpOnly`, `SameSite=Lax`, and `Secure` (when
  `SECURESHOP_HTTPS=1`), with a 30-minute idle lifetime.
- **Two-factor authentication (optional)**: a self-service RFC 6238 TOTP flow.
  The secret is generated server-side, stored base32, and verified with ±30 s
  clock drift **and** replay prevention (`last_totp_counter`).

### 6.2 Authorization & access control (A1)

- **Role-based access control**: `role` ∈ {`user`, `admin`}. Every admin route
  is wrapped in `admin_required`, which re-checks the database role on every
  request (least privilege).
- **Object-level access**: orders are always fetched with
  `WHERE order_ref = ? AND user_id = ?`, scoped to the session user, so an IDOR
  attempt returns 404 (the object is invisible to the attacker).
- **Account state**: deactivated users (`active=0`) are treated as non-existent
  by `current_user()`, and are rejected at login.

### 6.3 Input validation & injection defence (A5)

- **SQL injection**: the only way to touch the database is through
  `db.query`/`db.execute`, which use parameterised `?` placeholders. User input
  is never string-interpolated into SQL. Dynamic `ORDER BY` columns and
  directions come from a **whitelist** (`ALLOWED_SORTS`, `ALLOWED_ORDERS`,
  `ALLOWED_CATEGORIES`).
- **Command injection / path traversal**: the application never invokes a shell
  (`os.system`/`subprocess`) and never builds file paths from user input, so
  these classes are eliminated rather than merely mitigated.
- **Format validation**: usernames, emails, coupon codes and prices are
  validated against strict whitelist regexes/ranges server-side. Quantities are
  coerced to integers and clamped to stock.

### 6.4 Output encoding & XSS (A5)

- **Template auto-escaping**: every value rendered into Jinja2 templates is
  HTML-escaped by default. No user content is rendered with `|safe`.
- **Content-Security-Policy**: a strict CSP allows scripts/styles only from
  `'self'` and blocks `object`, framing, and other injection vectors, as a
  second layer if a reflection ever occurred.

### 6.5 CSRF

- Every state-changing request (`POST`) requires a synchroniser token stored in
  the session and compared with `hmac.compare_digest` (constant time). The token
  is embedded in forms as a hidden field. Missing or invalid tokens are rejected
  with 400 before the action runs.

### 6.6 Cryptography (A4)

- Passwords: peppered bcrypt (above).
- Session integrity: Flask's signed cookies (HMAC-SHA256 via itsdangerous).
- Secrets: session key and pepper are generated per-installation or supplied via
  environment; never hard-coded in the source.

### 6.7 Security misconfiguration & headers (A2)

- `debug=False` in the entry point; a strict set of security headers is applied
  to every response (CSP, `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`,
  `Permissions-Policy`, `Cache-Control: no-store`, HSTS behind TLS).

### 6.8 Logging & monitoring (A9)

- A structured `audit_log` records security-relevant events (login success and
  failure, lockout, 2FA, CSRF failure, admin actions, order placement,
  newsletter signup) with timestamp, actor, IP, and detail. It is viewable in the
  admin dashboard for incident response and accountability.

### 6.9 Fail secure & exceptional conditions (A10)

- Custom handlers return generic pages for 400/401/403/404/405/500. The 500
  handler logs the exception server-side and shows only a generic message — no
  stack traces or internal paths leak to the client.

### 6.10 Security principles (Lectures 2–3)

- **Least privilege**, **separation of duties**, **minimize common mechanism**,
  **defence in depth**, **fail secure**, **open design**, and **psychological
  acceptability** are applied as summarised in the Coverage Matrix (§C).

---

## 7. Security requirements traceability

| Requirement (from threat) | Control | Verification |
|---|---|---|
| R1 Only admins reach admin functions | `admin_required` | Self-test 5 |
| R2 Users can only read their own orders | ownership-scoped SQL | Self-test 6 |
| R3 Login cannot be brute-forced | lockout + throttle | Self-test 9 |
| R4 Login must not reveal which field failed | generic error | Self-test 10 |
| R5 Passwords un-crackable if DB stolen | peppered bcrypt | Self-test 7 |
| R6 SQL injection fails | parameterised SQL | Self-test 2 |
| R7 Reflected XSS fails | auto-escaping + CSP | Self-test 3 |
| R8 CSRF fails | synchroniser token | Self-test 4 |
| R9 Price tampering fails | server-side pricing | Self-test 11 |
| R10 Errors leak nothing | generic pages | Self-test 12 |
| R11 Optional 2FA strengthens login | TOTP | Self-test 8 |

---

## 8. Residual risk & accepted risks

- **Accepted**: the public catalogue is readable without authentication (by
  design for a storefront); denial-of-service is only partially mitigated (a
  production deployment would add a WAF/CDN and per-endpoint rate limits).
- **Residual**: the TOTP shared secret lives on the server (inherent to TOTP);
  a DB compromise would require rotating secrets. Passkeys (AAL3) are noted as a
  stronger future option but are out of scope for this exercise.
- **Environment note**: TLS termination is assumed to be provided by a reverse
  proxy in production (`SECURESHOP_HTTPS=1`). The app itself enforces the
  cookie/header behaviours that make TLS effective.

---

## 9. References

- OWASP Top 10 (2021) — risk categories A1–A10.
- RFC 4226 (HOTP) and RFC 6238 (TOTP) for the two-factor implementation.
- NIST SP 800-63-4 (Authenticator Assurance Levels) — motivation for the MFA
  design.
- Course study guide (Lectures 1–5) — STRIDE/DREAD, secure SDLC, and the
  security principles applied throughout.

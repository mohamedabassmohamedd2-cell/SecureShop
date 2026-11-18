# Red Team Penetration Test Report — SecureShop

**Target:** SecureShop (in-scope, self-owned application)
**Testers:** Red Team (3 members)
**Methodology:** manual request manipulation + the automated self-test suite
**Rules of engagement:** testing limited to the SecureShop application we own;
no testing of systems we do not own or are not authorized to test.

---

## 1. Scope & objectives

The Red Team attacked SecureShop exactly as an external attacker would, within a
fixed window, and reported every finding: **what was tried, the request used, the
result, and the severity**. The Blue Team then fixed any valid finding and
documented the fix.

**Objective:** determine whether the site is resilient to the vulnerabilities
covered in CET431 (OWASP Top 10 and authentication topics).

---

## 2. Test accounts used

| Account | Role | Used to test |
|---|---|---|
| `admin` | admin | Protected asset (target of escalation attempts) |
| `alice` | user | Normal user, victim of IDOR/CSRF attempts |
| `bob` | user | Normal user, 2FA and lockout tests |

---

## 3. Findings table

Severity scale: **Critical / High / Medium / Low / Informational**. A finding is
"open" until the Blue Team fixes it; a "mitigated" finding is one that was
confirmed fixed.

| # | Finding | What was tried (request) | Result | Severity | Status |
|---|---|---|---|---|---|
| F1 | SQL injection in search | `GET /?q=' OR '1'='1` and 3 other payloads | No injection; parameterised queries | Critical | **Mitigated** (defence in place) |
| F2 | SQL injection in login | `POST /login` username `admin' OR '1'='1` | 401 generic error | Critical | **Mitigated** |
| F3 | Reflected XSS in search | `GET /?q=<script>alert(1)</script>` | Output HTML-encoded; CSP blocks scripts | High | **Mitigated** |
| F4 | CSRF on state-changing actions | `POST /cart/add` without `_csrf_token` | 400; action not performed | High | **Mitigated** |
| F5 | Privilege escalation | non-admin `GET /admin/` | 403 | Critical | **Mitigated** |
| F6 | IDOR on orders | `GET /orders/<admin's ref>` as `alice` | 404; ownership enforced | High | **Mitigated** |
| F7 | Price tampering | submit order after modifying request fields | price re-derived from DB | High | **Mitigated** |
| F8 | Brute force login | 6 wrong passwords then correct password | account locked (429) | High | **Mitigated** |
| F9 | Username enumeration | unknown user vs wrong password | identical error | Medium | **Mitigated** |
| F10 | 2FA bypass / replay | login with correct password; wrong then right TOTP | password alone insufficient; replay prevented | High | **Mitigated** |
| F11 | Information disclosure | `GET /does-not-exist` and forced errors | generic pages, no traceback | Medium | **Mitigated** |
| F12 | Session cookie theft (XSS prerequisite) | inspect `Set-Cookie` | `HttpOnly`, `SameSite`, CSP present | Medium | **Mitigated** |
| F13 | Missing security headers | `GET /` header inspection | CSP, nosniff, frame-deny, referrer, permissions policy | Low | **Mitigated** |

**Outcome:** no exploitable vulnerability was found in the hardened application.
All attempted attacks were blocked by the defences documented in the Security
Coverage Matrix and the Security Design Report.

### Lab-topic findings (Labs 1–5)

| # | Finding | What was tried | Result | Severity | Status |
|---|---|---|---|---|---|
| F14 | Excessive trust in client-side controls | Submit `quantity=9999` | clamped to stock | High | **Mitigated** |
| F15 | Flawed business rules | Reuse a one-use coupon | rejected ("already been used") | Medium | **Mitigated** |
| F16 | Insufficient workflow validation | `GET /checkout` with empty cart | redirected to cart | Medium | **Mitigated** |
| F17 | 2FA broken logic | Supply `username=admin` at the 2FA step | ignored; identity is session-bound | High | **Mitigated** |
| F18 | Anomalous login rhythm | Paste the password (`typing_speed=100`) | flagged as `login_anomaly` | Medium | **Mitigated** |
| F19 | Login outside access window | login at 03:00 with policy on | 403 (blocked) | Medium | **Mitigated** |
| F20 | Passkey forgery / replay | flip signature byte / wrong credential / reuse challenge | all rejected | High | **Mitigated** |

---

## 4. Attack narratives (selected)

### F5 — Privilege escalation via admin panel
1. Log in as `alice` (normal user).
2. Request `GET /admin/`.
3. The server re-checks the role from the database and returns **403 Forbidden**.
4. Attempting `POST /admin/users/1/toggle` is likewise rejected.

→ The admin panel is not merely hidden in the UI; authorization is enforced on
the server (least privilege).

### F6 — Insecure Direct Object Reference
1. As `admin`, place an order and note its `order_ref`.
2. As `alice`, request `GET /orders/<that ref>`.
3. The query is scoped `WHERE order_ref = ? AND user_id = ?` to Alice's id, so no
   row matches and the server returns **404**.

→ The object is invisible to the attacker, which also avoids leaking that the
order exists.

### F8 — Brute force / credential stuffing
1. Submit six consecutive wrong passwords for `bob`.
2. After the 5th failure the account is locked for 15 minutes.
3. The correct password is then rejected with **429** until the lockout expires.

→ Rate limiting and lockout collapse the economics of guessing.

### F10 — Two-factor authentication
1. A 2FA-enabled account that supplies only a correct password is **not**
   authenticated; it is redirected to `/login/2fa`.
2. An incorrect code returns **401**.
3. A correct code (computed from the shared secret per RFC 6238) authenticates.
4. A code cannot be reused because `last_totp_counter` is checked.

→ MFA is a real second factor, not cosmetic.

---

## 5. Recommendations (hardening beyond scope)

Although no finding was exploitable, the Red Team recommends for a production
deployment:

1. **Passkeys (WebAuthn)** instead of TOTP for administrators (AAL3).
2. **Per-endpoint rate limiting** behind a reverse proxy/WAF to harden against
   distributed DoS.
3. **TLS everywhere** (`SECURESHOP_HTTPS=1`) so `Secure` cookies and HSTS apply.
4. **A real mailer** with short-lived, single-use confirmation/reset links
   (currently shown in-page for the demo).
5. **Centralized log shipping/SIEM** so the audit log is monitored, not just
   stored.

---

## 6. Sign-off

| Role | Member | Responsibility |
|---|---|---|
| Red Team 1 | — | Recon & mapping, F1–F4 |
| Red Team 2 | — | Authorization & IDOR, F5–F7 |
| Red Team 3 | — | Authentication & sessions, F8–F13 |
| Blue Team 1 | — | App factory, config, headers |
| Blue Team 2 | — | Auth, hashing, lockout, TOTP |
| Blue Team 3 | — | Shop, checkout, admin, audit log |

*(Replace placeholder member names with the real team before submission.)*

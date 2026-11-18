# Attack Evidence Report — SecureShop

This report records **how each attack was attempted** against SecureShop and the
**evidence that the attack fails**. It complements the automated self-test suite
(`tests/test_security.py`), whose output is reproduced at the end.

Each section shows: the **vulnerable pattern** the course teaches us to avoid,
the **secure pattern** used in SecureShop, and the **observed result** of
attacking the deployed site.

---

## 1. SQL injection

**Vulnerable pattern** (never used in SecureShop):
```python
query = "SELECT * FROM products WHERE name = '" + user_input + "'"
```

**Secure pattern** (used everywhere):
```python
rows = db.query("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",))
```

**Attempts**

| # | Vector | Payload | Result |
|---|---|---|---|
| 1 | Search box | `' OR '1'='1` | Normal search page; no unintended rows returned |
| 2 | Search box | `' UNION SELECT 1--` | No error, no UNION output |
| 3 | Search box | `" OR 1=1--` | Treated as literal text |
| 4 | Search box | `'; DROP TABLE users;--` | `users` table intact; no injection |
| 5 | Login | `admin' OR '1'='1` | 401, "Invalid username or password." |

**Evidence**: `tests/test_security.py` checks 2; the database schema (users,
products, orders) is unchanged after the payloads.

---

## 2. Cross-site scripting (XSS)

**Vulnerable pattern**:
```html
<!-- renders raw user input -->
<p>{{ user_input }}</p>   <!-- auto-escaped in Jinja2, so even this is safe -->
```
The classic mistake is deliberately marking input as safe (`| safe`) or
interpolating into an HTML attribute without encoding.

**Secure pattern**: Jinja2 auto-escaping (on by default) + a strict
Content-Security-Policy that forbids inline scripts.

**Attempts**

| # | Vector | Payload | Result |
|---|---|---|---|
| 1 | Search box | `<script>alert(1)</script>` | Response contains `&lt;script&gt;alert(1)&lt;/script&gt;` — encoded, not executed |

**Evidence**: self-test check 3; no `<script>` tag survives in the response body.

---

## 3. Cross-site request forgery (CSRF)

**Vulnerable pattern**: a state-changing endpoint that acts on any POST, so an
attacker's page can submit `<form action="http://secureshop/checkout">`.

**Secure pattern**: a per-session synchroniser token embedded in every form and
validated server-side with a constant-time compare.

**Attempt**

| # | Vector | Request | Result |
|---|---|---|---|
| 1 | Direct POST | `POST /cart/add` without `_csrf_token` | **400** — "Invalid or missing CSRF token"; cart unchanged |

**Evidence**: self-test check 4.

---

## 4. Broken access control / IDOR

**Vulnerable pattern**:
```python
# fetches any order by id with no ownership check
order = db.get_order(request.args["id"])
```

**Secure pattern**:
```python
order = query("SELECT * FROM orders WHERE order_ref = ? AND user_id = ?",
              (order_ref, current_user()["id"]), one=True)
```

**Attempts**

| # | Vector | Request | Result |
|---|---|---|---|
| 1 | Role escalation | non-admin `GET /admin/` | **403** |
| 2 | IDOR | `alice` requests `admin`'s order `GET /orders/ORD-…` | **404** — object invisible to Alice |

**Evidence**: self-test checks 5 and 6.

---

## 5. Business-logic / price tampering

**Vulnerable pattern**: the client submits a total (or the cart stores prices)
and the server charges it:
```html
<input type="hidden" name="price" value="1.00">
```

**Secure pattern**: the session cart stores only `product_id` + `quantity`;
checkout re-reads the price and stock from the database and computes the total
server-side.

**Attempt**: place an order for product #1 and inspect the recorded line price.

**Result**: the recorded `order_items.price` always equals the database price of
the product (129.99 credit), regardless of any client-submitted value.

**Evidence**: self-test check 11.

---

## 6. Brute force & account lockout

**Vulnerable pattern**: unlimited login attempts with no throttle.

**Secure pattern**: 5 failures → 15-minute account lockout, plus a per-IP rate
limit, plus a generic error.

**Attempt**: submit the correct password after 5 wrong attempts.

**Result**: **429** — "Too many failed attempts. Account temporarily locked."
The correct password is *not* accepted until the lockout expires.

**Evidence**: self-test check 9.

---

## 7. User enumeration

**Vulnerable pattern**:
```python
if user is None:  return "No account with that username"
else:             return "Incorrect password"
```

**Secure pattern**: one message for every failure case, and a dummy bcrypt hash
is verified when the user does not exist to equalize timing.

**Attempt**: log in with a non-existent user vs. a real user with a wrong
password.

**Result**: both return the identical "Invalid username or password." message.

**Evidence**: self-test check 10.

---

## 8. Two-factor authentication bypass / replay

**Vulnerable pattern**: accept the password and skip any second factor, or accept
a TOTP code more than once within its validity window.

**Secure pattern**: after a correct password, a 2FA-enabled account must supply a
valid TOTP code; each code is usable once (`last_totp_counter`).

**Attempts**

| # | Request | Result |
|---|---|---|
| 1 | `POST /login` with correct password (2FA enabled) | **302** to `/login/2fa` — not yet authenticated |
| 2 | `POST /login/2fa` with `000000` | **401** — rejected |
| 3 | `POST /login/2fa` with a valid current code | **302** to the store — authenticated |

**Evidence**: self-test check 8.

---

## 9. Information leakage via error pages

**Vulnerable pattern**: debug mode exposes a stack trace with file paths and SQL.

**Secure pattern**: generic error templates; exception logged server-side only.

**Attempt**: request a non-existent URL and inspect the response.

**Result**: a clean 404 page; the string "Traceback" is absent.

**Evidence**: self-test check 12.

---

## Automated self-test output

```
== SecureShop self-test ==
  [PASS] CSP header present
  [PASS] X-Content-Type-Options: nosniff
  [PASS] X-Frame-Options: DENY
  [PASS] Referrer-Policy set
  [PASS] SQLi in search blocked (' OR '1'='1…)
  [PASS] SQLi in search blocked (' UNION SELECT 1…)
  [PASS] SQLi in search blocked (" OR 1=1--…)
  [PASS] SQLi in search blocked ('; DROP TABLE us…)
  [PASS] SQLi in login blocked
  [PASS] XSS in search is HTML-encoded
  [PASS] CSRF: state-changing POST without token rejected
  [PASS] Non-admin blocked from /admin/
  [PASS] IDOR: cross-user order access blocked
  [PASS] Password hashed with bcrypt
  [PASS] Plaintext password not stored
  [PASS] 2FA: password login redirects to code step
  [PASS] 2FA: wrong code rejected
  [PASS] 2FA: correct code logs in
  [PASS] Account lockout: correct password rejected while locked
  [PASS] Login errors do not reveal which field failed
  [PASS] Order price re-derived from DB (client not trusted)
  [PASS] 404 page is generic (no traceback)

  22 passed, 0 failed
```

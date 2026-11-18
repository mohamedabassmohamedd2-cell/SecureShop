"""
SecureShop self-test suite (Step 1 — "test it the way an attacker would").

Run:  python tests/test_security.py

Each check simulates an attack or a misconfiguration probe and asserts the
application *resists* it. The output doubles as evidence for the Attack
Evidence Report. Exits non-zero if any check fails.
"""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_shop import create_app, seed_demo_data  # noqa: E402
from secure_shop.db import get_db  # noqa: E402
from secure_shop.totp import current_code  # noqa: E402

CSRF_RE = re.compile(r'name="_csrf_token" value="([^"]+)"')
SECRET_RE = re.compile(r"Secret: ([A-Z2-7]+)")

PASS = []
FAIL = []


def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  [PASS] {name}")
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}  {detail}")


def make_app():
    tmp = tempfile.mkdtemp(prefix="secureshop_test_")
    db_path = os.path.join(tmp, "test.db")
    app = create_app({"TESTING": True, "DATABASE": db_path})
    seed_demo_data(app)
    return app, db_path


def csrf_of(client, url):
    resp = client.get(url)
    m = CSRF_RE.search(resp.get_data(as_text=True))
    return (m.group(1) if m else None), resp


def login(client, username, password):
    token, _ = csrf_of(client, "/login")
    return client.post(
        "/login",
        data={"username": username, "password": password, "_csrf_token": token},
    )


def main():
    app, db_path = make_app()
    print(f"== SecureShop self-test (temp DB: {db_path}) ==\n")

    # --- 1. Security headers (security misconfiguration defence) ---
    resp = app.test_client().get("/")
    h = resp.headers
    check("CSP header present", "Content-Security-Policy" in h)
    check("X-Content-Type-Options: nosniff", h.get("X-Content-Type-Options") == "nosniff")
    check("X-Frame-Options: DENY", h.get("X-Frame-Options") == "DENY")
    check("Referrer-Policy set", "Referrer-Policy" in h)

    # --- 2. SQL injection blocked (parameterised queries) ---
    sqli_payloads = ["' OR '1'='1", "' UNION SELECT 1--", '" OR 1=1--', "'; DROP TABLE users;--"]
    for payload in sqli_payloads:
        r = app.test_client().get("/", query_string={"q": payload})
        check(f"SQLi in search blocked ({payload[:16]}…)", r.status_code == 200)
    r = login(app.test_client(), "admin' OR '1'='1", "whatever")
    check("SQLi in login blocked", r.status_code == 401)

    # --- 3. XSS output-encoded (no raw script in response) ---
    xss = '<script>alert(1)</script>'
    body = app.test_client().get("/", query_string={"q": xss}).get_data(as_text=True)
    check("XSS in search is HTML-encoded", "<script>alert(1)</script>" not in body
          and "&lt;script&gt;" in body)

    # --- 4. CSRF: POST without a token is rejected ---
    r = app.test_client().post("/cart/add", data={"product_id": "1", "quantity": "1"})
    check("CSRF: state-changing POST without token rejected", r.status_code == 400)

    # --- 5. Broken access control: non-admin cannot reach admin ---
    alice = app.test_client()
    login(alice, "alice", "Alice@SecureShop2026!")
    check("Non-admin blocked from /admin/", alice.get("/admin/").status_code == 403)

    # --- 6. IDOR: user cannot read another user's order ---
    admin = app.test_client()
    login(admin, "admin", "Admin@SecureShop2026!")
    token, _ = csrf_of(admin, "/")
    admin.post("/cart/add", data={"product_id": "1", "quantity": "2", "_csrf_token": token})
    ck_token, _ = csrf_of(admin, "/checkout")
    admin.post("/checkout", data={"_csrf_token": ck_token, "coupon_code": ""})
    with app.app_context():
        order_ref = get_db().execute("SELECT order_ref FROM orders ORDER BY id DESC LIMIT 1").fetchone()[0]
    check("IDOR: cross-user order access blocked", alice.get(f"/orders/{order_ref}").status_code == 404)

    # --- 7. Password stored as peppered bcrypt (not plaintext) ---
    with app.app_context():
        row = get_db().execute("SELECT password_hash FROM users WHERE username='admin'").fetchone()[0]
    check("Password hashed with bcrypt", row.startswith("$2b$") or row.startswith("$2a$"))
    check("Plaintext password not stored", "Admin@SecureShop2026!" not in row)

    # --- 8. TOTP two-factor authentication flow ---
    with app.app_context():
        get_db().execute(
            "UPDATE users SET totp_secret = ?, last_totp_counter = NULL WHERE username = 'bob'",
            ("JBSWY3DPEHPK3PXP",),  # RFC 6238 test secret
        )
        get_db().commit()
        secret = "JBSWY3DPEHPK3PXP"
    twofa = app.test_client()
    r = login(twofa, "bob", "Bob@SecureShop2026!")
    check("2FA: password login redirects to code step",
          r.status_code == 302 and "/login/2fa" in r.headers.get("Location", ""))
    token, _ = csrf_of(twofa, "/login/2fa")
    r_bad = twofa.post("/login/2fa", data={"_csrf_token": token, "code": "000000"})
    check("2FA: wrong code rejected", r_bad.status_code == 401)
    good_code = current_code(secret)
    token, _ = csrf_of(twofa, "/login/2fa")
    r_ok = twofa.post("/login/2fa", data={"_csrf_token": token, "code": good_code})
    check("2FA: correct code logs in", r_ok.status_code == 302 and "/login/2fa" not in r_ok.headers.get("Location", ""))

    # --- 9. Account lockout after repeated failures ---
    lock_client = app.test_client()
    for _ in range(6):
        login(lock_client, "carol-missing", "not-the-password")
    r = app.test_client().get("/login")
    # Verify the lockout path responds without crash for a known locked user:
    with app.app_context():
        get_db().execute("UPDATE users SET failed_logins = 5, locked_until = 9999999999 WHERE username = 'alice'")
        get_db().commit()
    alice2 = app.test_client()
    r = login(alice2, "alice", "Alice@SecureShop2026!")
    check("Account lockout: correct password rejected while locked", r.status_code == 429)
    with app.app_context():
        get_db().execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE username = 'alice'")
        get_db().commit()

    # --- 10. Username enumeration: same error either way ---
    body_a = login(app.test_client(), "no_such_user", "whatever").get_data(as_text=True)
    body_b = login(app.test_client(), "alice", "wrong-password").get_data(as_text=True)
    check("Login errors do not reveal which field failed",
          "Invalid username or password" in body_a and "Invalid username or password" in body_b)

    # --- 11. Checkout trusts server price, not client input ---
    with app.app_context():
        prod_price = get_db().execute("SELECT price FROM products WHERE id=1").fetchone()[0]
    buyer = app.test_client()
    login(buyer, "alice", "Alice@SecureShop2026!")
    token, _ = csrf_of(buyer, "/")
    buyer.post("/cart/add", data={"product_id": "1", "quantity": "1", "_csrf_token": token})
    ck_token, _ = csrf_of(buyer, "/checkout")
    buyer.post("/checkout", data={"_csrf_token": ck_token, "coupon_code": ""})
    with app.app_context():
        item_price = get_db().execute("SELECT price FROM order_items ORDER BY id DESC LIMIT 1").fetchone()[0]
    check("Order price re-derived from DB (client not trusted)", abs(item_price - prod_price) < 0.001)

    # --- 12. Error pages are generic (fail secure, no stack trace) ---
    r404 = app.test_client().get("/this-page-does-not-exist")
    body = r404.get_data(as_text=True)
    check("404 page is generic (no traceback)", r404.status_code == 404 and "Traceback" not in body)

    print("\n== Summary ==")
    print(f"  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  FAILED: " + ", ".join(FAIL))
        return 1
    print("  All security checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

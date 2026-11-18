"""
Lab-topic self-tests (Labs 1-5).

Run:  python tests/test_labs.py

Covers the hands-on lab content:
  Lab 1-2  Business-logic vulnerabilities (excessive trust in client controls,
           flawed business rules, insufficient workflow validation)
  Lab 3    2FA broken logic
  Lab 4    Behavioural anomaly detection (z-score)
  Lab 5    Location, time window, and passkeys

Exits non-zero if any check fails.
"""
import os
import re
import sys
import tempfile
import time as _time
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secure_shop import create_app, seed_demo_data  # noqa: E402
from secure_shop.db import get_db  # noqa: E402
from secure_shop import behavior, risk, passkey  # noqa: E402

CSRF_RE = re.compile(r'name="_csrf_token" value="([^"]+)"')
PASS = []
FAIL = []


def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  [PASS] {name}")
    else:
        FAIL.append(name)
        print(f"  [FAIL] {name}  {detail}")


def make_app(extra=None):
    tmp = tempfile.mkdtemp(prefix="ss_labs_")
    cfg = {"TESTING": True, "DATABASE": os.path.join(tmp, "test.db")}
    if extra:
        cfg.update(extra)
    app = create_app(cfg)
    seed_demo_data(app)
    return app


def csrf_of(client, url):
    m = CSRF_RE.search(client.get(url).get_data(as_text=True))
    return m.group(1) if m else None


def login(client, username, password, extra=None):
    data = {"username": username, "password": password, "_csrf_token": csrf_of(client, "/login")}
    if extra:
        data.update(extra)
    return client.post("/login", data=data)


def main():
    app = make_app()
    print("== SecureShop lab-topic self-tests ==\n")

    # ---------------- Lab 4: z-score unit tests ----------------
    rows = [
        {"typing_speed": 6.3, "gap_mean": 0.15, "hour": 10},
        {"typing_speed": 6.1, "gap_mean": 0.16, "hour": 10},
        {"typing_speed": 6.4, "gap_mean": 0.14, "hour": 11},
        {"typing_speed": 6.2, "gap_mean": 0.15, "hour": 10},
        {"typing_speed": 6.0, "gap_mean": 0.17, "hour": 10},
    ]
    profile = behavior.build_profile(rows)
    normal = behavior.anomaly_score({"typing_speed": 6.3, "gap_mean": 0.15, "hour": 10}, profile)
    paste = behavior.anomaly_score({"typing_speed": 47.5, "gap_mean": 0.02, "hour": 10}, profile)
    check("Lab4: natural typing -> low anomaly score", normal is not None and normal < 3.0, f"score={normal}")
    check("Lab4: pasted typing -> high anomaly score", paste is not None and paste > 3.0, f"score={paste}")
    check("Lab4: decide() flags only past threshold",
          behavior.decide(normal) is False and behavior.decide(paste) is True)

    # ---------------- Lab 4: integration (login flags anomaly) ----------------
    with app.app_context():
        uid = get_db().execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
        for _ in range(5):
            get_db().execute(
                "INSERT INTO login_behavior (user_id, hour, typing_speed, gap_mean) VALUES (?, 10, 6.0, 0.15)",
                (uid,))
        get_db().commit()
    c = app.test_client()
    login(c, "alice", "Alice@SecureShop2026!", {"typing_speed": "100", "gap_mean": "0.02"})
    with app.app_context():
        ev = get_db().execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE event_type='login_anomaly' AND username='alice'").fetchone()[0]
    check("Lab4: anomalous login is flagged in audit log", ev >= 1)

    # ---------------- Lab 5: location & time unit tests ----------------
    home = (30.0444, 31.2357)
    d_home = risk.haversine_km(*home, *home)
    d_near = risk.haversine_km(*home, 30.0131, 31.2089)
    d_london = risk.haversine_km(*home, 51.5074, -0.1278)
    check("Lab5: haversine home = ~0 km", d_home < 0.01, f"got {d_home}")
    check("Lab5: haversine nearby = ~4.3 km", 3.0 < d_near < 6.0, f"got {d_near}")
    check("Lab5: haversine London = ~3511 km", 3300 < d_london < 3700, f"got {d_london}")
    check("Lab5: location_ok inside radius", risk.location_ok(*home, 30.0131, 31.2089, 50))
    check("Lab5: location_ok rejects London", not risk.location_ok(*home, 51.5074, -0.1278, 50))
    check("Lab5: time window 08:00-22:00", risk.time_allowed(8) and risk.time_allowed(21) and not risk.time_allowed(22) and not risk.time_allowed(3))

    # ---------------- Lab 5: time-window integration ----------------
    app_win = make_app({"ENFORCE_LOGIN_HOURS": True, "LOGIN_WINDOW_START": 8, "LOGIN_WINDOW_END": 22})
    with mock.patch("time.localtime", return_value=_time.struct_time((2026, 1, 1, 3, 0, 0, 0, 1, 0))):
        r = login(app_win.test_client(), "alice", "Alice@SecureShop2026!")
        check("Lab5: login blocked outside window (03:00)", r.status_code == 403)
    with mock.patch("time.localtime", return_value=_time.struct_time((2026, 1, 1, 10, 0, 0, 0, 1, 0))):
        r = login(app_win.test_client(), "alice", "Alice@SecureShop2026!")
        check("Lab5: login allowed inside window (10:00)", r.status_code == 302)

    # ---------------- Lab 5: passkey unit tests ----------------
    key = passkey.register()
    challenge = passkey.make_challenge()
    sig = passkey.sign(key["private_key"], challenge)
    check("Lab5: genuine passkey signature accepted",
          passkey.passkey_allowed(key["public_key"], key["credential_id"], key["credential_id"], sig, challenge))
    flipped = bytearray(sig); flipped[0] ^= 0x01
    check("Lab5: flipped signature rejected",
          not passkey.passkey_allowed(key["public_key"], key["credential_id"], key["credential_id"], bytes(flipped), challenge))
    check("Lab5: wrong credential id rejected",
          not passkey.passkey_allowed(key["public_key"], key["credential_id"], b"\x00" * 16, sig, challenge))
    check("Lab5: signature for another challenge rejected",
          not passkey.passkey_allowed(key["public_key"], key["credential_id"], key["credential_id"], sig, passkey.make_challenge()))

    # ---------------- Lab 3: 2FA broken logic ----------------
    r = app.test_client().get("/login/2fa")
    check("Lab3: cannot reach /login/2fa without pending auth",
          r.status_code == 302 and "/login" in r.headers.get("Location", ""))
    c2 = app.test_client()
    csrf_of(c2, "/login")
    r = c2.post("/login/2fa", data={"username": "admin", "code": "000000",
                                    "_csrf_token": csrf_of(c2, "/login")})
    check("Lab3: 2FA step ignores client-supplied username (session-bound)",
          r.status_code == 302 and "/login" in r.headers.get("Location", ""))

    # ---------------- Lab 1-2: business logic ----------------
    with app.app_context():
        get_db().execute("INSERT INTO coupons (code, discount_percent, max_uses) VALUES ('ONCE10', 10, 1)")
        get_db().execute("UPDATE users SET store_credit = 100000 WHERE username='alice'")
        get_db().commit()
    buyer = app.test_client()
    login(buyer, "alice", "Alice@SecureShop2026!")
    # empty-cart workflow: cannot check out with an empty cart
    r = buyer.get("/checkout")
    check("Lab2: empty-cart checkout redirected", r.status_code == 302 and "/cart" in r.headers.get("Location", ""))
    # first coupon use succeeds
    buyer.post("/cart/add", data={"product_id": "11", "quantity": "1", "_csrf_token": csrf_of(buyer, "/")})
    buyer.post("/checkout", data={"_csrf_token": csrf_of(buyer, "/checkout"), "coupon_code": "ONCE10"})
    # second use must fail (flawed business-rule defence)
    buyer.post("/cart/add", data={"product_id": "11", "quantity": "1", "_csrf_token": csrf_of(buyer, "/")})
    r = buyer.post("/checkout", data={"_csrf_token": csrf_of(buyer, "/checkout"), "coupon_code": "ONCE10"})
    body = r.get_data(as_text=True)
    check("Lab2: one-use coupon rejected on reuse", r.status_code == 200 and "already been used" in body)
    # excessive quantity is clamped to stock (excessive trust in client controls)
    qbuyer = app.test_client()
    login(qbuyer, "alice", "Alice@SecureShop2026!")
    qbuyer.post("/cart/add", data={"product_id": "12", "quantity": "9999", "_csrf_token": csrf_of(qbuyer, "/")})
    qbuyer.post("/checkout", data={"_csrf_token": csrf_of(qbuyer, "/checkout"), "coupon_code": ""})
    with app.app_context():
        qty = get_db().execute("SELECT quantity FROM order_items ORDER BY id DESC LIMIT 1").fetchone()[0]
        stock = get_db().execute("SELECT stock FROM products WHERE id=12").fetchone()[0]
    check("Lab1: absurd quantity clamped to stock", qty == 10 and stock == 0, f"qty={qty} stock={stock}")

    print("\n== Summary ==")
    print(f"  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  FAILED: " + ", ".join(FAIL))
        return 1
    print("  All lab-topic checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

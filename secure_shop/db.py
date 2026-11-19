"""Database access layer for SecureShop.

Supports two backends:

- **SQLite** (default, local development) — file at ``DATABASE``.
- **PostgreSQL** (production / free Neon tier) — set ``DATABASE_URL`` to a
  ``postgresql://...`` connection string.

All SQL uses parameterised queries. User input is *never* string-interpolated
into a SQL statement — this is the core defence against SQL injection. The same
``query()`` / ``execute()`` API is used by the whole application regardless of
backend.
"""
import sqlite3

from flask import current_app, g

# --------------------------------------------------------------------------- #
# Schemas (SQLite and PostgreSQL dialects)
# --------------------------------------------------------------------------- #
SCHEMA_SQLITE = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT    UNIQUE NOT NULL,
    email               TEXT    UNIQUE NOT NULL,
    full_name           TEXT    NOT NULL DEFAULT '',
    password_hash       TEXT    NOT NULL,
    role                TEXT    NOT NULL DEFAULT 'user',
    store_credit        REAL    NOT NULL DEFAULT 0,
    email_confirmed     INTEGER NOT NULL DEFAULT 0,
    email_confirm_token TEXT,
    totp_secret         TEXT,
    last_totp_counter   INTEGER,
    failed_logins       INTEGER NOT NULL DEFAULT 0,
    locked_until        INTEGER,
    newsletter          INTEGER NOT NULL DEFAULT 0,
    active              INTEGER NOT NULL DEFAULT 1,
    created_at          TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL,
    price       REAL    NOT NULL CHECK (price >= 0),
    category    TEXT    NOT NULL,
    stock       INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS orders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    order_ref   TEXT    UNIQUE NOT NULL,
    total       REAL    NOT NULL,
    coupon_code TEXT,
    status      TEXT    NOT NULL DEFAULT 'confirmed',
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS order_items (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id   INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL,
    name       TEXT    NOT NULL,
    price      REAL    NOT NULL,
    quantity   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS coupons (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    code             TEXT    UNIQUE NOT NULL,
    discount_percent INTEGER NOT NULL CHECK (discount_percent BETWEEN 0 AND 100),
    active           INTEGER NOT NULL DEFAULT 1,
    max_uses         INTEGER,
    times_used       INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT    NOT NULL DEFAULT (datetime('now')),
    event_type TEXT    NOT NULL,
    username   TEXT,
    ip         TEXT,
    detail     TEXT
);

CREATE TABLE IF NOT EXISTS login_throttle (
    identifier      TEXT PRIMARY KEY,   -- client IP or account key
    failed_count    INTEGER NOT NULL DEFAULT 0,
    first_failed_at INTEGER,
    locked_until    INTEGER
);

CREATE TABLE IF NOT EXISTS login_behavior (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    ts            TEXT    NOT NULL DEFAULT (datetime('now')),
    hour          INTEGER NOT NULL,
    typing_speed  REAL,
    gap_mean      REAL
);
"""

SCHEMA_POSTGRES = """
CREATE TABLE IF NOT EXISTS users (
    id                  SERIAL PRIMARY KEY,
    username            TEXT UNIQUE NOT NULL,
    email               TEXT UNIQUE NOT NULL,
    full_name           TEXT NOT NULL DEFAULT '',
    password_hash       TEXT NOT NULL,
    role                TEXT NOT NULL DEFAULT 'user',
    store_credit        DOUBLE PRECISION NOT NULL DEFAULT 0,
    email_confirmed     INTEGER NOT NULL DEFAULT 0,
    email_confirm_token TEXT,
    totp_secret         TEXT,
    last_totp_counter   INTEGER,
    failed_logins       INTEGER NOT NULL DEFAULT 0,
    locked_until        INTEGER,
    newsletter          INTEGER NOT NULL DEFAULT 0,
    active              INTEGER NOT NULL DEFAULT 1,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL,
    price       DOUBLE PRECISION NOT NULL CHECK (price >= 0),
    category    TEXT NOT NULL,
    stock       INTEGER NOT NULL DEFAULT 0 CHECK (stock >= 0),
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    order_ref   TEXT UNIQUE NOT NULL,
    total       DOUBLE PRECISION NOT NULL,
    coupon_code TEXT,
    status      TEXT NOT NULL DEFAULT 'confirmed',
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS order_items (
    id         SERIAL PRIMARY KEY,
    order_id   INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL,
    name       TEXT NOT NULL,
    price      DOUBLE PRECISION NOT NULL,
    quantity   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS coupons (
    id               SERIAL PRIMARY KEY,
    code             TEXT UNIQUE NOT NULL,
    discount_percent INTEGER NOT NULL CHECK (discount_percent BETWEEN 0 AND 100),
    active           INTEGER NOT NULL DEFAULT 1,
    max_uses         INTEGER,
    times_used       INTEGER NOT NULL DEFAULT 0,
    created_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         SERIAL PRIMARY KEY,
    ts         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    username   TEXT,
    ip         TEXT,
    detail     TEXT
);

CREATE TABLE IF NOT EXISTS login_throttle (
    identifier      TEXT PRIMARY KEY,
    failed_count    INTEGER NOT NULL DEFAULT 0,
    first_failed_at INTEGER,
    locked_until    INTEGER
);

CREATE TABLE IF NOT EXISTS login_behavior (
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    ts            TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    hour          INTEGER NOT NULL,
    typing_speed  DOUBLE PRECISION,
    gap_mean      DOUBLE PRECISION
);
"""


def _is_postgres():
    url = current_app.config.get("DATABASE_URL") or ""
    return url.startswith("postgres://") or url.startswith("postgresql://")


def _translate(sql):
    """SQLite uses `?` placeholders; psycopg2 uses `%s`. This app never uses a
    literal `?` inside a SQL string, so a plain replacement is safe."""
    if _is_postgres():
        return sql.replace("?", "%s")
    return sql


def get_db():
    if "db" not in g:
        if _is_postgres():
            import psycopg2
            g.db = psycopg2.connect(current_app.config["DATABASE_URL"])
        else:
            g.db = sqlite3.connect(current_app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    with app.app_context():
        db = get_db()
        if _is_postgres():
            for stmt in (s.strip() for s in SCHEMA_POSTGRES.split(";") if s.strip()):
                db.cursor().execute(stmt)
            db.commit()
        else:
            db.executescript(SCHEMA_SQLITE)
            db.commit()


def query(sql, args=(), one=False):
    """Run a parameterised SELECT and return rows (or a single row)."""
    db = get_db()
    sql = _translate(sql)
    if _is_postgres():
        import psycopg2.extras
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql, args)
        rows = cur.fetchall()
        cur.close()
    else:
        cur = db.execute(sql, args)
        rows = cur.fetchall()
        cur.close()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    """Run a parameterised INSERT/UPDATE/DELETE and commit."""
    db = get_db()
    sql = _translate(sql)
    if _is_postgres():
        cur = db.cursor()
        cur.execute(sql, args)
        db.commit()
        cur.close()
    else:
        cur = db.execute(sql, args)
        db.commit()
    return cur

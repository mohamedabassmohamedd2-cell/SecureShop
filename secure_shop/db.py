"""Database access layer for SecureShop.

All SQL uses parameterised queries (`?` placeholders). User input is *never*
string-interpolated into a SQL statement — this is the core defence against
SQL injection.
"""
import sqlite3
import os
from flask import current_app, g

SCHEMA = """
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


def get_db():
    if "db" not in g:
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
        db.executescript(SCHEMA)
        db.commit()


def query(sql, args=(), one=False):
    """Run a parameterised SELECT and return rows (or a single row)."""
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    """Run a parameterised INSERT/UPDATE/DELETE and commit."""
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur

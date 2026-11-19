"""SecureShop application factory."""
import os

from flask import Flask, g, render_template

from . import db
from .config import Config
from .security import apply_security_headers


def seed_demo_data(app):
    """Seed the database with demo users, products and a coupon on first run.

    Credentials are documented in docs/README.md. Passwords are hashed with the
    same peppered-bcrypt path used by the application.
    """
    from .db import execute, query
    from .security import hash_password

    with app.app_context():
        if query("SELECT id FROM users LIMIT 1"):
            return

        # Demo accounts. Admin is the Blue Team's protected asset.
        execute(
            "INSERT INTO users (username, email, full_name, password_hash, role, store_credit,"
            " email_confirmed) VALUES (?, ?, ?, ?, ?, ?, 1)",
            ("admin", "admin@secureshop.test", "Shop Administrator",
             hash_password("Admin@SecureShop2026!"), "admin", 9999.0),
        )
        execute(
            "INSERT INTO users (username, email, full_name, password_hash, role, store_credit,"
            " email_confirmed) VALUES (?, ?, ?, ?, ?, ?, 1)",
            ("alice", "alice@example.com", "Alice Customer",
             hash_password("Alice@SecureShop2026!"), "user", 500.0),
        )
        execute(
            "INSERT INTO users (username, email, full_name, password_hash, role, store_credit,"
            " email_confirmed) VALUES (?, ?, ?, ?, ?, ?, 1)",
            ("bob", "bob@example.com", "Bob Customer",
             hash_password("Bob@SecureShop2026!"), "user", 250.0),
        )

        products = [
            ("Aurora Wireless Headphones", "Over-ear Bluetooth headphones with active noise cancelling.", 129.99, "electronics", 25),
            ("Nimbus Mechanical Keyboard", "RGB mechanical keyboard with hot-swappable switches.", 89.50, "electronics", 40),
            ("PocketBook e-Reader", "6-inch e-ink reader with front light and 8GB storage.", 119.00, "electronics", 15),
            ("Clean Code", "A handbook of agile software craftsmanship by Robert C. Martin.", 34.99, "books", 60),
            ("Designing Secure Software", "Practical patterns for building trustworthy software.", 42.00, "books", 30),
            ("The Web Application Hacker's Handbook", "Finding and exploiting security flaws.", 45.00, "books", 20),
            ("Everyday Cotton T-Shirt", "Soft, breathable 100% cotton t-shirt, unisex fit.", 18.00, "clothing", 120),
            ("Trail Running Jacket", "Lightweight waterproof jacket for all seasons.", 74.95, "clothing", 35),
            ("Ceramic Pour-Over Set", "Handcrafted ceramic dripper and 600ml server.", 39.50, "home", 18),
            ("Scented Soy Candle Trio", "Three 8oz soy candles in seasonal scents.", 24.00, "home", 50),
            ("Wooden Puzzle Cube", "Classic 3x3 puzzle cube with smooth turning.", 9.99, "toys", 200),
            ("Robot Coding Kit", "Build and program a small robot with 12 projects.", 99.00, "toys", 10),
        ]
        for name, desc, price, cat, stock in products:
            execute(
                "INSERT INTO products (name, description, price, category, stock) VALUES (?, ?, ?, ?, ?)",
                (name, desc, price, cat, stock),
            )

        execute(
            "INSERT INTO coupons (code, discount_percent, max_uses) VALUES (?, 20, 100)",
            ("STUDENT20",),
        )


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    config = Config()
    config.ensure_secrets()
    app.config.from_object(config)
    if test_config:
        app.config.update(test_config)

    db.init_db(app)

    # When running behind a reverse proxy (nginx, Render, etc.), trust the
    # X-Forwarded-For/Proto/Host headers so request.is_secure, HSTS, and the
    # client-IP used for rate limiting all reflect the real client.
    if app.config.get("TRUST_PROXY"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    # Register blueprints.
    from . import auth, shop, admin
    app.register_blueprint(auth.bp)
    app.register_blueprint(shop.bp)
    app.register_blueprint(admin.bp)

    # Jinja helpers for templates.
    from .security import current_user
    app.jinja_env.globals["current_user"] = current_user
    app.jinja_env.globals["csrf_token"] = _csrf_token_for_template
    app.jinja_env.filters["money"] = lambda v: f"{v:,.2f}"

    @app.before_request
    def set_dev_flags():
        g.DEV_CONFIRM_LINKS = app.config["SHOW_CONFIRM_LINKS"]

    @app.after_request
    def add_security_headers(response):
        return apply_security_headers(response)

    # ---- Fail secure / generic errors (no stack traces or internals) ----
    @app.errorhandler(400)
    def bad_request(e):
        return render_template("errors/400.html"), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return render_template("errors/401.html"), 401

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(e):
        from flask import request
        return (f"DIAG path={request.path!r} script_root={request.script_root!r} "
                f"path_info={request.environ.get('PATH_INFO')!r} "
                f"script_name={request.environ.get('SCRIPT_NAME')!r}"), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return render_template("errors/405.html"), 405

    @app.errorhandler(500)
    def internal_error(e):
        app.logger.exception("Unhandled error")
        return render_template("errors/500.html"), 500

    @app.teardown_appcontext
    def teardown(e):
        db.close_db(e)

    if not app.config.get("TESTING"):
        seed_demo_data(app)

    return app


def _csrf_token_for_template():
    from flask import session
    import secrets
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token

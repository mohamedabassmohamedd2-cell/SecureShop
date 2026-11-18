"""Admin panel: manage users, products and coupons, and view the audit log.

Every route is guarded server-side by admin_required (broken access control /
least privilege). No client-side "hidden" admin pages are relied upon.
"""
from flask import (
    Blueprint, abort, flash, redirect, render_template, request, url_for,
)

from .db import execute, query
from .security import (
    admin_required, audit, clean_int, csrf_protect, current_user,
    hash_password, valid_coupon_code, valid_email, valid_price, valid_username,
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@admin_required
def dashboard():
    stats = {
        "users": query("SELECT COUNT(*) AS n FROM users")[0]["n"],
        "products": query("SELECT COUNT(*) AS n FROM products")[0]["n"],
        "orders": query("SELECT COUNT(*) AS n FROM orders")[0]["n"],
        "coupons": query("SELECT COUNT(*) AS n FROM coupons")[0]["n"],
    }
    recent = query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 20")
    return render_template("admin/dashboard.html", stats=stats, recent=recent)


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
@bp.route("/users")
@admin_required
def users():
    rows = query("SELECT * FROM users ORDER BY id")
    return render_template("admin/users.html", users=rows)


@bp.route("/users/<int:user_id>/toggle", methods=("POST",))
@admin_required
@csrf_protect
def toggle_user(user_id):
    u = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if u is None:
        abort(404)
    if u["id"] == current_user()["id"]:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin.users"))
    new_active = 0 if u["active"] else 1
    execute("UPDATE users SET active = ? WHERE id = ?", (new_active, user_id))
    audit("admin_user_toggle", username=current_user()["username"],
          detail=f"user={u['username']} active={new_active}")
    flash(f"User “{u['username']}” {'activated' if new_active else 'deactivated'}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/role", methods=("POST",))
@admin_required
@csrf_protect
def set_role(user_id):
    u = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if u is None:
        abort(404)
    role = request.form.get("role")
    if role not in ("user", "admin"):
        abort(400)
    if u["id"] == current_user()["id"] and role != "admin":
        flash("You cannot demote your own account.", "error")
        return redirect(url_for("admin.users"))
    execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    audit("admin_role_change", username=current_user()["username"],
          detail=f"user={u['username']} role={role}")
    flash(f"Role for “{u['username']}” set to {role}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/credit", methods=("POST",))
@admin_required
@csrf_protect
def set_credit(user_id):
    u = query("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if u is None:
        abort(404)
    amount = request.form.get("amount")
    if not valid_price(amount, minimum=0, maximum=1_000_000):
        abort(400)
    execute("UPDATE users SET store_credit = ? WHERE id = ?", (float(amount), user_id))
    audit("admin_credit_change", username=current_user()["username"],
          detail=f"user={u['username']} credit={amount}")
    flash(f"Store credit for “{u['username']}” updated.", "success")
    return redirect(url_for("admin.users"))


# --------------------------------------------------------------------------- #
# Products
# --------------------------------------------------------------------------- #
@bp.route("/products")
@admin_required
def products():
    rows = query("SELECT * FROM products ORDER BY id")
    return render_template("admin/products.html", products=rows)


@bp.route("/products/new", methods=("GET", "POST"))
@admin_required
@csrf_protect
def new_product():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        category = (request.form.get("category") or "").strip().lower()
        price = request.form.get("price")
        stock = clean_int(request.form.get("stock"), default=0, minimum=0, maximum=1_000_000)
        errors = []
        if not (1 <= len(name) <= 120):
            errors.append("Product name is required (1-120 chars).")
        if not (1 <= len(description) <= 2000):
            errors.append("Description is required (1-2000 chars).")
        if category not in ("electronics", "books", "clothing", "home", "toys"):
            errors.append("Choose a valid category.")
        if not valid_price(price):
            errors.append("Enter a valid price.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("admin/product_form.html", name=name,
                                   description=description, category=category,
                                   price=price, stock=stock), 400
        execute(
            "INSERT INTO products (name, description, price, category, stock) VALUES (?, ?, ?, ?, ?)",
            (name, description, float(price), category, stock),
        )
        audit("admin_product_add", username=current_user()["username"], detail=name)
        flash("Product added.", "success")
        return redirect(url_for("admin.products"))
    return render_template("admin/product_form.html")


@bp.route("/products/<int:product_id>/toggle", methods=("POST",))
@admin_required
@csrf_protect
def toggle_product(product_id):
    p = query("SELECT * FROM products WHERE id = ?", (product_id,), one=True)
    if p is None:
        abort(404)
    new_active = 0 if p["active"] else 1
    execute("UPDATE products SET active = ? WHERE id = ?", (new_active, product_id))
    audit("admin_product_toggle", username=current_user()["username"],
          detail=f"product={p['name']} active={new_active}")
    flash(f"Product “{p['name']}” {'activated' if new_active else 'deactivated'}.", "success")
    return redirect(url_for("admin.products"))


# --------------------------------------------------------------------------- #
# Coupons
# --------------------------------------------------------------------------- #
@bp.route("/coupons")
@admin_required
def coupons():
    rows = query("SELECT * FROM coupons ORDER BY id DESC")
    return render_template("admin/coupons.html", coupons=rows)


@bp.route("/coupons/new", methods=("POST",))
@admin_required
@csrf_protect
def new_coupon():
    code = (request.form.get("code") or "").strip().upper()
    percent = clean_int(request.form.get("discount_percent"), default=0, minimum=1, maximum=100)
    max_uses_raw = (request.form.get("max_uses") or "").strip()
    max_uses = clean_int(max_uses_raw, default=1, minimum=1, maximum=1_000_000) if max_uses_raw else None
    if not valid_coupon_code(code):
        flash("Coupon code must be 3-24 letters, numbers or dashes.", "error")
        return redirect(url_for("admin.coupons"))
    if query("SELECT id FROM coupons WHERE code = ?", (code,), one=True):
        flash("That coupon code already exists.", "error")
        return redirect(url_for("admin.coupons"))
    execute(
        "INSERT INTO coupons (code, discount_percent, max_uses) VALUES (?, ?, ?)",
        (code, percent, max_uses),
    )
    audit("admin_coupon_add", username=current_user()["username"], detail=code)
    flash(f"Coupon {code} created.", "success")
    return redirect(url_for("admin.coupons"))


@bp.route("/coupons/<int:coupon_id>/toggle", methods=("POST",))
@admin_required
@csrf_protect
def toggle_coupon(coupon_id):
    c = query("SELECT * FROM coupons WHERE id = ?", (coupon_id,), one=True)
    if c is None:
        abort(404)
    new_active = 0 if c["active"] else 1
    execute("UPDATE coupons SET active = ? WHERE id = ?", (new_active, coupon_id))
    audit("admin_coupon_toggle", username=current_user()["username"],
          detail=f"coupon={c['code']} active={new_active}")
    flash(f"Coupon {c['code']} {'activated' if new_active else 'deactivated'}.", "success")
    return redirect(url_for("admin.coupons"))

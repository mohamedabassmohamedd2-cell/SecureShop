"""Customer-facing shop: catalogue, cart, coupons/newsletter, checkout and
orders, and the user account page.

Security notes (see Security Coverage Matrix for the full mapping):
- All reads are parameterised; sorting is from a whitelist (no SQL injection).
- Prices are ALWAYS re-derived from the database at checkout — the client is
  never trusted for a price or a total (tampering / business-logic abuse).
- Cart contents are re-validated against stock and active products.
- Object-level access: orders are always fetched scoped to the logged-in user
  (no IDOR).
"""
import secrets

from flask import (
    Blueprint, abort, flash, redirect, render_template, request, session,
    url_for,
)

from .db import execute, query
from .security import (
    admin_required, audit, clean_int, client_ip, csrf_protect,
    current_user, login_required, valid_coupon_code, valid_email, valid_price,
)

bp = Blueprint("shop", __name__)

ALLOWED_SORTS = {"name": "name", "price": "price", "newest": "id"}
ALLOWED_ORDERS = {"asc": "ASC", "desc": "DESC"}
ALLOWED_CATEGORIES = {"electronics", "books", "clothing", "home", "toys"}


# --------------------------------------------------------------------------- #
# Catalogue
# --------------------------------------------------------------------------- #
@bp.route("/")
def index():
    q = (request.args.get("q") or "").strip()[:100]
    category = (request.args.get("category") or "").strip().lower()
    sort = request.args.get("sort") or "newest"
    order = request.args.get("order") or "desc"

    sort_col = ALLOWED_SORTS.get(sort, "id")
    order_dir = ALLOWED_ORDERS.get(order, "DESC")

    sql = "SELECT * FROM products WHERE active = 1"
    params = []
    if category:
        if category not in ALLOWED_CATEGORIES:
            abort(400)
        sql += " AND category = ?"
        params.append(category)
    if q:
        # Parameterised LIKE — user input never concatenated into SQL.
        sql += " AND (name LIKE ? OR description LIKE ?)"
        like = f"%{q}%"
        params += [like, like]
    sql += f" ORDER BY {sort_col} {order_dir}"

    products = query(sql, params)
    categories = [r["category"] for r in query("SELECT DISTINCT category FROM products WHERE active = 1 ORDER BY category")]
    return render_template("index.html", products=products, categories=categories,
                           q=q, category=category, sort=sort, order=order)


@bp.route("/product/<int:product_id>")
def product_detail(product_id):
    product = query("SELECT * FROM products WHERE id = ? AND active = 1", (product_id,), one=True)
    if product is None:
        abort(404)
    return render_template("product.html", product=product)


# --------------------------------------------------------------------------- #
# Shopping cart (session-scoped, price never trusted from the client)
# --------------------------------------------------------------------------- #
def _get_cart():
    return session.setdefault("cart", {})


def _cart_lines():
    """Resolve the cart against the database and return (lines, total, errors)."""
    cart = _get_cart()
    lines, total, problems = [], 0.0, []
    for pid, qty in list(cart.items()):
        try:
            pid_int = int(pid)
            qty_int = clean_int(qty, default=0, minimum=1, maximum=99)
        except (ValueError, TypeError):
            cart.pop(pid, None)
            continue
        product = query("SELECT * FROM products WHERE id = ? AND active = 1", (pid_int,), one=True)
        if product is None:
            cart.pop(pid, None)
            problems.append(f"One item is no longer available and was removed.")
            continue
        qty_int = min(qty_int, product["stock"])
        cart[pid] = qty_int
        line_total = product["price"] * qty_int
        lines.append({"product": product, "qty": qty_int, "line_total": line_total})
        total += line_total
    session["cart"] = cart
    return lines, total, problems


@bp.route("/cart")
def cart_view():
    lines, total, problems = _cart_lines()
    for p in problems:
        flash(p, "warning")
    return render_template("cart.html", lines=lines, total=total)


@bp.route("/cart/add", methods=("POST",))
@csrf_protect
def cart_add():
    product_id = clean_int(request.form.get("product_id"), default=0, minimum=1)
    qty = clean_int(request.form.get("quantity"), default=1, minimum=1, maximum=99)
    product = query("SELECT * FROM products WHERE id = ? AND active = 1", (product_id,), one=True)
    if product is None:
        abort(404)
    cart = _get_cart()
    current_qty = clean_int(cart.get(str(product_id), 0), minimum=0, maximum=99)
    cart[str(product_id)] = min(current_qty + qty, product["stock"])
    session["cart"] = cart
    session.modified = True
    flash(f"Added “{product['name']}” to your cart.", "success")
    return redirect(request.form.get("next") or url_for("shop.cart_view"))


@bp.route("/cart/update", methods=("POST",))
@csrf_protect
def cart_update():
    product_id = clean_int(request.form.get("product_id"), default=0, minimum=1)
    qty = clean_int(request.form.get("quantity"), default=0, minimum=0, maximum=99)
    cart = _get_cart()
    if qty <= 0:
        cart.pop(str(product_id), None)
    else:
        product = query("SELECT * FROM products WHERE id = ? AND active = 1", (product_id,), one=True)
        if product is None:
            cart.pop(str(product_id), None)
        else:
            cart[str(product_id)] = min(qty, product["stock"])
    session["cart"] = cart
    session.modified = True
    return redirect(url_for("shop.cart_view"))


# --------------------------------------------------------------------------- #
# Coupons & newsletter
# --------------------------------------------------------------------------- #
def _active_coupon(code):
    if not code:
        return None
    return query("SELECT * FROM coupons WHERE code = ? AND active = 1", (code,), one=True)


@bp.route("/newsletter", methods=("POST",))
@csrf_protect
def newsletter():
    email = (request.form.get("email") or "").strip().lower()
    if not valid_email(email):
        flash("Please enter a valid email address.", "error")
        return redirect(url_for("shop.index"))
    if query("SELECT id FROM users WHERE email = ? AND newsletter = 1", (email,), one=True):
        flash("You are already subscribed.", "info")
        return redirect(url_for("shop.index"))
    # Issue a one-time 10% coupon on signup (the "newsletter issues a coupon" feature).
    code = "WELCOME-" + secrets.token_hex(4).upper()
    execute(
        "INSERT INTO coupons (code, discount_percent, max_uses) VALUES (?, 10, 1)",
        (code,),
    )
    u = current_user()
    if u:
        execute("UPDATE users SET newsletter = 1 WHERE id = ?", (u["id"],))
    audit("newsletter_signup", username=u["username"] if u else None, detail="coupon issued")
    flash(f"Subscribed! Use coupon {code} for 10% off your next order.", "success")
    return redirect(url_for("shop.index"))


# --------------------------------------------------------------------------- #
# Checkout & orders
# --------------------------------------------------------------------------- #
@bp.route("/checkout", methods=("GET", "POST"))
@login_required
@csrf_protect
def checkout():
    u = current_user()
    lines, total, problems = _cart_lines()
    if not lines:
        flash("Your cart is empty.", "info")
        return redirect(url_for("shop.cart_view"))

    if request.method == "POST":
        coupon_code = (request.form.get("coupon_code") or "").strip().upper()
        discount = 0.0
        applied_coupon = None
        if coupon_code:
            coupon = _active_coupon(coupon_code)
            if coupon is None:
                flash("Invalid or expired coupon code.", "error")
                return render_template("checkout.html", lines=lines, total=total, coupon_code=coupon_code)
            if coupon["max_uses"] is not None and coupon["times_used"] >= coupon["max_uses"]:
                flash("This coupon has already been used.", "error")
                return render_template("checkout.html", lines=lines, total=total, coupon_code=coupon_code)
            discount = round(total * coupon["discount_percent"] / 100.0, 2)
            applied_coupon = coupon

        final_total = round(total - discount, 2)
        if final_total < 0:
            final_total = 0.0

        # Re-validate stock atomically-ish; never trust client quantities/prices.
        for line in lines:
            p = query("SELECT stock, active FROM products WHERE id = ?", (line["product"]["id"],), one=True)
            if p is None or not p["active"] or p["stock"] < line["qty"]:
                flash(f"Sorry, “{line['product']['name']}” is no longer available in that quantity.", "error")
                return redirect(url_for("shop.cart_view"))

        if u["store_credit"] < final_total:
            flash("Insufficient store credit to complete this order.", "error")
            return render_template("checkout.html", lines=lines, total=total, coupon_code=coupon_code)

        order_ref = "ORD-" + secrets.token_hex(5).upper()
        execute(
            "INSERT INTO orders (user_id, order_ref, total, coupon_code) VALUES (?, ?, ?, ?)",
            (u["id"], order_ref, final_total, applied_coupon["code"] if applied_coupon else None),
        )
        order = query("SELECT * FROM orders WHERE order_ref = ?", (order_ref,), one=True)
        for line in lines:
            execute(
                "INSERT INTO order_items (order_id, product_id, name, price, quantity) VALUES (?, ?, ?, ?, ?)",
                (order["id"], line["product"]["id"], line["product"]["name"],
                 line["product"]["price"], line["qty"]),
            )
            execute("UPDATE products SET stock = stock - ? WHERE id = ?",
                    (line["qty"], line["product"]["id"]))
        execute("UPDATE users SET store_credit = store_credit - ? WHERE id = ?",
                (final_total, u["id"]))
        if applied_coupon:
            execute("UPDATE coupons SET times_used = times_used + 1 WHERE id = ?",
                    (applied_coupon["id"],))
        session.pop("cart", None)
        audit("order_placed", username=u["username"], detail=f"order={order_ref} total={final_total}")
        return redirect(url_for("shop.order_confirmation", order_ref=order_ref))

    return render_template("checkout.html", lines=lines, total=total, coupon_code="")


@bp.route("/orders/<order_ref>")
@login_required
def order_confirmation(order_ref):
    u = current_user()
    # Ownership check: the order must belong to the logged-in user (no IDOR).
    order = query("SELECT * FROM orders WHERE order_ref = ? AND user_id = ?",
                  (order_ref, u["id"]), one=True)
    if order is None:
        abort(404)
    items = query("SELECT * FROM order_items WHERE order_id = ?", (order["id"],))
    return render_template("order_confirmation.html", order=order, items=items)


# --------------------------------------------------------------------------- #
# Account page
# --------------------------------------------------------------------------- #
@bp.route("/account", methods=("GET", "POST"))
@login_required
@csrf_protect
def account():
    u = current_user()
    if request.method == "POST":
        full_name = (request.form.get("full_name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        if not valid_email(email):
            flash("Enter a valid email address.", "error")
        elif len(full_name) > 80:
            flash("Name is too long.", "error")
        else:
            if query("SELECT id FROM users WHERE email = ? AND id != ?", (email, u["id"]), one=True):
                flash("That email is already in use.", "error")
            else:
                execute("UPDATE users SET full_name = ?, email = ? WHERE id = ?",
                        (full_name, email, u["id"]))
                audit("profile_updated", username=u["username"])
                flash("Profile updated.", "success")
        return redirect(url_for("shop.account"))

    orders = query("SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC", (u["id"],))
    return render_template("account.html", user=u, orders=orders)

import os
import re
import secrets
import smtplib
from datetime import datetime, timedelta
from email.message import EmailMessage
from decimal import Decimal
from functools import wraps

import pymysql
import requests
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from dotenv import load_dotenv
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from db import connect

load_dotenv()
from dotenv import load_dotenv

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("APP_SECRET", "development-only-change-me")
CORS(app, origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:5173"), "http://127.0.0.1:5173"], supports_credentials=False)
token_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="krishimitra-auth-v1")
TOKEN_MAX_AGE_SECONDS = 60 * 60 * 24 * 7


def issue_token(user):
    return token_serializer.dumps({"user_id": user["id"], "email": user["email"]})


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "ದಯವಿಟ್ಟು ಮೊದಲು Login ಮಾಡಿ."}), 401
        token = header[7:].strip()
        try:
            data = token_serializer.loads(token, max_age=TOKEN_MAX_AGE_SECONDS)
        except SignatureExpired:
            return jsonify({"error": "Login ಅವಧಿ ಮುಗಿದಿದೆ. ಮತ್ತೆ Login ಮಾಡಿ."}), 401
        except BadSignature:
            return jsonify({"error": "ಅಮಾನ್ಯ Login token. ಮತ್ತೆ Login ಮಾಡಿ."}), 401
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id, name, email, created_at FROM users WHERE id=%s", (data.get("user_id"),))
                user = cur.fetchone()
            if not user:
                return jsonify({"error": "ಬಳಕೆದಾರರ ಖಾತೆ ಸಿಗಲಿಲ್ಲ. ಮತ್ತೆ Login ಮಾಡಿ."}), 401
            g.user = user
            return fn(*args, **kwargs)
        finally:
            conn.close()
    return wrapper


@app.get("/")
def home():
    return jsonify({"ok": True, "service": "KrishiMitra API"})


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "KrishiMitra API"})


def send_otp_email(recipient, otp, purpose):
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    smtp_from = os.getenv("SMTP_FROM", smtp_username).strip()
    if not smtp_username or not smtp_password or not smtp_from:
        raise RuntimeError("Gmail SMTP is not configured. Set SMTP_USERNAME, SMTP_PASSWORD and SMTP_FROM in backend/.env.")
    if purpose == "REGISTER":
        subject, heading, explanation = ("Verify your KrishiMitra account", "Welcome to KrishiMitra", "Use this code to verify your email and finish creating your account.")
    else:
        subject, heading, explanation = ("Reset your KrishiMitra password", "Password reset request", "Use this code to reset your KrishiMitra password.")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = recipient
    # Plain-text version for all email clients.
    msg.set_content(
        f"{heading}\n\n{explanation}\n\n"
        f"YOUR KRISHIMITRA OTP: {otp}\n\n"
        "This code expires in 10 minutes. Do not share it with anyone. "
        "If you did not request this, ignore this email.\n\nKrishiMitra Support"
    )
    # HTML version makes the six-digit code prominent in Gmail.
    msg.add_alternative(
        f"""        <!doctype html>
        <html><body style="margin:0;padding:24px;background:#f5f7f2;font-family:Arial,sans-serif;color:#243024;">
          <div style="max-width:520px;margin:0 auto;background:#ffffff;border:1px solid #e1e8dc;border-radius:14px;padding:28px;">
            <div style="font-size:13px;font-weight:bold;letter-spacing:1px;color:#357a38;">KRISHIMITRA</div>
            <h2 style="margin:16px 0 8px;">{heading}</h2>
            <p style="line-height:1.6;">{explanation}</p>
            <p style="margin:24px 0 8px;">Your one-time verification code is:</p>
            <div style="padding:18px;background:#f0f7eb;border-radius:10px;text-align:center;font-size:34px;font-weight:bold;letter-spacing:8px;color:#245d28;">{otp}</div>
            <p style="line-height:1.6;margin-top:20px;">This code expires in <strong>10 minutes</strong>. Do not share it with anyone.</p>
            <p style="font-size:12px;color:#667166;line-height:1.5;">If you did not request this, you can ignore this email.</p>
            <p style="margin-bottom:0;">KrishiMitra Support</p>
          </div>
        </body></html>
        """,
        subtype="html",
    )
    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as server:
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)


def create_otp_challenge(email, purpose):
    otp = f"{secrets.randbelow(1_000_000):06d}"
    otp_hash = generate_password_hash(otp)
    expires_at = datetime.now() + timedelta(minutes=10)
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS n FROM email_otp_challenges WHERE email=%s AND purpose=%s AND created_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)", (email, purpose))
            if int(cur.fetchone()["n"]) >= 4:
                raise ValueError("Too many code requests. Please wait 15 minutes.")
            cur.execute("UPDATE email_otp_challenges SET used_at=NOW() WHERE email=%s AND purpose=%s AND used_at IS NULL", (email, purpose))
            cur.execute("INSERT INTO email_otp_challenges(email,purpose,otp_hash,expires_at) VALUES(%s,%s,%s,%s)", (email, purpose, otp_hash, expires_at))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    try:
        send_otp_email(email, otp, purpose)
    except Exception:
        app.logger.exception("Could not send OTP email")
        conn = connect()
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE email_otp_challenges SET used_at=NOW() WHERE email=%s AND purpose=%s AND otp_hash=%s AND used_at IS NULL", (email, purpose, otp_hash))
            conn.commit()
        finally:
            conn.close()
        raise RuntimeError("Email delivery failed. Check Gmail App Password and SMTP settings.")


def verify_otp_in_transaction(cur, email, purpose, otp):
    cur.execute("SELECT id,otp_hash,expires_at,attempts FROM email_otp_challenges WHERE email=%s AND purpose=%s AND used_at IS NULL ORDER BY id DESC LIMIT 1 FOR UPDATE", (email, purpose))
    row = cur.fetchone()
    if not row:
        return None, "No active code found. Request a new code."
    if row["expires_at"] <= datetime.now():
        cur.execute("UPDATE email_otp_challenges SET used_at=NOW() WHERE id=%s", (row["id"],))
        return None, "The code has expired. Request a new code."
    if int(row["attempts"]) >= 5:
        cur.execute("UPDATE email_otp_challenges SET used_at=NOW() WHERE id=%s", (row["id"],))
        return None, "Too many incorrect attempts. Request a new code."
    if not check_password_hash(row["otp_hash"], otp):
        cur.execute("UPDATE email_otp_challenges SET attempts=attempts+1 WHERE id=%s", (row["id"],))
        return None, "Incorrect verification code."
    return row["id"], None


@app.post("/api/auth/register")
def register():
    return jsonify({"error": "Email verification is required. Use /api/auth/register/send-otp and /api/auth/register/verify-otp."}), 410


@app.post("/api/auth/register/send-otp")
def register_send_otp():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        return jsonify({"error": "Enter a valid email address."}), 400
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            if cur.fetchone():
                return jsonify({"error": "An account already exists. Please log in."}), 409
    finally:
        conn.close()
    try:
        create_otp_challenge(email, "REGISTER")
        return jsonify({"ok": True, "message": "Verification code sent. Check your inbox and spam folder."})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 429
    except Exception:
        app.logger.exception("Registration OTP request failed")
        return jsonify({"error": "Could not send verification email. Check Gmail SMTP settings."}), 503


@app.post("/api/auth/register/verify-otp")
def register_verify_otp():
    body = request.get_json(silent=True) or {}
    name = str(body.get("name", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    otp = str(body.get("otp", "")).strip()
    if not name or len(name) > 120:
        return jsonify({"error": "Enter your full name."}), 400
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        return jsonify({"error": "Enter a valid email address."}), 400
    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "Password must be 8–128 characters."}), 400
    if not re.fullmatch(r"\d{6}", otp):
        return jsonify({"error": "Enter the 6-digit email code."}), 400
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            if cur.fetchone():
                return jsonify({"error": "An account already exists. Please log in."}), 409
            challenge_id, error = verify_otp_in_transaction(cur, email, "REGISTER", otp)
            if error:
                conn.commit()
                return jsonify({"error": error}), 400
            cur.execute("INSERT INTO users(name,email,password_hash) VALUES(%s,%s,%s)", (name, email, generate_password_hash(password)))
            user_id = cur.lastrowid
            cur.execute("UPDATE email_otp_challenges SET used_at=NOW() WHERE id=%s", (challenge_id,))
        conn.commit()
        user = {"id": user_id, "name": name, "email": email}
        return jsonify({"ok": True, "token": issue_token(user), "user": user, "message": "Email verified and account created."}), 201
    except Exception:
        conn.rollback()
        app.logger.exception("Email-verified registration failed")
        return jsonify({"error": "Could not create your account. Please try again."}), 500
    finally:
        conn.close()


@app.post("/api/auth/forgot-password/send-otp")
def forgot_password_send_otp():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        return jsonify({"error": "Enter a valid email address."}), 400
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            exists = cur.fetchone() is not None
    finally:
        conn.close()
    if exists:
        try:
            create_otp_challenge(email, "PASSWORD_RESET")
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 429
        except Exception:
            app.logger.exception("Password reset OTP request failed")
            return jsonify({"error": "Email delivery failed. Check SMTP settings."}), 503
    return jsonify({"ok": True, "message": "If this email belongs to an account, a reset code has been sent."})


@app.post("/api/auth/forgot-password/reset")
def forgot_password_reset():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    otp = str(body.get("otp", "")).strip()
    password = str(body.get("new_password", ""))
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return jsonify({"error": "Enter a valid email address."}), 400
    if not re.fullmatch(r"\d{6}", otp):
        return jsonify({"error": "Enter the 6-digit email code."}), 400
    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "New password must be 8–128 characters."}), 400
    conn = connect()
    try:
        with conn.cursor() as cur:
            challenge_id, error = verify_otp_in_transaction(cur, email, "PASSWORD_RESET", otp)
            if error:
                conn.commit()
                return jsonify({"error": error}), 400
            cur.execute("UPDATE users SET password_hash=%s WHERE email=%s", (generate_password_hash(password), email))
            if cur.rowcount != 1:
                conn.rollback()
                return jsonify({"error": "Account not found."}), 404
            cur.execute("UPDATE email_otp_challenges SET used_at=NOW() WHERE id=%s", (challenge_id,))
            cur.execute("UPDATE email_otp_challenges SET used_at=NOW() WHERE email=%s AND purpose='PASSWORD_RESET' AND used_at IS NULL", (email,))
        conn.commit()
        return jsonify({"ok": True, "message": "Password reset successfully. Please log in."})
    except Exception:
        conn.rollback()
        app.logger.exception("Password reset failed")
        return jsonify({"error": "Could not reset the password. Please try again."}), 500
    finally:
        conn.close()

@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,email,password_hash FROM users WHERE email=%s", (email,))
            user = cur.fetchone()
        if not user or not check_password_hash(user["password_hash"], password):
            return jsonify({"error": "Email ಅಥವಾ password ತಪ್ಪಾಗಿದೆ."}), 401
        public_user = {"id": user["id"], "name": user["name"], "email": user["email"]}
        return jsonify({"ok": True, "token": issue_token(public_user), "user": public_user})
    finally:
        conn.close()


@app.get("/api/auth/me")
@require_auth
def me():
    user = dict(g.user)
    if user.get("created_at"):
        user["created_at"] = user["created_at"].isoformat(sep=" ", timespec="seconds")
    return jsonify({"user": user})


@app.get("/api/products")
def products():
    q = request.args.get("q", "").strip()
    city = request.args.get("city", "Nanjangud").strip()
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT p.id,p.name,p.category,p.description,p.unit,MIN(i.price*(1-i.discount_percent/100)) AS price, "
                "MAX(i.discount_percent) AS discount_percent, SUM(CASE WHEN s.is_open=1 AND i.stock_qty>0 THEN 1 ELSE 0 END) AS available_stores, "
                "SUM(CASE WHEN s.is_open=1 THEN i.stock_qty ELSE 0 END) AS stock_qty, "
                "(SELECT s2.name FROM inventory i2 JOIN stores s2 ON s2.id=i2.store_id WHERE i2.product_id=p.id AND s2.city=%s AND s2.is_open=1 AND i2.stock_qty>0 ORDER BY i2.price*(1-i2.discount_percent/100) LIMIT 1) AS store_name "
                "FROM products p JOIN inventory i ON i.product_id=p.id "
                "JOIN stores s ON s.id=i.store_id WHERE s.city=%s AND "
                "(p.name LIKE %s OR p.category LIKE %s) "
                "GROUP BY p.id,p.name,p.category,p.description,p.unit ORDER BY p.name",
                (city, city, "%" + q + "%", "%" + q + "%")
            )
            rows = cur.fetchall()
        for row in rows:
            row["price"] = float(row["price"] or 0)
            row["discount_percent"] = float(row.get("discount_percent") or 0)
            row["available_stores"] = int(row["available_stores"] or 0)
            row["stock_qty"] = int(row.get("stock_qty") or 0)
        return jsonify(rows)
    finally:
        conn.close()


@app.post("/api/discounts/validate")
def validate_discount():
    body = request.get_json(silent=True) or {}
    code = str(body.get("code", "")).strip().upper()
    try:
        subtotal = Decimal(str(body.get("subtotal", 0)))
        if subtotal < 0 or subtotal > Decimal("100000000"):
            raise ValueError()
    except Exception:
        return jsonify({"error": "Invalid subtotal."}), 400
    if not code:
        return jsonify({"error": "Enter a coupon code."}), 400
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT code,discount_type,discount_value,min_order_amount,max_discount_amount,active,valid_from,valid_until FROM coupons WHERE code=%s", (code,))
            c = cur.fetchone()
        if not c or not c["active"]:
            return jsonify({"error": "Coupon is invalid or inactive."}), 400
        from datetime import datetime
        now = datetime.now()
        if c["valid_from"] and now < c["valid_from"]:
            return jsonify({"error": "Coupon is not active yet."}), 400
        if c["valid_until"] and now > c["valid_until"]:
            return jsonify({"error": "Coupon has expired."}), 400
        if subtotal < Decimal(str(c["min_order_amount"])):
            return jsonify({"error": f"Minimum order value is ₹{c['min_order_amount']}."}), 400
        amount = subtotal * Decimal(str(c["discount_value"])) / Decimal("100") if c["discount_type"] == "PERCENT" else Decimal(str(c["discount_value"]))
        if c["max_discount_amount"] is not None:
            amount = min(amount, Decimal(str(c["max_discount_amount"])))
        amount = min(amount, subtotal).quantize(Decimal("0.01"))
        return jsonify({"ok": True, "code": c["code"], "discount_amount": float(amount), "message": f"Coupon {c['code']} applied."})
    finally:
        conn.close()


@app.get("/api/stores")
def stores():
    city = request.args.get("city", "Nanjangud").strip()
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id,name,city,area,phone,is_open,delivery_minutes FROM stores WHERE city=%s ORDER BY is_open DESC,delivery_minutes", (city,))
            rows = cur.fetchall()
        for row in rows:
            row["is_open"] = bool(row["is_open"])
        return jsonify(rows)
    finally:
        conn.close()


@app.get("/api/products/<int:product_id>/stores")
def product_store_options(product_id):
    city = request.args.get("city", "").strip()
    if not city:
        return jsonify({"error": "Choose a city first."}), 400
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT s.id AS store_id, s.name AS store_name, s.city, s.area, s.phone, s.is_open,
                       i.product_id, i.price AS list_price, i.discount_percent,
                       ROUND(i.price * (1 - i.discount_percent / 100), 2) AS final_price,
                       i.stock_qty, COALESCE(ROUND(AVG(r.rating), 1), 0) AS rating,
                       COUNT(DISTINCT r.id) AS review_count
                FROM inventory i JOIN stores s ON s.id=i.store_id
                LEFT JOIN store_reviews r ON r.store_id=s.id
                WHERE i.product_id=%s AND s.city=%s AND s.is_open=1
                GROUP BY s.id,s.name,s.city,s.area,s.phone,s.is_open,i.product_id,i.price,i.discount_percent,i.stock_qty
                ORDER BY rating DESC, final_price ASC
            """, (product_id, city))
            rows = cur.fetchall()
        for row in rows:
            for key in ("list_price", "discount_percent", "final_price", "rating"):
                row[key] = float(row[key] or 0)
            row["stock_qty"] = int(row["stock_qty"] or 0)
            row["review_count"] = int(row["review_count"] or 0)
            row["is_open"] = bool(row["is_open"])
        return jsonify(rows)
    finally:
        conn.close()


@app.get("/api/stores/<int:store_id>/reviews")
def get_store_reviews(store_id):
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT r.id,r.rating,r.review,r.created_at,u.name AS reviewer_name FROM store_reviews r JOIN users u ON u.id=r.user_id WHERE r.store_id=%s ORDER BY r.created_at DESC LIMIT 100", (store_id,))
            rows = cur.fetchall()
        for row in rows:
            row["created_at"] = row["created_at"].isoformat(sep=" ", timespec="seconds")
        return jsonify(rows)
    finally:
        conn.close()


@app.post("/api/stores/<int:store_id>/reviews")
@require_auth
def create_store_review(store_id):
    body = request.get_json(silent=True) or {}
    try:
        rating = int(body.get("rating", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "Rating must be from 1 to 5."}), 400
    review = str(body.get("review", "")).strip()
    if rating < 1 or rating > 5:
        return jsonify({"error": "Rating must be from 1 to 5."}), 400
    if len(review) < 5 or len(review) > 1000:
        return jsonify({"error": "Review must contain 5–1000 characters."}), 400
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT oi.id FROM order_items oi JOIN orders o ON o.id=oi.order_id WHERE o.user_id=%s AND oi.store_id=%s LIMIT 1", (g.user["id"], store_id))
            if not cur.fetchone():
                return jsonify({"error": "You can review a store after placing an order from it."}), 403
            cur.execute("INSERT INTO store_reviews(store_id,user_id,rating,review) VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE rating=VALUES(rating),review=VALUES(review),created_at=CURRENT_TIMESTAMP", (store_id, g.user["id"], rating, review))
        conn.commit()
        return jsonify({"ok": True, "message": "Your store review has been saved."})
    except Exception:
        conn.rollback()
        app.logger.exception("Store review save failed")
        return jsonify({"error": "Could not save review."}), 500
    finally:
        conn.close()


@app.post("/api/orders")
@require_auth
def create_order():
    body = request.get_json(silent=True) or {}

    customer_name = str(body.get("customer_name") or g.user["name"]).strip()
    customer_phone = str(body.get("customer_phone") or "").strip()
    address = str(body.get("delivery_address") or "").strip()
    city = str(body.get("city") or "").strip()
    district = str(body.get("district") or "").strip()[:100]
    coupon_code = str(body.get("coupon_code") or "").strip().upper() or None
    items = body.get("items")

    # Validate checkout fields.
    if not customer_name or len(customer_name) > 120:
        return jsonify({"error": "ಸರಿಯಾದ ಹೆಸರನ್ನು ನಮೂದಿಸಿ."}), 400

    if not re.fullmatch(r"[0-9+\-\s()]{7,20}", customer_phone):
        return jsonify({"error": "ಸರಿಯಾದ ಮೊಬೈಲ್ ಸಂಖ್ಯೆಯನ್ನು ನಮೂದಿಸಿ."}), 400

    if not address or len(address) > 5000 or not city:
        return jsonify({
            "error": "ಪೂರ್ಣ ಡೆಲಿವರಿ ವಿಳಾಸ ಮತ್ತು ನಗರ ನಮೂದಿಸಿ."
        }), 400

    if not isinstance(items, list) or not items:
        return jsonify({"error": "ನಿಮ್ಮ Cart ಖಾಲಿಯಾಗಿದೆ."}), 400

    # Combine duplicate product/store pairs.
    quantities = {}

    try:
        for item in items:
            if not isinstance(item, dict):
                raise ValueError()

            product_id = int(item.get("product_id", 0))
            store_id = int(item.get("store_id", 0))
            quantity = int(item.get("quantity", 0))

            if product_id < 1 or store_id < 1:
                raise ValueError()

            if quantity < 1 or quantity > 1000:
                raise ValueError()

            key = (product_id, store_id)
            quantities[key] = quantities.get(key, 0) + quantity

            if quantities[key] > 1000:
                raise ValueError()

        if len(quantities) > 50:
            raise ValueError()

    except (ValueError, TypeError, AttributeError):
        return jsonify({
            "error": "ಪ್ರತಿ Cart item‌ಗೆ ಸರಿಯಾದ product_id, store_id ಮತ್ತು quantity ಅಗತ್ಯ."
        }), 400

    conn = None

    try:
        conn = connect()
        total = Decimal("0.00")
        saved_items = []

        with conn.cursor() as cur:
            # Lock inventory rows to prevent overselling.
            for (product_id, store_id), quantity in quantities.items():

                cur.execute(
                    """
                    SELECT
                        i.id AS inventory_id,
                        i.store_id,
                        i.product_id,
                        i.price AS list_price,
                        i.discount_percent,
                        ROUND(
                            i.price * (1 - i.discount_percent / 100),
                            2
                        ) AS final_price,
                        i.stock_qty,
                        p.name AS product_name,
                        s.name AS store_name,
                        s.city AS store_city,
                        s.is_open
                    FROM inventory i
                    JOIN products p ON p.id = i.product_id
                    JOIN stores s ON s.id = i.store_id
                    WHERE i.product_id = %s
                      AND i.store_id = %s
                    LIMIT 1
                    FOR UPDATE
                    """,
                    (product_id, store_id)
                )

                row = cur.fetchone()

                if not row:
                    conn.rollback()
                    return jsonify({
                        "error": (
                            f"ಉತ್ಪನ್ನ ID {product_id} ಆಯ್ಕೆ ಮಾಡಿದ ಅಂಗಡಿಯಲ್ಲಿ "
                            "ಲಭ್ಯವಿಲ್ಲ. ದಯವಿಟ್ಟು ಉತ್ಪನ್ನವನ್ನು ಮತ್ತೆ ಆಯ್ಕೆಮಾಡಿ."
                        ),
                        "code": "INVENTORY_NOT_FOUND",
                        "product_id": product_id,
                        "store_id": store_id
                    }), 409

                # Compare city names without case/space differences.
                store_city = str(row.get("store_city") or "").strip()
                if store_city.casefold() != city.casefold():
                    conn.rollback()
                    return jsonify({
                        "error": (
                            f"{row['product_name']} ಉತ್ಪನ್ನದ ಅಂಗಡಿ "
                            f"{store_city} ನಗರದಲ್ಲಿದೆ; Checkout ನಗರ "
                            f"{city} ಆಗಿದೆ. ಸರಿಯಾದ ನಗರ ಆಯ್ಕೆಮಾಡಿ."
                        ),
                        "code": "CITY_MISMATCH",
                        "store_city": store_city,
                        "checkout_city": city
                    }), 409

                if not row.get("is_open"):
                    conn.rollback()
                    return jsonify({
                        "error": (
                            f"{row['store_name']} ಅಂಗಡಿ ಈಗ ಮುಚ್ಚಿದೆ. "
                            "ಬೇರೆ ಅಂಗಡಿ ಆಯ್ಕೆಮಾಡಿ."
                        ),
                        "code": "STORE_CLOSED"
                    }), 409

                available_stock = int(row.get("stock_qty") or 0)

                if available_stock < quantity:
                    conn.rollback()
                    return jsonify({
                        "error": (
                            f"{row['product_name']} ಗೆ ಸಾಕಷ್ಟು stock ಇಲ್ಲ. "
                            f"ಲಭ್ಯವಿರುವ ಪ್ರಮಾಣ: {available_stock}; "
                            f"ನೀವು ಕೇಳಿದ ಪ್ರಮಾಣ: {quantity}. "
                            "Cart‌ನಲ್ಲಿ ಪ್ರಮಾಣ ಕಡಿಮೆ ಮಾಡಿ ಅಥವಾ ಬೇರೆ ಅಂಗಡಿ ಆಯ್ಕೆಮಾಡಿ."
                        ),
                        "code": "INSUFFICIENT_STOCK",
                        "product_id": product_id,
                        "store_id": store_id,
                        "available_stock": available_stock,
                        "requested_quantity": quantity
                    }), 409

                price = Decimal(str(row["final_price"] or 0))

                if price < 0:
                    conn.rollback()
                    return jsonify({
                        "error": "ಉತ್ಪನ್ನದ ಬೆಲೆ ಸರಿಯಾಗಿಲ್ಲ. ಅಂಗಡಿಯನ್ನು ಸಂಪರ್ಕಿಸಿ."
                    }), 409

                total += price * quantity

                saved_items.append({
                    **row,
                    "quantity": quantity,
                    "price": price
                })

            # Validate coupon, if one was provided.
            discount_amount = Decimal("0.00")

            if coupon_code:
                cur.execute(
                    """
                    SELECT
                        code, discount_type, discount_value,
                        min_order_amount, max_discount_amount,
                        active, valid_from, valid_until
                    FROM coupons
                    WHERE code = %s
                    FOR UPDATE
                    """,
                    (coupon_code,)
                )
                coupon = cur.fetchone()
                now = datetime.now()

                if (
                    not coupon
                    or not coupon["active"]
                    or (
                        coupon["valid_from"]
                        and now < coupon["valid_from"]
                    )
                    or (
                        coupon["valid_until"]
                        and now > coupon["valid_until"]
                    )
                ):
                    conn.rollback()
                    return jsonify({
                        "error": "Coupon ಅಮಾನ್ಯವಾಗಿದೆ ಅಥವಾ ಅವಧಿ ಮುಗಿದಿದೆ.",
                        "code": "INVALID_COUPON"
                    }), 400

                if total < Decimal(str(coupon["min_order_amount"])):
                    conn.rollback()
                    return jsonify({
                        "error": (
                            "Coupon ಬಳಸಲು ಕನಿಷ್ಠ Order ಮೊತ್ತ ₹"
                            f"{coupon['min_order_amount']} ಇರಬೇಕು."
                        ),
                        "code": "MINIMUM_ORDER_NOT_MET"
                    }), 400

                discount_value = Decimal(str(coupon["discount_value"]))

                if coupon["discount_type"] == "PERCENT":
                    discount_amount = total * discount_value / Decimal("100")
                else:
                    discount_amount = discount_value

                if coupon["max_discount_amount"] is not None:
                    discount_amount = min(
                        discount_amount,
                        Decimal(str(coupon["max_discount_amount"]))
                    )

                discount_amount = min(
                    discount_amount, total
                ).quantize(Decimal("0.01"))

            total = max(
                Decimal("0.00"),
                total - discount_amount
            ).quantize(Decimal("0.01"))

            # Create order.
            cur.execute(
                """
                INSERT INTO orders (
                    user_id,
                    customer_name,
                    customer_phone,
                    delivery_address,
                    city,
                    district,
                    coupon_code,
                    discount_amount,
                    payment_method,
                    payment_status,
                    order_status,
                    total_amount
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    'COD', 'PENDING', 'PLACED', %s
                )
                """,
                (
                    g.user["id"],
                    customer_name,
                    customer_phone,
                    address,
                    city,
                    district,
                    coupon_code,
                    discount_amount,
                    total
                )
            )

            order_id = cur.lastrowid

            # Save order items and deduct stock atomically.
            for item in saved_items:
                cur.execute(
                    """
                    INSERT INTO order_items (
                        order_id,
                        store_id,
                        product_id,
                        quantity,
                        unit_price,
                        discount_percent
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        order_id,
                        item["store_id"],
                        item["product_id"],
                        item["quantity"],
                        item["price"],
                        item.get("discount_percent", 0)
                    )
                )

                cur.execute(
                    """
                    UPDATE inventory
                    SET stock_qty = stock_qty - %s
                    WHERE id = %s
                      AND stock_qty >= %s
                    """,
                    (
                        item["quantity"],
                        item["inventory_id"],
                        item["quantity"]
                    )
                )

                if cur.rowcount != 1:
                    raise RuntimeError(
                        "Inventory changed during checkout."
                    )

            cur.execute(
                """
                INSERT INTO order_status_history (
                    order_id, status, note
                )
                VALUES (%s, 'PLACED', 'Order created; COD selected')
                """,
                (order_id,)
            )

        conn.commit()

        return jsonify({
            "ok": True,
            "message": "ನಿಮ್ಮ Order ಯಶಸ್ವಿಯಾಗಿ ದಾಖಲಿಸಲಾಗಿದೆ.",
            "order_id": order_id,
            "total_amount": float(total),
            "discount_amount": float(discount_amount),
            "payment_method": "COD",
            "payment_status": "PENDING",
            "order_status": "PLACED"
        }), 201

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception("Order creation failed")

        return jsonify({
            "error": (
                "ಆರ್ಡರ್ ದಾಖಲಿಸಲಾಗಲಿಲ್ಲ. Backend terminal‌ನಲ್ಲಿರುವ "
                "Order creation failed ವಿವರವನ್ನು ಪರಿಶೀಲಿಸಿ."
            ),
            "code": "ORDER_CREATION_FAILED"
        }), 500

    finally:
        if conn:
            conn.close()

@app.get("/api/orders/mine")
@require_auth
def my_orders():
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id,city,district,coupon_code,discount_amount,payment_method,payment_status,order_status,total_amount,created_at FROM orders WHERE user_id=%s ORDER BY id DESC LIMIT 100", (g.user["id"],))
            rows = cur.fetchall()
        for row in rows:
            row["total_amount"] = float(row["total_amount"])
            row["discount_amount"] = float(row.get("discount_amount") or 0)
            row["created_at"] = row["created_at"].isoformat(sep=" ", timespec="seconds")
        return jsonify(rows)
    finally:
        conn.close()


@app.get("/api/orders/<int:order_id>")
@require_auth
def track_order(order_id):
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id,customer_name,customer_phone,delivery_address,city,district,coupon_code,discount_amount,payment_method,payment_status,order_status,total_amount,created_at FROM orders WHERE id=%s AND user_id=%s", (order_id, g.user["id"]))
            order = cur.fetchone()
            if not order:
                return jsonify({"error": "ಈ ಖಾತೆಗೆ ಸೇರಿದ ಆರ್ಡರ್ ಸಿಗಲಿಲ್ಲ."}), 404
            cur.execute("SELECT oi.product_id,p.name product_name,p.unit,oi.quantity,oi.unit_price,oi.discount_percent,s.name store_name FROM order_items oi JOIN products p ON p.id=oi.product_id JOIN stores s ON s.id=oi.store_id WHERE oi.order_id=%s ORDER BY oi.id", (order_id,))
            order["items"] = cur.fetchall()
        order["total_amount"] = float(order["total_amount"])
        order["discount_amount"] = float(order.get("discount_amount") or 0)
        order["created_at"] = order["created_at"].isoformat(sep=" ", timespec="seconds")
        for item in order["items"]:
            item["unit_price"] = float(item["unit_price"])
            item["discount_percent"] = float(item.get("discount_percent") or 0)
        conn2 = connect()
        try:
            with conn2.cursor() as cur2:
                cur2.execute("SELECT status,note,created_at FROM order_status_history WHERE order_id=%s ORDER BY id", (order_id,))
                order["status_history"] = cur2.fetchall()
            for ev in order["status_history"]:
                ev["created_at"] = ev["created_at"].isoformat(sep=" ", timespec="seconds")
        finally:
            conn2.close()
        return jsonify(order)
    finally:
        conn.close()


@app.get("/api/admin/orders")
@require_auth
def admin_list_orders():
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    if not admin_email or g.user["email"].lower() != admin_email:
        return jsonify({"error": "Admin access required."}), 403
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id,customer_name,customer_phone,city,district,order_status,payment_status,total_amount,created_at FROM orders ORDER BY id DESC LIMIT 250")
            rows = cur.fetchall()
        for row in rows:
            row["total_amount"] = float(row["total_amount"])
            row["created_at"] = row["created_at"].isoformat(sep=" ", timespec="seconds")
        return jsonify(rows)
    finally:
        conn.close()



@app.patch("/api/admin/orders/<int:order_id>/status")
@require_auth
def admin_update_order_status(order_id):
    # Only the configured administrator may update order status.
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()

    if not admin_email or g.user["email"].lower() != admin_email:
        return jsonify({"error": "Admin access required."}), 403

    body = request.get_json(silent=True) or {}
    status = str(body.get("status", "")).strip().upper()
    note = str(body.get("note", "")).strip()[:255] or None

    allowed_statuses = {
        "ACCEPTED",
        "PACKED",
        "OUT_FOR_DELIVERY",
        "DELIVERED",
        "CANCELLED",
    }

    if status not in allowed_statuses:
        return jsonify({
            "error": "Invalid order status.",
            "allowed_statuses": sorted(allowed_statuses),
        }), 400

    conn = None

    try:
        conn = connect()

        with conn.cursor() as cur:
            # Lock the order so two admins cannot update it simultaneously.
            cur.execute(
                """
                SELECT id, order_status
                FROM orders
                WHERE id = %s
                FOR UPDATE
                """,
                (order_id,),
            )
            order = cur.fetchone()

            if not order:
                conn.rollback()
                return jsonify({"error": "Order not found."}), 404

            current_status = str(order["order_status"]).upper()

            if current_status in {"DELIVERED", "CANCELLED"}:
                conn.rollback()
                return jsonify({
                    "error": (
                        f"Order is already {current_status}. "
                        "Closed orders cannot be changed."
                    ),
                    "current_status": current_status,
                }), 409

            # Enforce a sensible order-status sequence.
            transitions = {
                "PLACED": {"ACCEPTED", "CANCELLED"},
                "ACCEPTED": {"PACKED", "CANCELLED"},
                "PACKED": {"OUT_FOR_DELIVERY", "CANCELLED"},
                "OUT_FOR_DELIVERY": {"DELIVERED"},
            }

            permitted = transitions.get(current_status, set())

            if status not in permitted:
                conn.rollback()
                return jsonify({
                    "error": (
                        f"Cannot change order from {current_status} "
                        f"to {status}."
                    ),
                    "current_status": current_status,
                    "permitted_next_statuses": sorted(permitted),
                }), 409

            # Restore stock only when cancelling an active order.
            # This and the status update happen in one transaction.
            if status == "CANCELLED":
                cur.execute(
                    """
                    SELECT product_id, store_id, quantity
                    FROM order_items
                    WHERE order_id = %s
                    FOR UPDATE
                    """,
                    (order_id,),
                )
                items = cur.fetchall()

                for item in items:
                    cur.execute(
                        """
                        UPDATE inventory
                        SET stock_qty = stock_qty + %s
                        WHERE product_id = %s
                          AND store_id = %s
                        """,
                        (
                            int(item["quantity"]),
                            int(item["product_id"]),
                            int(item["store_id"]),
                        ),
                    )

                    if cur.rowcount != 1:
                        raise RuntimeError(
                            "Could not restore inventory for a cancelled order."
                        )

            cur.execute(
                """
                UPDATE orders
                SET order_status = %s
                WHERE id = %s
                """,
                (status, order_id),
            )

            cur.execute(
                """
                INSERT INTO order_status_history
                    (order_id, status, note)
                VALUES (%s, %s, %s)
                """,
                (
                    order_id,
                    status,
                    note or f"Status updated by admin: {status}",
                ),
            )

        conn.commit()

        return jsonify({
            "ok": True,
            "message": f"Order #{order_id} status updated to {status}.",
            "order_id": order_id,
            "previous_status": current_status,
            "order_status": status,
        }), 200

    except Exception:
        if conn:
            conn.rollback()

        app.logger.exception(
            "Admin status update failed for order %s",
            order_id,
        )

        return jsonify({
            "error": "Could not update order status. Please try again.",
        }), 500

    finally:
        if conn:
            conn.close()


@app.post("/api/vendor/products")
@require_auth
def vendor_add_product_listing():
    body=request.get_json(silent=True) or {}
    try:
        product_id=int(body.get('product_id')); price=Decimal(str(body.get('price'))); stock=int(body.get('stock_qty')); discount=Decimal(str(body.get('discount_percent',0)))
        if price <= 0 or price > Decimal('10000000') or stock < 0 or stock > 1000000 or discount < 0 or discount > 90: raise ValueError()
    except Exception: return jsonify({"error":"ಸರಿಯಾದ product, price, stock ಮತ್ತು 0–90% discount ನಮೂದಿಸಿ."}),400
    conn=connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT store_id FROM vendor_applications WHERE user_id=%s AND verification_status='APPROVED' AND store_id IS NOT NULL ORDER BY id DESC LIMIT 1",(g.user['id'],)); own=cur.fetchone()
            if not own: return jsonify({"error":"Admin ಅನುಮೋದಿಸಿದ Store/Company ಅಗತ್ಯ."}),403
            cur.execute("SELECT id FROM products WHERE id=%s",(product_id,))
            if not cur.fetchone(): return jsonify({"error":"Product catalogue item ಸಿಗಲಿಲ್ಲ."}),404
            cur.execute("INSERT INTO inventory(store_id,product_id,price,stock_qty,discount_percent) VALUES(%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE price=VALUES(price),stock_qty=VALUES(stock_qty),discount_percent=VALUES(discount_percent)",(own['store_id'],product_id,price,stock,discount))
        conn.commit(); return jsonify({"ok":True,"message":"Product listing ಉಳಿಸಲಾಗಿದೆ."}),201
    except Exception:
        conn.rollback(); app.logger.exception('Vendor product listing failed'); return jsonify({"error":"Product listing ಉಳಿಸಲಾಗಲಿಲ್ಲ."}),500
    finally: conn.close()

@app.get("/api/ai/history")
@require_auth
def ai_history():
    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id,user_question,language,assistant_answer,created_at FROM ai_chats WHERE user_id=%s ORDER BY id DESC LIMIT 30", (g.user["id"],))
            rows = cur.fetchall()
        for row in rows:
            row["created_at"] = row["created_at"].isoformat(sep=" ", timespec="seconds")
        return jsonify(rows)
    finally:
        conn.close()


@app.post("/api/ai/ask")
def ask_ai():
    body = request.get_json(silent=True) or {}
    question = str(body.get("question", "")).strip()
    language = str(body.get("language", "kn")).lower()
    if not question or len(question) > 4000:
        return jsonify({"error": "ಪ್ರಶ್ನೆಯನ್ನು ನಮೂದಿಸಿ (ಗರಿಷ್ಠ 4000 ಅಕ್ಷರಗಳು)."}), 400
    language_names = {"kn": "Kannada", "en": "English", "hi": "Hindi"}
    language_name = language_names.get(language, "Kannada")
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip()
    if not api_key:
        return jsonify({"error": "OpenRouter API key ಹೊಂದಿಸಿಲ್ಲ. backend/.env ನಲ್ಲಿ OPENROUTER_API_KEY ಸೇರಿಸಿ."}), 503

    system_prompt = (
        "You are KrishiMitra, a careful agriculture assistant for farmers in India. "
        f"Reply in {language_name} only. Be practical and clear. Ask for crop, location, symptoms, "
        "and growth stage when needed. Do not invent pesticide or fertilizer dosages, and do not "
        "recommend unsafe chemical mixing. Encourage users to follow the registered product label "
        "and consult a local agricultural officer for diagnosis or chemical use. Make clear that you "
        "cannot confirm a diagnosis from limited information."
    )
    conversation = [{"role": "system", "content": system_prompt}]
    history = body.get("history", [])
    if isinstance(history, list):
        # Keep only a short, bounded conversation; never accept system/developer roles from the client.
        for message in history[-10:]:
            if not isinstance(message, dict):
                continue
            role = message.get("role")
            content = message.get("content")
            if role not in ("user", "assistant") or not isinstance(content, str):
                continue
            content = content.strip()[:4000]
            if content:
                conversation.append({"role": role, "content": content})
    if not conversation or conversation[-1].get("role") != "user" or conversation[-1].get("content") != question:
        conversation.append({"role": "user", "content": question})

    try:
        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost:5173"),
                "X-Title": os.getenv("OPENROUTER_APP_NAME", "KrishiMitra")
            },
            json={
                "model": os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
                "messages": conversation,
                "temperature": 0.4,
                "max_tokens": 800
            },
            timeout=45
        )
        if response.status_code >= 400:
            app.logger.warning("OpenRouter returned status %s", response.status_code)
            return jsonify({"error": "AI ಸೇವೆ ಈಗ ಉತ್ತರಿಸಲಿಲ್ಲ. API key, model ಮತ್ತು OpenRouter credits ಪರಿಶೀಲಿಸಿ."}), 502
        data = response.json()
        answer = data["choices"][0]["message"]["content"].strip()
        if not answer:
            raise ValueError("Empty AI answer")
    except requests.Timeout:
        return jsonify({"error": "AI ಉತ್ತರಿಸಲು ಹೆಚ್ಚು ಸಮಯ ತೆಗೆದುಕೊಂಡಿತು. ಮತ್ತೆ ಪ್ರಯತ್ನಿಸಿ."}), 504
    except Exception:
        app.logger.exception("OpenRouter request failed")
        return jsonify({"error": "AI ಉತ್ತರ ಪಡೆಯಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ. backend terminal ಪರಿಶೀಲಿಸಿ."}), 502

    user_id = None
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        try:
            token_data = token_serializer.loads(header[7:].strip(), max_age=TOKEN_MAX_AGE_SECONDS)
            user_id = token_data.get("user_id")
        except (BadSignature, SignatureExpired):
            user_id = None

    conn = connect()
    try:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO ai_chats(user_id,user_question,language,assistant_answer) VALUES(%s,%s,%s,%s)", (user_id, question, language, answer))
        conn.commit()
    except Exception:
        conn.rollback()
        app.logger.exception("Could not save AI chat history")
    finally:
        conn.close()
    return jsonify({"answer": answer, "mode": "openrouter"})



# Store/company onboarding and GPS review
def _is_admin():
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    return bool(admin_email) and g.user["email"].lower() == admin_email

@app.post("/api/vendor/applications")
@require_auth
def create_vendor_application():
    b = request.get_json(silent=True) or {}
    kind = str(b.get("business_type", "STORE")).upper()
    name = str(b.get("business_name", "")).strip()
    contact = str(b.get("contact_name", g.user.get("name", ""))).strip()
    phone = re.sub(r"[^0-9+]", "", str(b.get("phone", "")))[:20]
    email = str(b.get("business_email", g.user.get("email", ""))).strip().lower()
    district, city = str(b.get("district", "")).strip(), str(b.get("city", "")).strip()
    address = str(b.get("address", "")).strip()
    category = str(b.get("category", "Agricultural supplies")).strip()[:100]
    registration_no = str(b.get("registration_no", "")).strip()[:100]
    try: lat, lng = float(b.get("latitude")), float(b.get("longitude"))
    except (TypeError, ValueError): return jsonify({"error":"ಮೊದಲು GPS ಸ್ಥಳವನ್ನು ಪಡೆದು ಸೇರಿಸಿ."}), 400
    if not (11.5 <= lat <= 18.5 and 74.0 <= lng <= 78.8): return jsonify({"error":"GPS ಸ್ಥಳ ಕರ್ನಾಟಕದ ವ್ಯಾಪ್ತಿಯಂತೆ ಕಾಣುತ್ತಿಲ್ಲ."}), 400
    if kind not in {"STORE","COMPANY","DISTRIBUTOR","FARMER_SELLER"}: return jsonify({"error":"ಅಮಾನ್ಯ business type."}), 400
    if not name or not contact or len(phone)<10 or not district or not city or len(address)<8: return jsonify({"error":"ಹೆಸರು, ಮೊಬೈಲ್, ಜಿಲ್ಲೆ, ನಗರ ಮತ್ತು ಸಂಪೂರ್ಣ ವಿಳಾಸ ಕಡ್ಡಾಯ."}), 400
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): return jsonify({"error":"ಸರಿಯಾದ business email ನಮೂದಿಸಿ."}), 400
    conn=connect()
    try:
        with conn.cursor() as cur:
            cur.execute("""INSERT INTO vendor_applications(user_id,business_type,business_name,contact_name,phone,business_email,district,city,address,category,registration_no,latitude,longitude,verification_status) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING')""",(g.user['id'],kind,name,contact,phone,email,district,city,address,category,registration_no or None,lat,lng))
            app_id=cur.lastrowid
        conn.commit(); return jsonify({"ok":True,"application_id":app_id,"verification_status":"PENDING","message":"ಅರ್ಜಿ ಸಲ್ಲಿಸಲಾಗಿದೆ. Admin ಪರಿಶೀಲನೆ ನಂತರವೇ ಅಂಗಡಿ ಸಾರ್ವಜನಿಕವಾಗಿ ಕಾಣಿಸುತ್ತದೆ."}),201
    except Exception:
        conn.rollback(); app.logger.exception("Vendor application failed"); return jsonify({"error":"ಅರ್ಜಿ ಉಳಿಸಲಾಗಲಿಲ್ಲ. vendor GPS migration ಚಲಾಯಿಸಿದ್ದೀರಾ ಪರಿಶೀಲಿಸಿ."}),500
    finally: conn.close()

@app.get("/api/vendor/mine")
@require_auth
def my_vendor_applications():
    conn=connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id,business_type,business_name,district,city,category,latitude,longitude,gps_verified,verification_status,admin_note,created_at FROM vendor_applications WHERE user_id=%s ORDER BY id DESC",(g.user['id'],)); rows=cur.fetchall()
        for r in rows:
            r['latitude']=float(r['latitude']); r['longitude']=float(r['longitude']); r['gps_verified']=bool(r['gps_verified']); r['created_at']=r['created_at'].isoformat(sep=' ',timespec='seconds')
        return jsonify(rows)
    finally: conn.close()

@app.get("/api/admin/vendor-applications")
@require_auth
def admin_vendor_applications():
    if not _is_admin(): return jsonify({"error":"Admin access required."}),403
    conn=connect()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT a.*,u.email AS applicant_email FROM vendor_applications a JOIN users u ON u.id=a.user_id ORDER BY (a.verification_status='PENDING') DESC,a.id DESC LIMIT 300"); rows=cur.fetchall()
        for r in rows:
            r['latitude']=float(r['latitude']); r['longitude']=float(r['longitude']); r['gps_verified']=bool(r['gps_verified']); r['created_at']=r['created_at'].isoformat(sep=' ',timespec='seconds')
            if r.get('reviewed_at'): r['reviewed_at']=r['reviewed_at'].isoformat(sep=' ',timespec='seconds')
        return jsonify(rows)
    finally: conn.close()

@app.patch("/api/admin/vendor-applications/<int:application_id>")
@require_auth
def admin_review_vendor_application(application_id):
    if not _is_admin(): return jsonify({"error":"Admin access required."}),403
    b=request.get_json(silent=True) or {}; status=str(b.get('verification_status','')).upper(); note=str(b.get('admin_note','')).strip()[:500]
    if status not in {'APPROVED','REJECTED','PENDING'}: return jsonify({"error":"Invalid verification status."}),400
    conn=connect()
    try:
        with conn.cursor() as cur:
            cur.execute('SELECT id FROM vendor_applications WHERE id=%s FOR UPDATE',(application_id,))
            if not cur.fetchone(): return jsonify({"error":"Application not found."}),404
            cur.execute("SELECT * FROM vendor_applications WHERE id=%s FOR UPDATE",(application_id,))
            vendor=cur.fetchone()
            store_id=vendor.get('store_id')
            if status == 'APPROVED' and not store_id:
                cur.execute("INSERT INTO stores(name,city,area,phone,is_open,delivery_minutes,latitude,longitude) VALUES(%s,%s,%s,%s,1,90,%s,%s)",(vendor['business_name'],vendor['city'],vendor['address'],vendor['phone'],vendor['latitude'],vendor['longitude']))
                store_id=cur.lastrowid
            cur.execute("UPDATE vendor_applications SET verification_status=%s,admin_note=%s,gps_verified=%s,reviewed_by=%s,reviewed_at=NOW(),store_id=%s WHERE id=%s",(status,note or None,1 if status=='APPROVED' else 0,g.user['id'],store_id,application_id))
        conn.commit(); return jsonify({"ok":True,"application_id":application_id,"store_id":store_id,"verification_status":status,"gps_verified":status=='APPROVED'})
    except Exception:
        conn.rollback(); app.logger.exception('Vendor review failed'); return jsonify({"error":"Could not review vendor application."}),500
    finally: conn.close()


if __name__ == "__main__":
    app.run(debug=True, port=5000)


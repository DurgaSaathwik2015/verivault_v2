from functools import wraps

from flask import Blueprint, request, jsonify, session
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from app.models import db, User
from app.ratelimit import limiter

MAX_PASSWORD_LENGTH = 128  # bounds password-hashing cost (DoS)
LOGIN_LIMIT_PER_ACCOUNT = 8     # failed attempts / 15 min per IP+email
LOGIN_LIMIT_PER_IP = 40         # failed attempts / 15 min per IP
# Used to spend the same time on unknown emails as on known ones.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def get_current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    user = db.session.get(User, user_id)

    if not user or not user.is_active:
        session.clear()
        return None

    # Session revocation: a cookie issued before the last bump is dead.
    if session.get("sv", 0) != user.session_version:
        session.clear()
        return None

    return user


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            return jsonify({"error": "Authentication required"}), 401

        return func(*args, **kwargs)

    return wrapper


def role_required(*allowed_roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()

            if not user:
                return jsonify({"error": "Authentication required"}), 401

            if user.role not in allowed_roles:
                return jsonify({"error": "Permission denied"}), 403

            return func(*args, **kwargs)

        return wrapper

    return decorator


def _clean_str(value):
    """Return a stripped string, or None if the value is not a string."""
    if not isinstance(value, str):
        return None
    return value.strip()


auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = {}

    username = _clean_str(data.get("username"))
    email = _clean_str(data.get("email"))
    password = data.get("password")

    # Non-string values (null, numbers, lists...) are rejected instead of
    # crashing with AttributeError / 500.
    if (
        not username
        or not email
        or not isinstance(password, str)
        or not password
    ):
        return jsonify({"error": "All fields are required"}), 400

    email = email.lower()

    if len(password) < 8:
        return jsonify({
            "error": "Password must contain at least 8 characters"
        }), 400

    if len(password) > MAX_PASSWORD_LENGTH or len(username) > 80 \
            or len(email) > 120:
        return jsonify({"error": "Input is too long"}), 400

    existing_user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()

    if existing_user:
        return jsonify({
            "error": "Username or email already exists"
        }), 409

    user = User(username=username, email=email, role="viewer")
    user.set_password(password)

    try:
        db.session.add(user)
        db.session.commit()
    except IntegrityError:
        # Two simultaneous registrations can pass the check above.
        db.session.rollback()
        return jsonify({
            "error": "Username or email already exists"
        }), 409

    return jsonify({
        "message": "Registration successful",
        "user": user.to_dict()
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        data = {}

    email = (_clean_str(data.get("email")) or "").lower()
    password = data.get("password")
    ip = request.remote_addr or "?"
    acct_key, ip_key = f"{ip}|{email}", f"{ip}|*"

    if (limiter.blocked(acct_key, LOGIN_LIMIT_PER_ACCOUNT)
            or limiter.blocked(ip_key, LOGIN_LIMIT_PER_IP)):
        return jsonify({
            "error": "Too many failed attempts. Try again in 15 minutes."
        }), 429

    if not email or not isinstance(password, str) \
            or len(password) > MAX_PASSWORD_LENGTH:
        limiter.record(ip_key)
        return jsonify({"error": "Invalid email or password"}), 401

    user = User.query.filter_by(email=email).first()

    if user is None:
        check_password_hash(_DUMMY_HASH, password)  # constant-ish timing
        ok = False
    else:
        ok = user.check_password(password)

    if not ok:
        limiter.record(acct_key)
        limiter.record(ip_key)
        return jsonify({"error": "Invalid email or password"}), 401

    if not user.is_active:
        return jsonify({"error": "Account is disabled"}), 403

    limiter.reset(acct_key)
    session.clear()
    session.permanent = True
    session["user_id"] = user.id
    session["sv"] = user.session_version

    return jsonify({
        "message": "Login successful",
        "user": user.to_dict()
    }), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    # Bump the version so a copied cookie cannot be replayed after logout.
    user = get_current_user()
    if user:
        user.session_version += 1
        db.session.commit()

    session.clear()

    return jsonify({"message": "Logout successful"}), 200


@auth_bp.route("/me", methods=["GET"])
def current_user():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Authentication required"}), 401

    return jsonify({"user": user.to_dict()}), 200



@auth_bp.route("/change-password", methods=["POST"])
def change_password():
    user = get_current_user()

    if not user:
        return jsonify({"error": "Authentication required"}), 401

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}

    current = data.get("current_password")
    new = data.get("new_password")

    if not isinstance(current, str) or not user.check_password(current):
        return jsonify({"error": "Current password is incorrect"}), 403

    if not isinstance(new, str) or not 8 <= len(new) <= MAX_PASSWORD_LENGTH:
        return jsonify({
            "error": "New password must be 8 to 128 characters"
        }), 400

    user.set_password(new)
    user.session_version += 1          # logs out every other session
    db.session.commit()
    session["sv"] = user.session_version  # keep this one

    return jsonify({"message": "Password changed"}), 200

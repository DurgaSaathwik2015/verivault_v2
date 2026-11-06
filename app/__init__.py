import os
import secrets
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_from_directory

from app.models import db


def _load_secret_key(instance_path):
    """SECRET_KEY from the environment, else a random key generated once and
    kept in the instance folder. There is deliberately NO hard-coded default:
    a public default would let anyone forge a session cookie."""
    from_env = os.environ.get("SECRET_KEY")
    if from_env:
        return from_env
    key_file = Path(instance_path) / "secret.key"
    if key_file.exists():
        return key_file.read_text().strip()
    key = secrets.token_hex(32)
    key_file.write_text(key)
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass
    return key


def create_app(test_config=None):
    data_dir = os.environ.get("DATA_DIR")
    app = Flask(
        __name__,
        instance_relative_config=True,
        instance_path=os.path.abspath(data_dir) if data_dir else None,
    )
    os.makedirs(app.instance_path, exist_ok=True)

    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///trustvault.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = (
        os.environ.get("COOKIE_SECURE", "").lower() == "true"
    )
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
    app.config["MAX_CONTENT_LENGTH"] = 11 * 1024 * 1024  # 10 MB file + form
    app.config["DEMO_MODE"] = os.environ.get("VERIVAULT_DEMO", "") == "1"

    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_secret_key(app.instance_path)

    if os.environ.get("TRUST_PROXY") == "1":
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    from app.ratelimit import limiter
    limiter.clear()

    db.init_app(app)

    from app import models  # noqa: F401  (registers tables + audit triggers)
    from app.admin import admin_bp
    from app.audit import register_audit_hooks
    from app.auth import auth_bp
    from app.documents import documents_bp
    from app.sharing import sharing_bp

    # ---- Cross-site request protection (defence in depth over SameSite) ----
    @app.before_request
    def block_cross_site_writes():
        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if request.headers.get("Sec-Fetch-Site") == "cross-site":
                return jsonify({"error": "Cross-site request blocked"}), 403
            origin = request.headers.get("Origin")
            if origin and urlparse(origin).netloc != request.host:
                return jsonify({"error": "Cross-site request blocked"}), 403

    # Registered BEFORE the audit hook so it runs AFTER it (Flask runs
    # after_request handlers in reverse order) and also covers 503 replies.
    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'",
        )
        if not request.path.startswith("/static/") and request.path != "/":
            resp.headers.setdefault("Cache-Control", "no-store")
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000"
            )
        return resp

    app.register_blueprint(admin_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(sharing_bp)
    register_audit_hooks(app)

    @app.errorhandler(413)
    def too_large(_e):
        return jsonify({"error": "File exceeds the 10 MB limit"}), 413

    with app.app_context():
        db.create_all()  # safe to repeat; creates tables + audit triggers
        if os.environ.get("SEED_DEMO") == "1":
            from app.seed import seed_demo
            seed_demo()

    register_cli(app)

    @app.route("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/health")
    def health():
        return {"status": "healthy", "application": "TrustVault"}

    return app


def register_cli(app):
    import click

    from app.models import User

    @app.cli.command("set-role")
    @click.argument("email")
    @click.argument("role", type=click.Choice(["viewer", "owner", "admin"]))
    def set_role(email, role):
        """Promote/demote a user: flask --app run set-role EMAIL ROLE"""
        user = User.query.filter_by(email=email.strip().lower()).first()
        if user is None:
            raise click.ClickException(f"No user with email {email}")
        user.role = role
        user.session_version += 1
        db.session.commit()
        click.echo(f"{user.email} is now '{role}'")

    @app.cli.command("seed-demo")
    def seed_cmd():
        """Create demo users + sample documents (idempotent)."""
        from app.seed import seed_demo
        seed_demo()
        click.echo("Demo data ready.")

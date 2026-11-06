"""Admin, audit and helper endpoints.

The administrator manages ACCOUNTS and oversees ACTIVITY. An admin cannot
read, download, edit or delete any document unless an owner grants them
access like anyone else (least privilege) - see authz.py.
"""

from datetime import timedelta

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import func

from app.audit import chain_head, verify_chain
from app.auth import get_current_user, role_required
from app.models import AuditLog, Document, Grant, User, current_utc_time, db

admin_bp = Blueprint("admin", __name__)

ROLES = {"viewer", "owner", "admin"}


@admin_bp.route("/config", methods=["GET"])
def public_config():
    return jsonify({"demo_mode": bool(current_app.config.get("DEMO_MODE"))})


@admin_bp.route("/auth/demo-owner", methods=["POST"])
def demo_owner():
    """Self-service viewer -> owner. Only when VERIVAULT_DEMO=1."""
    if not current_app.config.get("DEMO_MODE"):
        return jsonify({"error": "Not available"}), 403
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    if user.role == "viewer":
        user.role = "owner"
        db.session.commit()
    return jsonify({"user": user.to_dict()}), 200


@admin_bp.route("/users", methods=["GET"])
def list_users():
    """Usernames for the share dialog. Owners and admins only, so a plain
    viewer cannot harvest the user directory."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401
    if user.role not in {"owner", "admin"}:
        return jsonify({"error": "Permission denied"}), 403
    q = (request.args.get("q") or "").strip()[:100]
    query = User.query.filter(User.is_active.is_(True), User.id != user.id)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(User.username.ilike(f"%{escaped}%", escape="\\"))
    rows = query.order_by(User.username).limit(50).all()
    return jsonify({"users": [{"id": u.id, "username": u.username} for u in rows]}), 200


# ----------------------------- admin: accounts -----------------------------

@admin_bp.route("/admin/users", methods=["GET"])
@role_required("admin")
def admin_list_users():
    counts = dict(db.session.query(Document.owner_id, func.count(Document.id))
                  .group_by(Document.owner_id).all())
    return jsonify({"users": [{
        **u.to_dict(), "documents": counts.get(u.id, 0),
    } for u in User.query.order_by(User.id).all()]}), 200


@admin_bp.route("/admin/users/<int:user_id>", methods=["PATCH"])
@role_required("admin")
def admin_update_user(user_id):
    """Change a user's role or enable/disable them. Takes effect at once:
    the user's existing sessions are revoked."""
    admin = get_current_user()
    target = db.session.get(User, user_id)
    if target is None:
        return jsonify({"error": "User not found"}), 404
    if target.id == admin.id:
        return jsonify({"error": "You cannot change your own account"}), 400

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not data \
            or not set(data) <= {"role", "is_active"}:
        return jsonify({"error": "Provide 'role' and/or 'is_active'"}), 400

    if "role" in data:
        if data["role"] not in ROLES:
            return jsonify({"error": "Invalid role"}), 400
        target.role = data["role"]
    if "is_active" in data:
        if not isinstance(data["is_active"], bool):
            return jsonify({"error": "is_active must be true or false"}), 400
        target.is_active = data["is_active"]

    target.session_version += 1  # kick existing sessions
    db.session.commit()
    return jsonify({"user": target.to_dict()}), 200


@admin_bp.route("/admin/documents", methods=["GET"])
@role_required("admin")
def admin_list_documents():
    """Document METADATA and who has access. Never file content."""
    grants = {}
    for g, name in db.session.query(Grant, User.username).join(
            User, User.id == Grant.user_id).all():
        grants.setdefault(g.document_id, []).append(
            {"username": name, "permission": g.permission})
    rows = db.session.query(Document, User.username).join(
        User, User.id == Document.owner_id
    ).order_by(Document.created_at.desc()).limit(500).all()
    return jsonify({"documents": [{
        "id": d.id, "filename": d.original_filename, "owner": owner,
        "category": d.category, "size": d.size,
        "created_at": d.created_at.isoformat(),
        "shared_with": grants.get(d.id, []),
    } for d, owner in rows]}), 200


@admin_bp.route("/admin/summary", methods=["GET"])
@role_required("admin")
def admin_summary():
    """Headline numbers and 'worth noticing' alerts for the last 24 hours."""
    since = current_utc_time() - timedelta(hours=24)
    recent = AuditLog.query.filter(AuditLog.created_at >= since)
    names = {u.id: u.username for u in User.query.all()}

    def count(action=None, outcome=None):
        q = recent
        if action:
            q = q.filter(AuditLog.action == action)
        if outcome:
            q = q.filter(AuditLog.outcome == outcome)
        return q.count()

    alerts = []
    denied = dict(db.session.query(AuditLog.actor_id, func.count(AuditLog.id))
                  .filter(AuditLog.created_at >= since,
                          AuditLog.outcome == "denied",
                          AuditLog.action != "login",
                          AuditLog.actor_id.isnot(None))
                  .group_by(AuditLog.actor_id).all())
    for uid, n in denied.items():
        if n >= 5:
            alerts.append(f"{names.get(uid, uid)} was refused {n} times on "
                          f"documents in 24h (possible probing)")
    failed = count("login", "denied")
    if failed >= 5:
        alerts.append(f"{failed} failed or blocked logins in 24h")
    if not verify_chain():
        alerts.append("AUDIT CHAIN BROKEN - history may have been altered")

    total, head = chain_head()
    return jsonify({
        "users": User.query.count(), "documents": Document.query.count(),
        "grants": Grant.query.count(),
        "last_24h": {
            "downloads": count("download", "success"),
            "refused": count(outcome="denied"),
            "permission_changes": count("grant") + count("revoke"),
            "failed_logins": failed,
        },
        "alerts": alerts,
        "audit": {"entries": total, "head": head},
    }), 200


# --------------------------------- audit ----------------------------------

@admin_bp.route("/audit", methods=["GET"])
def audit_feed():
    """Admins see everything; others see their own actions and events on
    documents they currently own. Optional filters: action, outcome."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Authentication required"}), 401

    query = AuditLog.query
    if user.role != "admin":
        owned = [d.id for d in Document.query.filter_by(owner_id=user.id).all()]
        cond = AuditLog.actor_id == user.id
        if owned:
            cond = cond | AuditLog.document_id.in_(owned)
        query = query.filter(cond)

    action = (request.args.get("action") or "").strip()[:50]
    outcome = (request.args.get("outcome") or "").strip()
    if action:
        query = query.filter(AuditLog.action == action)
    if outcome in {"success", "denied", "failure"}:
        query = query.filter(AuditLog.outcome == outcome)

    rows = query.order_by(AuditLog.id.desc()).limit(200).all()
    names = {u.id: u.username for u in User.query.filter(
        User.id.in_({r.actor_id for r in rows if r.actor_id})).all()} if rows else {}

    total, head = chain_head()
    return jsonify({
        "chain_valid": verify_chain(),
        "scope": "all" if user.role == "admin" else "mine",
        "head": {"entries": total, "hash": head},
        "entries": [{
            "id": r.id,
            "actor": names.get(r.actor_id, "anonymous" if r.actor_id is None else f"user #{r.actor_id}"),
            "document_id": r.document_id,
            "action": r.action,
            "outcome": r.outcome,
            "details": r.details if user.role == "admin" else None,
            "hash": r.entry_hash[:12],
            "created_at": r.created_at.isoformat(),
        } for r in rows],
    }), 200

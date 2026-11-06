"""Append-only, hash-chained audit logging for TrustVault."""

import hashlib
import json
import threading
from datetime import timezone

from sqlalchemy import DDL, event

from app.models import AuditLog, db, current_utc_time

# Prevent two threads in this process from selecting the same previous hash.
# A production multi-worker deployment should additionally use a DB-level
# serialized writer/transaction strategy.
_audit_lock = threading.RLock()


def _normalise_datetime(value):
    """Return a stable ISO-8601 representation for hashing."""
    if value.tzinfo is None:
        # SQLite commonly returns naive datetimes for timezone=True columns.
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def calculate_entry_hash(
    actor_id,
    document_id,
    action,
    outcome,
    details,
    previous_hash,
    created_at,
):
    payload = {
        "actor_id": actor_id,
        "document_id": document_id,
        "action": action,
        "outcome": outcome,
        "details": details,
        "previous_hash": previous_hash,
        "created_at": _normalise_datetime(created_at),
    }
    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def record_audit(actor_id, document_id, action, outcome, details=None):
    """Append and commit one audit row. Never update an existing row."""
    if outcome not in {"success", "denied", "failure"}:
        raise ValueError("Invalid audit outcome")
    if not isinstance(action, str) or not action.strip():
        raise ValueError("Audit action is required")

    # Keep details compact and deterministic; callers must not pass secrets.
    if details is not None and not isinstance(details, str):
        details = json.dumps(details, sort_keys=True, separators=(",", ":"))

    with _audit_lock:
        try:
            latest = AuditLog.query.order_by(AuditLog.id.desc()).first()
            previous_hash = latest.entry_hash if latest else None
            created_at = current_utc_time()
            entry_hash = calculate_entry_hash(
                actor_id, document_id, action, outcome, details,
                previous_hash, created_at,
            )
            entry = AuditLog(
                actor_id=actor_id,
                document_id=document_id,
                action=action,
                outcome=outcome,
                details=details,
                previous_hash=previous_hash,
                entry_hash=entry_hash,
                created_at=created_at,
            )
            db.session.add(entry)
            db.session.commit()
            return entry
        except Exception:
            db.session.rollback()
            raise


def verify_chain():
    """Return True only when every row and previous-hash link is valid."""
    entries = AuditLog.query.order_by(AuditLog.id.asc()).all()
    expected_previous_hash = None

    for entry in entries:
        if entry.previous_hash != expected_previous_hash:
            return False
        expected_hash = calculate_entry_hash(
            actor_id=entry.actor_id,
            document_id=entry.document_id,
            action=entry.action,
            outcome=entry.outcome,
            details=entry.details,
            previous_hash=entry.previous_hash,
            created_at=entry.created_at,
        )
        if entry.entry_hash != expected_hash:
            return False
        expected_previous_hash = entry.entry_hash
    return True


# ORM-level protection.
@event.listens_for(AuditLog, "before_update")
def _prevent_audit_update(mapper, connection, target):
    raise ValueError("Audit records cannot be updated")


@event.listens_for(AuditLog, "before_delete")
def _prevent_audit_delete(mapper, connection, target):
    raise ValueError("Audit records cannot be deleted")


# SQLite database-level protection. These triggers also block raw SQL UPDATE
# and DELETE statements, not just SQLAlchemy ORM operations.
event.listen(
    AuditLog.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS prevent_audit_update "
        "BEFORE UPDATE ON audit_logs BEGIN "
        "SELECT RAISE(ABORT, 'audit records are immutable'); END"
    ).execute_if(dialect="sqlite"),
)
event.listen(
    AuditLog.__table__,
    "after_create",
    DDL(
        "CREATE TRIGGER IF NOT EXISTS prevent_audit_delete "
        "BEFORE DELETE ON audit_logs BEGIN "
        "SELECT RAISE(ABORT, 'audit records are immutable'); END"
    ).execute_if(dialect="sqlite"),
)


def chain_head():
    """(entry count, hash of the newest entry). Publish it somewhere the
    database owner cannot edit to make tail-truncation detectable."""
    latest = AuditLog.query.order_by(AuditLog.id.desc()).first()
    return AuditLog.query.count(), (latest.entry_hash if latest else None)


# Endpoint function name -> audit action name.
ENDPOINT_ACTIONS = {
    "upload_document": "upload",
    "download_document": "download",
    "edit_document": "change",
    "delete_document": "delete",
    "share_document": "grant",
    "revoke_document_access": "revoke",
    "login": "login",
    "logout": "logout",
    "register": "register",
    "change_password": "password_change",
    "admin_update_user": "user_admin_change",
    "demo_owner": "role_change_demo",
}


def _extra_details(endpoint, response):
    """Small, validated, secret-free facts that make an entry provable."""
    from flask import request

    extra = {}
    body = request.get_json(silent=True) if request.is_json else None
    body = body if isinstance(body, dict) else {}
    view_args = request.view_args or {}

    if endpoint == "share_document":
        uid = body.get("user_id")
        if isinstance(uid, int) and not isinstance(uid, bool):
            extra["target_user_id"] = uid
        perm = body.get("permission")
        if isinstance(perm, str) and perm in {"read", "edit"}:
            extra["permission"] = perm
    elif endpoint == "revoke_document_access":
        extra["target_user_id"] = view_args.get("target_user_id")
    elif endpoint == "edit_document":
        extra["fields"] = sorted(k for k in body if k in {"filename", "category"})
    elif endpoint == "admin_update_user":
        extra["target_user_id"] = view_args.get("user_id")
        role = body.get("role")
        if isinstance(role, str) and role in {"viewer", "owner", "admin"}:
            extra["role"] = role
        if isinstance(body.get("is_active"), bool):
            extra["is_active"] = body["is_active"]
    elif endpoint == "login" and response.status_code >= 400:
        email = body.get("email")
        if isinstance(email, str):
            extra["email"] = email.strip().lower()[:120]
    return extra


def register_audit_hooks(app):
    """Audit sensitive API actions centrally, including refused ones.

    FAIL-CLOSED: if the audit row cannot be written, the response is
    replaced with a 503 so a file is never delivered without a record.
    """
    from flask import g, jsonify, request, session
    from app.models import User

    @app.before_request
    def remember_actor():
        # Captured up-front because logout/disable clear the session.
        g.audit_actor_id = session.get("user_id")

    @app.after_request
    def audit_sensitive_request(response):
        endpoint = (request.endpoint or "").rsplit(".", 1)[-1]
        action = ENDPOINT_ACTIONS.get(endpoint)
        if action is None:
            return response

        if action == "login":
            actor_id = session.get("user_id")  # set only on success
        else:
            actor_id = g.get("audit_actor_id", session.get("user_id"))
        if actor_id is not None and db.session.get(User, actor_id) is None:
            actor_id = None

        document_id = (request.view_args or {}).get("document_id")
        if document_id is None and action == "upload" and response.is_json:
            try:
                document_id = response.get_json(silent=True).get("document_id")
            except (AttributeError, TypeError):
                document_id = None

        if response.status_code in {401, 403, 404, 429}:
            outcome = "denied"
        elif 200 <= response.status_code < 400:
            outcome = "success"
        else:
            outcome = "failure"

        details = {
            "method": request.method,
            "endpoint": endpoint,
            "http_status": response.status_code,
        }
        details.update(_extra_details(endpoint, response))

        try:
            record_audit(actor_id, document_id, action, outcome, details)
        except Exception:
            app.logger.exception("Audit write failed; failing closed")
            try:
                response.close()
            except Exception:
                pass
            blocked = jsonify({
                "error": "Audit log unavailable; request not completed"
            })
            blocked.status_code = 503
            return blocked
        return response

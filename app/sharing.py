from flask import Blueprint, request, jsonify

from app.models import db, Document, Grant, User
from app.auth import get_current_user


sharing_bp = Blueprint("sharing", __name__, url_prefix="/documents")


def get_owned_document(user, document_id):
    """Return the document only if the current user owns it."""
    document = db.session.get(Document, document_id)

    if document is None or document.owner_id != user.id:
        return None

    return document


@sharing_bp.route("/<int:document_id>/share", methods=["POST"])
def share_document(document_id):
    """Grant read or edit access to another user."""
    user = get_current_user()

    if user is None:
        return jsonify({"error": "Authentication required"}), 401

    document = get_owned_document(user, document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    user_id = data.get("user_id")
    permission = data.get("permission")

    if isinstance(user_id, bool) or not isinstance(user_id, int):
        return jsonify({"error": "A valid user_id is required"}), 400

    if not isinstance(permission, str) or permission not in {"read", "edit"}:
        return jsonify({
            "error": "Permission must be 'read' or 'edit'"
        }), 400

    target_user = db.session.get(User, user_id)

    if target_user is None or not target_user.is_active:
        return jsonify({"error": "Active target user not found"}), 404

    if target_user.id == user.id:
        return jsonify({"error": "You already own this document"}), 400

    grant = Grant.query.filter_by(
        document_id=document.id,
        user_id=target_user.id
    ).first()

    if grant is None:
        grant = Grant(
            document_id=document.id,
            user_id=target_user.id,
            permission=permission
        )
        db.session.add(grant)
    else:
        grant.permission = permission

    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Unable to update document access"}), 500

    return jsonify({
        "message": "Document access granted",
        "document_id": document.id,
        "user_id": target_user.id,
        "permission": grant.permission
    }), 200


@sharing_bp.route("/<int:document_id>/permissions", methods=["GET"])
def list_permissions(document_id):
    """List users who have access to an owned document."""
    user = get_current_user()

    if user is None:
        return jsonify({"error": "Authentication required"}), 401

    document = get_owned_document(user, document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    grants = Grant.query.filter_by(document_id=document.id).all()

    permissions = []

    for grant in grants:
        target_user = db.session.get(User, grant.user_id)

        if target_user is not None:
            permissions.append({
                "user_id": target_user.id,
                "username": target_user.username,
                "permission": grant.permission
            })

    return jsonify({
        "document_id": document.id,
        "permissions": permissions
    }), 200


@sharing_bp.route(
    "/<int:document_id>/share/<int:target_user_id>",
    methods=["DELETE"]
)
def revoke_document_access(document_id, target_user_id):
    """Revoke a user's access to an owned document."""
    user = get_current_user()

    if user is None:
        return jsonify({"error": "Authentication required"}), 401

    document = get_owned_document(user, document_id)

    if document is None:
        return jsonify({"error": "Document not found"}), 404

    grant = Grant.query.filter_by(
        document_id=document.id,
        user_id=target_user_id
    ).first()

    if grant is None:
        return jsonify({"error": "Access grant not found"}), 404

    try:
        db.session.delete(grant)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return jsonify({"error": "Unable to revoke document access"}), 500

    return jsonify({
        "message": "Document access revoked",
        "document_id": document.id,
        "user_id": target_user_id
    }), 200
from werkzeug.utils import secure_filename
import uuid


from datetime import date, datetime, timedelta, timezone
from pathlib import Path


from flask import (
    Blueprint,
    request,
    jsonify,
    current_app,
    send_file
)


from sqlalchemy import or_


from app.models import db, Document, Grant, User
from app.auth import get_current_user
from app.validation import validate_upload
from app.authz import authorize



documents_bp = Blueprint(
    "documents",
    __name__,
    url_prefix="/documents"
)



def get_private_storage():
    storage_path = Path(
        current_app.instance_path
    ) / "uploads"


    storage_path.mkdir(
        parents=True,
        exist_ok=True
    )


    return storage_path



def _like(value):
    """Escape LIKE wildcards so user input is matched literally."""
    escaped = (value.replace("\\", "\\\\")
                    .replace("%", "\\%").replace("_", "\\_"))
    return f"%{escaped}%"


def _parse_day(value):
    return date.fromisoformat(value)  # raises ValueError on bad input


@documents_bp.route("", methods=["GET"], strict_slashes=False)
def list_documents():
    """List/search documents. Filters (all optional, combinable):
    q (name), owner (username), category, date_from, date_to (YYYY-MM-DD).
    Filters only narrow the set the caller is ALREADY allowed to read."""
    user = get_current_user()

    if not user:
        return jsonify({
            "error": "Authentication required"
        }), 401

    q = (request.args.get("q") or "").strip()
    owner = (request.args.get("owner") or "").strip()
    category = (request.args.get("category") or "").strip()

    if max(len(q), len(owner), len(category)) > 100:
        return jsonify({"error": "Search text is too long"}), 400

    try:
        date_from = _parse_day(request.args["date_from"]) \
            if request.args.get("date_from") else None
        date_to = _parse_day(request.args["date_to"]) \
            if request.args.get("date_to") else None
        limit = min(max(int(request.args.get("limit", 100)), 1), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify({
            "error": "Dates must be YYYY-MM-DD; limit/offset must be numbers"
        }), 400

    query = Document.query.join(
        User, User.id == Document.owner_id
    ).outerjoin(
        Grant,
        Grant.document_id == Document.id
    ).filter(
        or_(
            Document.owner_id == user.id,
            Grant.user_id == user.id
        )
    )

    if q:
        query = query.filter(
            Document.original_filename.ilike(_like(q), escape="\\"))
    if owner:
        query = query.filter(User.username.ilike(_like(owner), escape="\\"))
    if category:
        query = query.filter(
            Document.category.ilike(_like(category), escape="\\"))
    if date_from:
        query = query.filter(Document.created_at >= datetime(
            date_from.year, date_from.month, date_from.day,
            tzinfo=timezone.utc))
    if date_to:
        end = datetime(date_to.year, date_to.month, date_to.day,
                       tzinfo=timezone.utc) + timedelta(days=1)
        query = query.filter(Document.created_at < end)

    documents = query.distinct().order_by(
        Document.created_at.desc()
    ).limit(limit).offset(offset).all()

    results = []

    for document in documents:
        # The server re-checks every row; the SQL above is only a filter.
        if not authorize(user, document, "read"):
            continue

        if document.owner_id == user.id:
            access = "owner"
        else:
            grant = Grant.query.filter_by(
                document_id=document.id, user_id=user.id
            ).first()
            access = grant.permission if grant else "read"

        results.append({
            "access": access,
            "owner": document.owner.username,
            "id": document.id,
            "filename": document.original_filename,
            "size": document.size,
            "category": document.category,
            "created_at": document.created_at.isoformat()
        })

    return jsonify({
        "documents": results
    }), 200



@documents_bp.route("/upload", methods=["POST"])
def upload_document():
    user = get_current_user()


    if not user:
        return jsonify({
            "error": "Authentication required"
        }), 401


    if user.role != "owner":
        return jsonify({
            "error": "Only document owners can upload files"
        }), 403


    if "file" not in request.files:
        return jsonify({
            "error": "No file part in request"
        }), 400


    file = request.files["file"]


    valid, result = validate_upload(file)


    if not valid:
        return jsonify({
            "error": result
        }), 400


    storage_name = uuid.uuid4().hex + "." + result["extension"]
    storage_path = get_private_storage() / storage_name


    document = Document(
        owner_id=user.id,
        original_filename=result["original_filename"],
        storage_filename=storage_name,
        content_type="application/octet-stream",
        size=result["size"]
    )


    # Check the document's authorization before storing it.
    if not authorize(user, document, "edit"):
        return jsonify({
            "error": "Permission denied"
        }), 403


    try:
        file.save(storage_path)


        db.session.add(document)
        db.session.commit()


    except Exception:
        db.session.rollback()


        if storage_path.exists():
            storage_path.unlink()


        current_app.logger.exception(
            "Document upload failed"
        )


        return jsonify({
            "error": "Document upload failed"
        }), 500


    return jsonify({
        "message": "Document uploaded successfully",
        "document_id": document.id,
        "filename": document.original_filename
    }), 201



@documents_bp.route("/<int:document_id>/download", methods=["GET"])
def download_document(document_id):
    user = get_current_user()


    if not user:
        return jsonify({
            "error": "Authentication required"
        }), 401


    document = db.session.get(Document, document_id)


    if not document:
        return jsonify({
            "error": "Document not found"
        }), 404


    # Check authorization on every download request.
    if not authorize(user, document, "read"):
        return jsonify({
            "error": "Document not found"
        }), 404


    storage_path = get_private_storage() / document.storage_filename


    if not storage_path.is_file():
        return jsonify({
            "error": "Document not found"
        }), 404


    response = send_file(
        storage_path,
        as_attachment=True,
        download_name=document.original_filename,
        mimetype="application/octet-stream"
    )


    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"


    return response



@documents_bp.route("/<int:document_id>", methods=["DELETE"])
def delete_document(document_id):
    user = get_current_user()


    if not user:
        return jsonify({
            "error": "Authentication required"
        }), 401


    document = db.session.get(Document, document_id)


    if not document:
        return jsonify({
            "error": "Document not found"
        }), 404


    if not authorize(user, document, "delete"):
        return jsonify({
            "error": "Document not found"
        }), 404


    storage_path = get_private_storage() / document.storage_filename


    try:
        db.session.delete(document)
        db.session.commit()


    except Exception:
        db.session.rollback()


        current_app.logger.exception(
            "Document deletion failed"
        )


        return jsonify({
            "error": "Document deletion failed"
        }), 500


    # Remove the file only after the DB commit succeeded, so a failed
    # commit can never leave a record pointing at a deleted file.
    try:
        if storage_path.is_file():
            storage_path.unlink()
    except OSError:
        current_app.logger.exception(
            "Orphaned file could not be removed"
        )


    return jsonify({
        "message": "Document deleted successfully"
    }), 200



@documents_bp.route("/<int:document_id>", methods=["PATCH"])
def edit_document(document_id):
    user = get_current_user()


    if not user:
        return jsonify({
            "error": "Authentication required"
        }), 401


    document = db.session.get(Document, document_id)


    if not document:
        return jsonify({
            "error": "Document not found"
        }), 404


    # Centralized authorization check.
    if not authorize(user, document, "edit"):
        return jsonify({
            "error": "Document not found"
        }), 404


    data = request.get_json(silent=True)


    if not isinstance(data, dict) or not data:
        return jsonify({
            "error": "A JSON object with editable fields is required"
        }), 400


    allowed_fields = {"filename", "category"}


    if not set(data.keys()).issubset(allowed_fields):
        return jsonify({
            "error": "Unsupported field"
        }), 400


    if "filename" in data:
        filename = data["filename"]


        if not isinstance(filename, str) or not filename.strip():
            return jsonify({
                "error": "Filename must be a non-empty string"
            }), 400


        safe_filename = secure_filename(filename)


        if not safe_filename or "." not in safe_filename:
            return jsonify({
                "error": "Invalid filename"
            }), 400


        if len(safe_filename) > 255:
            return jsonify({
                "error": "Filename is too long"
            }), 400


        document.original_filename = safe_filename


    if "category" in data:
        category = data["category"]


        if not isinstance(category, str) or not category.strip():
            return jsonify({
                "error": "Category must be a non-empty string"
            }), 400


        if len(category.strip()) > 100:
            return jsonify({
                "error": "Category is too long"
            }), 400


        document.category = category.strip()


    try:
        db.session.commit()


    except Exception:
        db.session.rollback()


        current_app.logger.exception(
            "Document update failed"
        )


        return jsonify({
            "error": "Document update failed"
        }), 500


    return jsonify({
        "message": "Document updated successfully",
        "document": {
            "id": document.id,
            "filename": document.original_filename,
            "category": document.category
        }
    }), 200
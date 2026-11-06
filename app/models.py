
from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint, UniqueConstraint, Index
from werkzeug.security import generate_password_hash, check_password_hash


db = SQLAlchemy()


def current_utc_time():
    return datetime.now(timezone.utc)


# --------------------------------------------------
# USER MODEL
# --------------------------------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80), unique=True, nullable=False, index=True
    )

    email = db.Column(
        db.String(120), unique=True, nullable=False, index=True
    )

    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False, default="viewer")

    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Bumped on logout, password change, role change and deactivation.
    # Every session cookie carries the value it was issued under, so
    # bumping it revokes all previously issued sessions immediately.
    session_version = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=current_utc_time,
        nullable=False
    )

    owned_documents = db.relationship(
        "Document",
        back_populates="owner",
        foreign_keys="Document.owner_id"
    )

    grants = db.relationship(
        "Grant",
        back_populates="user",
        cascade="all, delete-orphan"
    )

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat()
        }


# --------------------------------------------------
# DOCUMENT MODEL
# --------------------------------------------------

class Document(db.Model):
    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True
    )

    original_filename = db.Column(db.String(255), nullable=False)

    storage_filename = db.Column(
        db.String(255), unique=True, nullable=False
    )

    content_type = db.Column(db.String(100), nullable=False)

    size = db.Column(db.Integer, nullable=False)

    category = db.Column(db.String(80), nullable=True, index=True)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=current_utc_time,
        nullable=False,
        index=True
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=current_utc_time,
        onupdate=current_utc_time,
        nullable=False
    )

    owner = db.relationship(
        "User",
        back_populates="owned_documents",
        foreign_keys=[owner_id]
    )

    grants = db.relationship(
        "Grant",
        back_populates="document",
        cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "size > 0",
            name="check_document_size_positive"
        ),
        Index(
            "ix_documents_owner_created",
            "owner_id",
            "created_at"
        ),
    )


# --------------------------------------------------
# GRANT MODEL
# --------------------------------------------------

class Grant(db.Model):
    __tablename__ = "grants"

    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False
    )

    permission = db.Column(db.String(20), nullable=False)

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=current_utc_time,
        nullable=False
    )

    document = db.relationship(
        "Document",
        back_populates="grants"
    )

    user = db.relationship(
        "User",
        back_populates="grants"
    )

    __table_args__ = (
        UniqueConstraint(
            "document_id",
            "user_id",
            name="unique_document_user_grant"
        ),
        CheckConstraint(
            "permission IN ('read', 'edit')",
            name="check_grant_permission"
        ),
        Index(
            "ix_grants_user_document",
            "user_id",
            "document_id"
        ),
    )


# --------------------------------------------------
# AUDIT LOG MODEL
# --------------------------------------------------

class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    # Historical IDs: intentionally no foreign keys.
    actor_id = db.Column(db.Integer, nullable=True, index=True)

    document_id = db.Column(db.Integer, nullable=True, index=True)

    action = db.Column(db.String(50), nullable=False)

    outcome = db.Column(db.String(20), nullable=False)

    details = db.Column(db.Text, nullable=True)

    previous_hash = db.Column(db.String(64), nullable=True)

    entry_hash = db.Column(
        db.String(64),
        nullable=False,
        unique=True
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        default=current_utc_time,
        nullable=False,
        index=True
    )

    __table_args__ = (
        CheckConstraint(
            "outcome IN ('success', 'denied', 'failure')",
            name="check_audit_outcome"
        ),
        Index(
            "ix_audit_action_created",
            "action",
            "created_at"
        ),
    )

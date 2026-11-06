"""Idempotent demo data: one account per role, plus sample documents."""

from pathlib import Path

from flask import current_app

from app.audit import record_audit
from app.models import Document, Grant, User, db

DEMO_USERS = [
    ("admin",   "admin@vault.test",   "Admin#Demo2026",   "admin"),
    ("owner",   "owner@vault.test",   "Owner#Demo2026",   "owner"),
    ("viewer",  "viewer@vault.test",  "Viewer#Demo2026",  "viewer"),
    ("partner", "partner@vault.test", "Partner#Demo2026", "viewer"),
]

# (stored name, shown name, category, text, {username: permission})
DEMO_DOCS = [
    ("seed-salary-letter.txt", "salary-letter.txt", "HR",
     "Confidential: salary letter for the employee.\n", {"viewer": "read"}),
    ("seed-contract-draft.txt", "contract-draft.txt", "Contracts",
     "Draft customer contract. Partner may edit the metadata.\n",
     {"partner": "edit"}),
    ("seed-board-minutes.txt", "board-minutes.txt", "Board",
     "Private board minutes. Shared with nobody.\n", {}),
]


def seed_demo():
    storage = Path(current_app.instance_path) / "uploads"
    storage.mkdir(parents=True, exist_ok=True)

    users = {}
    for username, email, password, role in DEMO_USERS:
        user = User.query.filter_by(email=email).first()
        if user is None:
            user = User(username=username, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
        users[username] = user

    owner = users["owner"]
    for stored, shown, category, text, grants in DEMO_DOCS:
        (storage / stored).write_text(text, encoding="utf-8")  # always restore
        doc = Document.query.filter_by(storage_filename=stored).first()
        if doc is not None:
            continue
        doc = Document(owner_id=owner.id, original_filename=shown,
                       storage_filename=stored, category=category,
                       content_type="application/octet-stream",
                       size=len(text.encode()))
        db.session.add(doc)
        db.session.commit()
        record_audit(owner.id, doc.id, "upload", "success",
                     {"method": "POST", "endpoint": "seed", "http_status": 201})
        for username, perm in grants.items():
            db.session.add(Grant(document_id=doc.id,
                                 user_id=users[username].id, permission=perm))
            db.session.commit()
            record_audit(owner.id, doc.id, "grant", "success", {
                "method": "POST", "endpoint": "seed", "http_status": 200,
                "target_user_id": users[username].id, "permission": perm})

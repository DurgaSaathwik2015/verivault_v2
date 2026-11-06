import pytest
from sqlalchemy import text

from app import create_app
from app.models import db, User, Document, AuditLog
from app.audit import record_audit, verify_chain


@pytest.fixture
def app(tmp_path):
    database_path = (tmp_path / "audit_test.db").as_posix()
    test_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "audit-test-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })
    with test_app.app_context():
        db.create_all()
        owner = User(username="owner", email="owner@test.com", role="owner")
        owner.set_password("Owner@12345")
        db.session.add(owner)
        db.session.commit()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def test_audit_entries_form_valid_hash_chain(app):
    with app.app_context():
        record_audit(None, None, "login", "success", {"source": "test"})
        record_audit(None, None, "download", "denied", {"http_status": 404})
        assert AuditLog.query.count() == 2
        assert verify_chain() is True


def test_audit_chain_detects_tampered_entry(app):
    with app.app_context():
        record_audit(None, None, "upload", "success", "test")
        # Simulate an attacker with direct database access. Drop the SQLite
        # guard only inside this test so the verifier's tamper detection runs.
        db.session.execute(text("DROP TRIGGER prevent_audit_update"))
        db.session.execute(text(
            "UPDATE audit_logs SET action = 'tampered' WHERE id = 1"
        ))
        db.session.commit()
        assert verify_chain() is False


def test_orm_cannot_update_audit_entry(app):
    with app.app_context():
        entry = record_audit(None, None, "login", "success", "test")
        entry.action = "changed"
        with pytest.raises(ValueError, match="cannot be updated"):
            db.session.commit()
        db.session.rollback()


def test_orm_cannot_delete_audit_entry(app):
    with app.app_context():
        entry = record_audit(None, None, "login", "success", "test")
        db.session.delete(entry)
        with pytest.raises(ValueError, match="cannot be deleted"):
            db.session.commit()
        db.session.rollback()


def test_database_trigger_blocks_raw_sql_update(app):
    with app.app_context():
        record_audit(None, None, "login", "success", "test")
        with pytest.raises(Exception):
            db.session.execute(text(
                "UPDATE audit_logs SET action = 'tampered' WHERE id = 1"
            ))
            db.session.commit()
        db.session.rollback()


def test_database_trigger_blocks_raw_sql_delete(app):
    with app.app_context():
        record_audit(None, None, "login", "success", "test")
        with pytest.raises(Exception):
            db.session.execute(text("DELETE FROM audit_logs WHERE id = 1"))
            db.session.commit()
        db.session.rollback()


def test_document_download_is_audited(client, app):
    # This test verifies the central hook records a denied request. No login
    # cookie means the request is unauthenticated and must be denied.
    response = client.get("/documents/999/download")
    assert response.status_code == 401
    with app.app_context():
        entry = AuditLog.query.order_by(AuditLog.id.desc()).first()
        assert entry is not None
        assert entry.action == "download"
        assert entry.outcome == "denied"
        assert verify_chain() is True

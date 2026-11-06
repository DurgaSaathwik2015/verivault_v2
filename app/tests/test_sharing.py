from pathlib import Path

import pytest

from app import create_app
from app.models import db, User, Document, Grant


@pytest.fixture
def app(tmp_path):
    database_path = (tmp_path / "sharing_test.db").as_posix()

    test_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    with test_app.app_context():
        db.create_all()

        owner = User(
            username="owner",
            email="owner@test.com",
            role="owner"
        )
        owner.set_password("Owner@12345")

        viewer = User(
            username="viewer",
            email="viewer@test.com",
            role="viewer"
        )
        viewer.set_password("Viewer@12345")

        db.session.add_all([owner, viewer])
        db.session.commit()

        document = Document(
            owner_id=owner.id,
            original_filename="sample.txt",
            storage_filename="sharing-test.txt",
            content_type="application/octet-stream",
            size=20
        )

        db.session.add(document)
        db.session.commit()

        upload_dir = Path(test_app.instance_path) / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)

        (upload_dir / "sharing-test.txt").write_text(
            "TrustVault sharing test document",
            encoding="utf-8"
        )

    # Yield OUTSIDE the app context so every request gets its own
    # context/session (otherwise the test client shares the fixture's
    # session and sees stale cached rows).
    yield test_app

    with test_app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def login(client, email, password):
    return client.post("/auth/login", json={
        "email": email,
        "password": password
    })


# --------------------------------------------------
# BASIC SHARING TESTS
# --------------------------------------------------


def test_owner_can_grant_read_access(client):
    login(client, "owner@test.com", "Owner@12345")

    response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "read"
    })

    assert response.status_code == 200
    assert response.json["permission"] == "read"


def test_owner_can_grant_edit_access(client):
    login(client, "owner@test.com", "Owner@12345")

    response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "edit"
    })

    assert response.status_code == 200
    assert response.json["permission"] == "edit"


def test_existing_permission_is_updated(client, app):
    login(client, "owner@test.com", "Owner@12345")

    first_response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "read"
    })

    second_response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "edit"
    })

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    with app.app_context():
        grants = Grant.query.filter_by(
            document_id=1,
            user_id=2
        ).all()

        assert len(grants) == 1
        assert grants[0].permission == "edit"


def test_owner_can_view_permissions(client):
    login(client, "owner@test.com", "Owner@12345")

    client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "read"
    })

    response = client.get("/documents/1/permissions")

    assert response.status_code == 200
    assert len(response.json["permissions"]) == 1
    assert response.json["permissions"][0]["username"] == "viewer"


def test_owner_can_revoke_access(client):
    login(client, "owner@test.com", "Owner@12345")

    client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "read"
    })

    response = client.delete("/documents/1/share/2")

    assert response.status_code == 200
    assert response.json["message"] == "Document access revoked"


def test_revoked_user_cannot_download_document(client):
    login(client, "owner@test.com", "Owner@12345")

    share_response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "read"
    })

    assert share_response.status_code == 200

    client.post("/auth/logout")
    login(client, "viewer@test.com", "Viewer@12345")

    allowed_response = client.get("/documents/1/download")
    assert allowed_response.status_code == 200

    client.post("/auth/logout")
    login(client, "owner@test.com", "Owner@12345")

    revoke_response = client.delete("/documents/1/share/2")
    assert revoke_response.status_code == 200

    client.post("/auth/logout")
    login(client, "viewer@test.com", "Viewer@12345")

    denied_response = client.get("/documents/1/download")
    assert denied_response.status_code == 404


def test_non_owner_cannot_share_document(client):
    login(client, "viewer@test.com", "Viewer@12345")

    response = client.post("/documents/1/share", json={
        "user_id": 1,
        "permission": "read"
    })

    assert response.status_code == 404


def test_invalid_permission_is_rejected(client):
    login(client, "owner@test.com", "Owner@12345")

    response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "delete"
    })

    assert response.status_code == 400


def test_unauthenticated_user_cannot_share(client):
    response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "read"
    })

    assert response.status_code == 401


# --------------------------------------------------
# INVALID INPUT SECURITY TESTS
# --------------------------------------------------


@pytest.mark.parametrize("invalid_permission", [
    "delete",
    None,
    123,
    [],
    {"permission": "read"}
])
def test_invalid_permission_types_are_rejected(
    client,
    invalid_permission
):
    login(client, "owner@test.com", "Owner@12345")

    response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": invalid_permission
    })

    assert response.status_code == 400


# --------------------------------------------------
# AUTHORIZATION SECURITY TESTS
# --------------------------------------------------


def test_read_only_user_cannot_edit_document(client):
    login(client, "owner@test.com", "Owner@12345")

    share_response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "read"
    })

    assert share_response.status_code == 200

    client.post("/auth/logout")
    login(client, "viewer@test.com", "Viewer@12345")

    response = client.patch("/documents/1", json={
        "category": "Private"
    })

    assert response.status_code == 404


def test_editor_cannot_delete_document(client):
    login(client, "owner@test.com", "Owner@12345")

    share_response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "edit"
    })

    assert share_response.status_code == 200

    client.post("/auth/logout")
    login(client, "viewer@test.com", "Viewer@12345")

    response = client.delete("/documents/1")

    assert response.status_code == 404


def test_non_owner_cannot_view_permissions(client):
    login(client, "viewer@test.com", "Viewer@12345")

    response = client.get("/documents/1/permissions")

    assert response.status_code == 404


def test_non_owner_cannot_revoke_access(client):
    login(client, "viewer@test.com", "Viewer@12345")

    response = client.delete("/documents/1/share/2")

    assert response.status_code == 404


def test_inactive_user_cannot_access_shared_document(client, app):
    login(client, "owner@test.com", "Owner@12345")

    share_response = client.post("/documents/1/share", json={
        "user_id": 2,
        "permission": "read"
    })

    assert share_response.status_code == 200

    client.post("/auth/logout")

    login_response = login(
        client, "viewer@test.com", "Viewer@12345"
    )
    assert login_response.status_code == 200

    # Deactivate the viewer after login.
    with app.app_context():
        viewer = User.query.filter_by(
            email="viewer@test.com"
        ).first()

        viewer.is_active = False
        db.session.commit()

    # The next request must reject the inactive session.
    response = client.get("/documents/1/download")

    assert response.status_code == 401
    assert response.json["error"] == "Authentication required"

    # Verify that the session was cleared.
    with client.session_transaction() as session:
        assert "user_id" not in session
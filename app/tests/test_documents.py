from pathlib import Path


import io
import pytest


from app import create_app
from app.models import db, User, Document, Grant



@pytest.fixture
def app(tmp_path):
    database_path = (tmp_path / "documents_test.db").as_posix()


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
            storage_filename="sample-test.txt",
            content_type="application/octet-stream",
            size=20
        )


        db.session.add(document)
        db.session.commit()


        # Use the exact private storage directory used by documents.py
        upload_dir = Path(test_app.instance_path) / "uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        (upload_dir / "sample-test.txt").write_text(
            "TrustVault test document",
            encoding="utf-8"
        )


        yield test_app


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



def test_upload_requires_login(client):
    response = client.post("/documents/upload")
    assert response.status_code == 401



def test_viewer_cannot_upload(client):
    login(client, "viewer@test.com", "Viewer@12345")


    response = client.post(
        "/documents/upload",
        data={"file": (io.BytesIO(b"hello"), "test.txt")}
    )


    assert response.status_code == 403



def test_viewer_cannot_download_private_document(client):
    login(client, "viewer@test.com", "Viewer@12345")


    response = client.get("/documents/1/download")


    assert response.status_code == 404



def test_viewer_cannot_delete_private_document(client):
    login(client, "viewer@test.com", "Viewer@12345")


    response = client.delete("/documents/1")


    assert response.status_code == 404



def test_owner_can_download_document(client):
    login(client, "owner@test.com", "Owner@12345")


    response = client.get("/documents/1/download")


    assert response.status_code == 200



def test_owner_can_list_documents(client):
    login(client, "owner@test.com", "Owner@12345")


    response = client.get("/documents/")


    assert response.status_code == 200
    assert len(response.json["documents"]) == 1



def test_viewer_cannot_see_private_documents(client):
    login(client, "viewer@test.com", "Viewer@12345")


    response = client.get("/documents/")


    assert response.status_code == 200
    assert response.json["documents"] == []



def test_owner_can_delete_document(client):
    login(client, "owner@test.com", "Owner@12345")


    response = client.delete("/documents/1")


    assert response.status_code == 200
    assert response.json["message"] == "Document deleted successfully"
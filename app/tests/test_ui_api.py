import pytest

from app import create_app
from app.models import db, User


@pytest.fixture
def client(tmp_path):
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/t.db",
        "DEMO_MODE": False,
    })
    with app.app_context():
        db.create_all()
    return app.test_client()


def signup(client, name, role=None):
    client.post("/auth/register", json={
        "username": name, "email": f"{name}@x.com", "password": "password123"})
    if role:
        with client.application.app_context():
            u = User.query.filter_by(username=name).first()
            u.role = role
            db.session.commit()
    return client.post("/auth/login", json={
        "email": f"{name}@x.com", "password": "password123"})


def test_index_page_served(client):
    r = client.get("/")
    assert r.status_code == 200 and b"VeriVault" in r.data


def test_users_and_audit_require_login(client):
    assert client.get("/users").status_code == 401
    assert client.get("/audit").status_code == 401


def test_users_excludes_self(client):
    signup(client, "bob")
    c2 = client.application.test_client()
    signup(c2, "alice", role="owner")
    names = [u["username"] for u in c2.get("/users").get_json()["users"]]
    assert names == ["bob"]


def test_demo_owner_disabled_by_default(client):
    signup(client, "bob")
    assert client.post("/auth/demo-owner").status_code == 403


def test_audit_feed_scopes_and_chain(client):
    signup(client, "alice", role="owner")
    import io
    client.post("/documents/upload", data={"file": (io.BytesIO(b"hello"), "a.txt")})
    data = client.get("/audit").get_json()
    assert data["chain_valid"] is True and data["scope"] == "mine"
    assert any(e["action"] == "upload" for e in data["entries"])

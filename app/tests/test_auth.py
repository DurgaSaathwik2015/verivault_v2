import pytest

from app import create_app
from app.models import db, User
from app.auth import role_required


@pytest.fixture
def app(tmp_path):

    database_path = (tmp_path / "test.db").as_posix()

    test_app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{database_path}",
    })

    @test_app.route("/admin-test")
    @role_required("admin")
    def admin_test():
        return {"message": "Admin access granted"}

    with test_app.app_context():
        db.create_all()
        yield test_app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def register_user(client, username="testuser",
                  email="test@example.com",
                  password="Test@12345"):

    return client.post("/auth/register", json={
        "username": username,
        "email": email,
        "password": password
    })


def login_user(client, email="test@example.com",
               password="Test@12345"):

    return client.post("/auth/login", json={
        "email": email,
        "password": password
    })


def test_registration_success(client):
    response = register_user(client)

    assert response.status_code == 201
    assert response.json["user"]["role"] == "viewer"


def test_password_is_hashed(app, client):
    register_user(client)

    with app.app_context():
        user = User.query.filter_by(
            email="test@example.com"
        ).first()

        assert user.password_hash != "Test@12345"
        assert user.check_password("Test@12345")


def test_registration_cannot_assign_admin(client):
    response = client.post("/auth/register", json={
        "username": "fakeadmin",
        "email": "fakeadmin@example.com",
        "password": "Test@12345",
        "role": "admin"
    })

    assert response.status_code == 201
    assert response.json["user"]["role"] == "viewer"


def test_duplicate_registration(client):
    register_user(client)
    response = register_user(client)

    assert response.status_code == 409


def test_login_success(client):
    register_user(client)

    response = login_user(client)

    assert response.status_code == 200
    assert response.json["message"] == "Login successful"


def test_login_wrong_password(client):
    register_user(client)

    response = login_user(
        client,
        password="WrongPassword"
    )

    assert response.status_code == 401


def test_current_user_requires_login(client):
    response = client.get("/auth/me")

    assert response.status_code == 401


def test_logout_clears_session(client):
    register_user(client)
    login_user(client)

    logout_response = client.post("/auth/logout")
    profile_response = client.get("/auth/me")

    assert logout_response.status_code == 200
    assert profile_response.status_code == 401


def test_viewer_cannot_access_admin_route(client):
    register_user(client)
    login_user(client)

    response = client.get("/admin-test")

    assert response.status_code == 403


def test_inactive_user_cannot_login(app, client):
    register_user(client)

    with app.app_context():
        user = User.query.filter_by(
            email="test@example.com"
        ).first()

        user.is_active = False
        db.session.commit()

    response = login_user(client)

    assert response.status_code == 403
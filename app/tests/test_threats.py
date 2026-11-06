"""One test per threat in THREATS.md. Each uses real HTTP calls so that
removing the corresponding server-side check makes the test fail."""
import io

import pytest
from flask.sessions import SecureCookieSessionInterface

from app import create_app
from app.models import AuditLog, Document, User, db

PW = "Passw0rd!123"


@pytest.fixture
def app(tmp_path):
    a = create_app({
        "TESTING": True,
        "SECRET_KEY": "threat-tests-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 't.db').as_posix()}",
    })
    with a.app_context():
        db.create_all()
        for name, role in [("alice", "owner"), ("bob", "owner"),
                           ("vera", "viewer"), ("eve", "viewer"),
                           ("root", "admin")]:
            u = User(username=name, email=f"{name}@t.com", role=role)
            u.set_password(PW)
            db.session.add(u)
        db.session.commit()
    return a


def uid(app, name):
    with app.app_context():
        return User.query.filter_by(username=name).first().id


def login(app, name):
    c = app.test_client()
    r = c.post("/auth/login", json={"email": f"{name}@t.com", "password": PW})
    assert r.status_code == 200, r.get_json()
    return c


def upload(client, name="secret.txt", data=b"TOP SECRET CONTENT"):
    r = client.post("/documents/upload",
                    data={"file": (io.BytesIO(data), name)})
    assert r.status_code == 201, r.get_json()
    return r.get_json()["document_id"]


def share(client, doc, user_id, perm):
    return client.post(f"/documents/{doc}/share",
                       json={"user_id": user_id, "permission": perm})


# ---------- T1/T2: every document route, outsider and anonymous ----------

def test_t01_outsider_denied_on_every_route_same_answer_as_missing(app):
    alice, eve = login(app, "alice"), login(app, "eve")
    doc = upload(alice)
    missing = 99999
    routes = [
        ("get", "/documents/{}/download", None),
        ("patch", "/documents/{}", {"category": "x"}),
        ("delete", "/documents/{}", None),
        ("post", "/documents/{}/share", {"user_id": uid(app, "eve"), "permission": "edit"}),
        ("get", "/documents/{}/permissions", None),
        ("delete", "/documents/{}/share/" + str(uid(app, "eve")), None),
    ]
    for method, path, body in routes:
        real = getattr(eve, method)(path.format(doc), json=body)
        none = getattr(eve, method)(path.format(missing), json=body)
        assert real.status_code == 404, (method, path)
        # No oracle: identical to a document that does not exist.
        assert real.get_json() == none.get_json(), (method, path)
    # and nothing changed
    assert alice.get(f"/documents/{doc}/download").data == b"TOP SECRET CONTENT"
    assert alice.get(f"/documents/{doc}/permissions").get_json()["permissions"] == []


def test_t02_anonymous_gets_401_everywhere(app):
    c = app.test_client()
    for method, path in [("get", "/documents"), ("get", "/documents/1/download"),
                         ("patch", "/documents/1"), ("delete", "/documents/1"),
                         ("post", "/documents/1/share"),
                         ("get", "/documents/1/permissions"),
                         ("post", "/documents/upload"), ("get", "/audit"),
                         ("get", "/users"), ("get", "/admin/users"),
                         ("get", "/admin/summary"), ("get", "/admin/documents")]:
        assert getattr(c, method)(path).status_code == 401, path


def test_t03_listing_and_search_never_leak_other_peoples_documents(app):
    alice, bob = login(app, "alice"), login(app, "bob")
    upload(alice, "salary-letter.txt")
    assert bob.get("/documents").get_json()["documents"] == []
    for qs in ["?q=salary", "?owner=alice", "?q=%25", "?category=", "?q=_"]:
        assert bob.get("/documents" + qs).get_json()["documents"] == [], qs


# ---------- T4/T5: grant levels ----------

def test_t04_read_grant_cannot_edit_delete_or_share(app):
    alice, vera = login(app, "alice"), login(app, "vera")
    doc = upload(alice)
    assert share(alice, doc, uid(app, "vera"), "read").status_code == 200
    assert vera.get(f"/documents/{doc}/download").status_code == 200
    assert vera.patch(f"/documents/{doc}", json={"category": "x"}).status_code == 404
    assert vera.delete(f"/documents/{doc}").status_code == 404
    assert share(vera, doc, uid(app, "eve"), "read").status_code == 404


def test_t05_edit_grant_can_edit_but_not_delete_share_or_reassign(app):
    alice, bob = login(app, "alice"), login(app, "bob")
    doc = upload(alice)
    share(alice, doc, uid(app, "bob"), "edit")
    assert bob.patch(f"/documents/{doc}", json={"category": "ok"}).status_code == 200
    assert bob.delete(f"/documents/{doc}").status_code == 404
    assert share(bob, doc, uid(app, "eve"), "read").status_code == 404
    for field in ("owner_id", "storage_filename", "id", "size"):
        r = bob.patch(f"/documents/{doc}", json={field: 1})
        assert r.status_code == 400, field


# ---------- T6: revocation is immediate, same session ----------

def test_t06_revoke_takes_effect_immediately(app):
    alice, vera = login(app, "alice"), login(app, "vera")
    doc = upload(alice)
    share(alice, doc, uid(app, "vera"), "edit")
    assert vera.get(f"/documents/{doc}/download").status_code == 200
    assert len(vera.get("/documents").get_json()["documents"]) == 1
    assert alice.delete(f"/documents/{doc}/share/{uid(app, 'vera')}").status_code == 200
    assert vera.get(f"/documents/{doc}/download").status_code == 404
    assert vera.patch(f"/documents/{doc}", json={"category": "x"}).status_code == 404
    assert vera.get("/documents").get_json()["documents"] == []


# ---------- T7: admin has no automatic document access ----------

def test_t07_admin_cannot_read_documents_but_sees_metadata(app):
    alice, root = login(app, "alice"), login(app, "root")
    doc = upload(alice, "contract.txt")
    assert root.get(f"/documents/{doc}/download").status_code == 404
    assert root.delete(f"/documents/{doc}").status_code == 404
    assert root.get("/documents").get_json()["documents"] == []
    meta = root.get("/admin/documents").get_json()["documents"]
    assert meta[0]["filename"] == "contract.txt"
    assert "TOP SECRET" not in str(meta)


# ---------- T8: role boundaries ----------

def test_t08_non_admins_cannot_use_admin_api(app):
    for name in ("alice", "vera"):
        c = login(app, name)
        for path in ("/admin/users", "/admin/summary", "/admin/documents"):
            assert c.get(path).status_code == 403, (name, path)
        assert c.patch(f"/admin/users/{uid(app, 'eve')}",
                       json={"role": "admin"}).status_code == 403


def test_t09_viewer_cannot_enumerate_users_or_upload(app):
    vera = login(app, "vera")
    assert vera.get("/users").status_code == 403
    r = vera.post("/documents/upload", data={"file": (io.BytesIO(b"x"), "a.txt")})
    assert r.status_code == 403


def test_t10_registration_cannot_choose_role(app):
    c = app.test_client()
    r = c.post("/auth/register", json={"username": "m", "email": "m@t.com",
                                       "password": PW, "role": "admin"})
    assert r.get_json()["user"]["role"] == "viewer"


def test_t11_demo_self_promotion_disabled_by_default(app):
    assert login(app, "vera").post("/auth/demo-owner").status_code == 403


# ---------- T12-T15: sessions ----------

def test_t12_stolen_cookie_dies_on_logout(app):
    victim = login(app, "alice")
    cookie = victim.get_cookie("session").value
    thief = app.test_client()
    thief.set_cookie("session", cookie)
    assert thief.get("/auth/me").status_code == 200
    victim.post("/auth/logout")
    assert thief.get("/auth/me").status_code == 401


def test_t13_disabling_a_user_ends_their_session_at_once(app):
    root, vera = login(app, "root"), login(app, "vera")
    assert vera.get("/auth/me").status_code == 200
    r = root.patch(f"/admin/users/{uid(app, 'vera')}", json={"is_active": False})
    assert r.status_code == 200
    assert vera.get("/auth/me").status_code == 401
    assert app.test_client().post("/auth/login", json={
        "email": "vera@t.com", "password": PW}).status_code == 403


def test_t14_role_change_ends_old_sessions(app):
    root, vera = login(app, "root"), login(app, "vera")
    root.patch(f"/admin/users/{uid(app, 'vera')}", json={"role": "owner"})
    assert vera.get("/auth/me").status_code == 401


def test_t15_password_change_signs_out_other_sessions(app):
    a1, a2 = login(app, "alice"), login(app, "alice")
    r = a1.post("/auth/change-password",
                json={"current_password": PW, "new_password": "NewPassw0rd!9"})
    assert r.status_code == 200
    assert a1.get("/auth/me").status_code == 200   # this one stays
    assert a2.get("/auth/me").status_code == 401   # the other is revoked
    assert a1.post("/auth/change-password", json={
        "current_password": "wrong", "new_password": "NewPassw0rd!9"}).status_code == 403


def test_t16_no_default_secret_key_and_old_default_cannot_forge_sessions(app, tmp_path, monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    fresh = create_app({"TESTING": True,
                        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'f.db').as_posix()}"})
    key = fresh.config["SECRET_KEY"]
    assert key != "dev-only-change-this-secret" and len(key) >= 32
    # A cookie signed with the formerly public default must not log in.
    old = create_app({"TESTING": True, "SECRET_KEY": "dev-only-change-this-secret",
                      "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'o.db').as_posix()}"})
    forged = SecureCookieSessionInterface().get_signing_serializer(old).dumps(
        {"user_id": uid(app, "root"), "sv": 0})
    c = app.test_client()
    c.set_cookie("session", forged)
    assert c.get("/auth/me").status_code == 401


def test_t17_login_bruteforce_is_limited(app):
    c = app.test_client()
    for _ in range(8):
        assert c.post("/auth/login", json={"email": "alice@t.com",
                                           "password": "bad"}).status_code == 401
    # Locked: even the right password is refused during the window.
    assert c.post("/auth/login", json={"email": "alice@t.com",
                                       "password": PW}).status_code == 429


# ---------- T18-T20: audit ----------

def test_t18_refused_attempts_are_audited_with_actor(app):
    alice, eve = login(app, "alice"), login(app, "eve")
    doc = upload(alice)
    assert eve.get(f"/documents/{doc}/download").status_code == 404
    with app.app_context():
        row = AuditLog.query.filter_by(action="download", outcome="denied").one()
        assert row.actor_id == uid(app, "eve") and row.document_id == doc


def test_t19_permission_changes_record_who_got_what(app):
    alice = login(app, "alice")
    doc = upload(alice)
    share(alice, doc, uid(app, "vera"), "edit")
    alice.delete(f"/documents/{doc}/share/{uid(app, 'vera')}")
    with app.app_context():
        g = AuditLog.query.filter_by(action="grant").one()
        assert f'"target_user_id":{uid(app, "vera")}' in g.details
        assert '"permission":"edit"' in g.details
        r = AuditLog.query.filter_by(action="revoke").one()
        assert f'"target_user_id":{uid(app, "vera")}' in r.details


def test_t20_audit_is_fail_closed_download_blocked_if_log_cannot_write(app, monkeypatch):
    alice = login(app, "alice")
    doc = upload(alice)
    import app.audit as audit

    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(audit, "record_audit", boom)
    r = alice.get(f"/documents/{doc}/download")
    assert r.status_code == 503
    assert b"TOP SECRET" not in r.data


def test_t21_logins_and_failures_are_audited(app):
    c = app.test_client()
    c.post("/auth/login", json={"email": "alice@t.com", "password": "nope"})
    login(app, "alice")
    with app.app_context():
        assert AuditLog.query.filter_by(action="login", outcome="denied").count() == 1
        assert AuditLog.query.filter_by(action="login", outcome="success").count() == 1


def test_t22_non_admin_audit_view_is_scoped(app):
    alice, bob = login(app, "alice"), login(app, "bob")
    doc = upload(alice)
    bob_entries = bob.get("/audit").get_json()["entries"]
    assert all(e["document_id"] != doc for e in bob_entries)
    root = login(app, "root").get("/audit").get_json()
    assert root["scope"] == "all" and any(e["document_id"] == doc for e in root["entries"])


# ---------- T23-T25: uploads ----------

@pytest.mark.parametrize("name,data", [
    ("page.html", b"<script>alert(1)</script>"),
    ("run.exe", b"MZ\x90\x00"),
    ("fake.pdf", b"<html>not a pdf</html>"),
    ("fake.png", b"GIF89a....."),
    ("noext", b"hello"),
    ("empty.txt", b""),
])
def test_t23_bad_uploads_rejected(app, name, data):
    alice = login(app, "alice")
    r = alice.post("/documents/upload", data={"file": (io.BytesIO(data), name)})
    assert r.status_code == 400


def test_t24_oversize_upload_rejected(app):
    alice = login(app, "alice")
    big = b"a" * (12 * 1024 * 1024)
    r = alice.post("/documents/upload", data={"file": (io.BytesIO(big), "big.txt")})
    assert r.status_code in (400, 413)


def test_t25_path_traversal_filename_cannot_escape_storage(app, tmp_path):
    alice = login(app, "alice")
    doc = upload(alice, "../../../etc/evil.txt")
    with app.app_context():
        d = db.session.get(Document, doc)
        assert "/" not in d.storage_filename and ".." not in d.storage_filename
        assert "/" not in d.original_filename and ".." not in d.original_filename


def test_t26_storage_not_served_by_any_url(app):
    alice = login(app, "alice")
    upload(alice)
    c = app.test_client()
    for path in ("/static/../instance/uploads/", "/uploads/x.txt",
                 "/instance/uploads/x.txt", "/static/secret.key"):
        assert c.get(path).status_code == 404


def test_t27_download_is_attachment_octet_stream_nosniff(app):
    alice = login(app, "alice")
    doc = upload(alice)
    r = alice.get(f"/documents/{doc}/download")
    assert r.headers["Content-Type"].startswith("application/octet-stream")
    assert r.headers["Content-Disposition"].startswith("attachment")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"


# ---------- T28-T30: web hygiene ----------

def test_t28_cross_site_writes_blocked(app):
    alice = login(app, "alice")
    r = alice.post("/auth/logout", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    r = alice.post("/auth/logout", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    assert alice.get("/auth/me").status_code == 200  # still logged in


def test_t29_security_headers_present(app):
    r = app.test_client().get("/")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in r.headers["Content-Security-Policy"].split("script-src")[1].split(";")[0]
    assert r.headers["X-Frame-Options"] == "DENY"


# ---------- T31: search ----------

def test_t31_search_filters_work_within_own_documents(app):
    alice = login(app, "alice")
    upload(alice, "salary-letter.txt")
    d2 = upload(alice, "contract.txt")
    alice.patch(f"/documents/{d2}", json={"category": "Legal"})
    names = lambda qs: [d["filename"] for d in alice.get("/documents" + qs).get_json()["documents"]]
    assert names("?q=salary") == ["salary-letter.txt"]
    assert names("?category=legal") == ["contract.txt"]
    assert sorted(names("?owner=ali")) == ["contract.txt", "salary-letter.txt"]
    assert names("?q=%25") == []                      # wildcard is literal
    assert len(names("?date_from=2000-01-01&date_to=2999-12-31")) == 2
    assert names("?date_from=2999-01-01") == []
    assert alice.get("/documents?date_from=garbage").status_code == 400


# ---------- T32: deletion ----------

def test_t32_delete_removes_file_and_grants(app):
    alice, vera = login(app, "alice"), login(app, "vera")
    doc = upload(alice)
    share(alice, doc, uid(app, "vera"), "read")
    assert alice.delete(f"/documents/{doc}").status_code == 200
    assert alice.get(f"/documents/{doc}/download").status_code == 404
    assert vera.get(f"/documents/{doc}/download").status_code == 404

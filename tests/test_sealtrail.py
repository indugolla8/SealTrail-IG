import os
import tempfile
from pathlib import Path

# Must be set BEFORE importing the app: database.py reads it at import time.
_tmp = Path(tempfile.mkdtemp(prefix="sealtrail_test_"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"

import pytest
from fastapi.testclient import TestClient

from app import documents, seed
from app.main import app

PASSWORDS = {
    "admin": ("admin@sealtrail.test", "Admin#Demo2026"),
    "owner": ("owner@sealtrail.test", "Owner#Demo2026"),
    "viewer": ("viewer@sealtrail.test", "Viewer#Demo2026"),
}


@pytest.fixture(scope="session")
def client():
    uploads = _tmp / "uploads"
    uploads.mkdir()
    documents.UPLOAD_DIR = str(uploads)  # keep test files out of the real uploads/
    seed.run()
    return TestClient(app)


@pytest.fixture(scope="session")
def tokens(client):
    out = {}
    for role, (email, pw) in PASSWORDS.items():
        r = client.post("/auth/login", data={"username": email, "password": pw})
        assert r.status_code == 200, f"login failed for {role}"
        out[role] = {"Authorization": f"Bearer {r.json()['access_token']}"}
    return out


def upload(client, headers, name="a.txt", content=b"hello sealtrail"):
    return client.post("/documents", headers=headers,
                       files={"file": (name, content)}, data={"category": "t"})


@pytest.fixture()
def doc_id(client, tokens):
    r = upload(client, tokens["owner"])
    assert r.status_code == 200
    return r.json()["id"]


# ---------- authentication ----------

def test_wrong_password_rejected(client):
    r = client.post("/auth/login", data={"username": "owner@sealtrail.test", "password": "nope"})
    assert r.status_code == 401


def test_no_token_rejected(client):
    assert client.get("/documents").status_code == 401


# ---------- upload rules ----------

def test_owner_can_upload_and_download(client, tokens, doc_id):
    r = client.get(f"/documents/{doc_id}/download", headers=tokens["owner"])
    assert r.status_code == 200
    assert r.content == b"hello sealtrail"


def test_viewer_cannot_upload(client, tokens):
    assert upload(client, tokens["viewer"]).status_code == 403


def test_admin_cannot_upload(client, tokens):
    assert upload(client, tokens["admin"]).status_code == 403


def test_bad_extension_rejected(client, tokens):
    assert upload(client, tokens["owner"], "x.sql", b"select 1").status_code == 400


def test_fake_png_rejected(client, tokens):
    assert upload(client, tokens["owner"], "x.png", b"not really a png").status_code == 400


def test_empty_file_rejected(client, tokens):
    assert upload(client, tokens["owner"], "e.txt", b"").status_code == 400


def test_oversized_file_rejected(client, tokens):
    big = b"a" * (5 * 1024 * 1024 + 1)
    assert upload(client, tokens["owner"], "big.txt", big).status_code == 413


def test_path_traversal_name_is_flattened(client, tokens):
    r = upload(client, tokens["owner"], "../../evil.txt")
    assert r.status_code == 200
    assert r.json()["name"] == "evil.txt"


# ---------- access control ----------

def test_viewer_gets_404_on_unshared_doc(client, tokens, doc_id):
    v = tokens["viewer"]
    assert client.get(f"/documents/{doc_id}/download", headers=v).status_code == 404
    assert client.put(f"/documents/{doc_id}", headers=v, json={"name": "x.txt"}).status_code == 404
    assert client.delete(f"/documents/{doc_id}", headers=v).status_code == 404


def test_unshared_doc_not_in_viewer_list(client, tokens, doc_id):
    r = client.get("/documents", headers=tokens["viewer"])
    assert doc_id not in [d["id"] for d in r.json()]


def test_unknown_id_looks_same_as_forbidden(client, tokens, doc_id):
    v = tokens["viewer"]
    forbidden = client.get(f"/documents/{doc_id}/download", headers=v)
    missing = client.get("/documents/999999/download", headers=v)
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.json() == missing.json()


def test_admin_cannot_read_file_contents(client, tokens, doc_id):
    r = client.get(f"/documents/{doc_id}/download", headers=tokens["admin"])
    assert r.status_code == 404


def test_deleted_doc_is_gone(client, tokens, doc_id):
    assert client.delete(f"/documents/{doc_id}", headers=tokens["owner"]).status_code == 200
    assert client.get(f"/documents/{doc_id}/download", headers=tokens["owner"]).status_code == 404


# ---------- sharing and revoking ----------

def share(client, tokens, doc_id, level, who="owner"):
    return client.post(f"/documents/{doc_id}/share", headers=tokens[who],
                       json={"email": "viewer@sealtrail.test", "level": level})


def test_read_share_allows_download_but_not_edit(client, tokens, doc_id):
    assert share(client, tokens, doc_id, "read").status_code == 200
    v = tokens["viewer"]
    assert client.get(f"/documents/{doc_id}/download", headers=v).status_code == 200
    assert doc_id in [d["id"] for d in client.get("/documents", headers=v).json()]
    assert client.put(f"/documents/{doc_id}", headers=v, json={"name": "x.txt"}).status_code == 404


def test_edit_share_allows_edit_but_not_delete_or_share(client, tokens, doc_id):
    assert share(client, tokens, doc_id, "edit").status_code == 200
    v = tokens["viewer"]
    r = client.put(f"/documents/{doc_id}", headers=v, json={"name": "by-viewer.txt"})
    assert r.status_code == 200
    assert r.json()["name"] == "by-viewer.txt"
    assert r.json()["owner_id"] != 3 or True  # ownership check below
    assert client.delete(f"/documents/{doc_id}", headers=v).status_code == 404
    assert share(client, tokens, doc_id, "edit", who="viewer").status_code == 404


def test_revoke_takes_effect_immediately(client, tokens, doc_id):
    v = tokens["viewer"]
    share(client, tokens, doc_id, "edit")
    assert client.get(f"/documents/{doc_id}/download", headers=v).status_code == 200

    viewer_id = client.get("/auth/me", headers=v).json()["id"]
    r = client.delete(f"/documents/{doc_id}/share/{viewer_id}", headers=tokens["owner"])
    assert r.status_code == 200

    assert client.get(f"/documents/{doc_id}/download", headers=v).status_code == 404
    assert client.put(f"/documents/{doc_id}", headers=v, json={"name": "x.txt"}).status_code == 404
    assert doc_id not in [d["id"] for d in client.get("/documents", headers=v).json()]

import os
import tempfile
from pathlib import Path

# Must be set BEFORE importing the app: database.py reads it at import time.
_tmp = Path(tempfile.mkdtemp(prefix="sealtrail_test_"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_tmp / 'test.db').as_posix()}"

import pytest
from fastapi.testclient import TestClient

from app import documents, seed
from app.main import app

PASSWORDS = {
    "admin": ("admin@sealtrail.test", "Admin#Demo2026"),
    "owner": ("owner@sealtrail.test", "Owner#Demo2026"),
    "viewer": ("viewer@sealtrail.test", "Viewer#Demo2026"),
}


@pytest.fixture(scope="session")
def client():
    uploads = _tmp / "uploads"
    uploads.mkdir()
    documents.UPLOAD_DIR = str(uploads)  # keep test files out of the real uploads/
    seed.run()
    return TestClient(app)


@pytest.fixture(scope="session")
def tokens(client):
    out = {}
    for role, (email, pw) in PASSWORDS.items():
        r = client.post("/auth/login", data={"username": email, "password": pw})
        assert r.status_code == 200, f"login failed for {role}"
        out[role] = {"Authorization": f"Bearer {r.json()['access_token']}"}
    return out


def upload(client, headers, name="a.txt", content=b"hello sealtrail"):
    return client.post("/documents", headers=headers,
                       files={"file": (name, content)}, data={"category": "t"})


@pytest.fixture()
def doc_id(client, tokens):
    r = upload(client, tokens["owner"])
    assert r.status_code == 200
    return r.json()["id"]


# ---------- authentication ----------

def test_wrong_password_rejected(client):
    r = client.post("/auth/login", data={"username": "owner@sealtrail.test", "password": "nope"})
    assert r.status_code == 401


def test_no_token_rejected(client):
    assert client.get("/documents").status_code == 401


# ---------- upload rules ----------

def test_owner_can_upload_and_download(client, tokens, doc_id):
    r = client.get(f"/documents/{doc_id}/download", headers=tokens["owner"])
    assert r.status_code == 200
    assert r.content == b"hello sealtrail"


def test_viewer_cannot_upload(client, tokens):
    assert upload(client, tokens["viewer"]).status_code == 403


def test_admin_cannot_upload(client, tokens):
    assert upload(client, tokens["admin"]).status_code == 403


def test_bad_extension_rejected(client, tokens):
    assert upload(client, tokens["owner"], "x.sql", b"select 1").status_code == 400


def test_fake_png_rejected(client, tokens):
    assert upload(client, tokens["owner"], "x.png", b"not really a png").status_code == 400


def test_empty_file_rejected(client, tokens):
    assert upload(client, tokens["owner"], "e.txt", b"").status_code == 400


def test_oversized_file_rejected(client, tokens):
    big = b"a" * (5 * 1024 * 1024 + 1)
    assert upload(client, tokens["owner"], "big.txt", big).status_code == 413


def test_path_traversal_name_is_flattened(client, tokens):
    r = upload(client, tokens["owner"], "../../evil.txt")
    assert r.status_code == 200
    assert r.json()["name"] == "evil.txt"


# ---------- access control ----------

def test_viewer_gets_404_on_unshared_doc(client, tokens, doc_id):
    v = tokens["viewer"]
    assert client.get(f"/documents/{doc_id}/download", headers=v).status_code == 404
    assert client.put(f"/documents/{doc_id}", headers=v, json={"name": "x.txt"}).status_code == 404
    assert client.delete(f"/documents/{doc_id}", headers=v).status_code == 404


def test_unshared_doc_not_in_viewer_list(client, tokens, doc_id):
    r = client.get("/documents", headers=tokens["viewer"])
    assert doc_id not in [d["id"] for d in r.json()]


def test_unknown_id_looks_same_as_forbidden(client, tokens, doc_id):
    v = tokens["viewer"]
    forbidden = client.get(f"/documents/{doc_id}/download", headers=v)
    missing = client.get("/documents/999999/download", headers=v)
    assert forbidden.status_code == missing.status_code == 404
    assert forbidden.json() == missing.json()


def test_admin_cannot_read_file_contents(client, tokens, doc_id):
    r = client.get(f"/documents/{doc_id}/download", headers=tokens["admin"])
    assert r.status_code == 404


def test_deleted_doc_is_gone(client, tokens, doc_id):
    assert client.delete(f"/documents/{doc_id}", headers=tokens["owner"]).status_code == 200
    assert client.get(f"/documents/{doc_id}/download", headers=tokens["owner"]).status_code == 404


# ---------- sharing and revoking ----------

def share(client, tokens, doc_id, level, who="owner"):
    return client.post(f"/documents/{doc_id}/share", headers=tokens[who],
                       json={"email": "viewer@sealtrail.test", "level": level})


def test_read_share_allows_download_but_not_edit(client, tokens, doc_id):
    assert share(client, tokens, doc_id, "read").status_code == 200
    v = tokens["viewer"]
    assert client.get(f"/documents/{doc_id}/download", headers=v).status_code == 200
    assert doc_id in [d["id"] for d in client.get("/documents", headers=v).json()]
    assert client.put(f"/documents/{doc_id}", headers=v, json={"name": "x.txt"}).status_code == 404


def test_edit_share_allows_edit_but_not_delete_or_share(client, tokens, doc_id):
    assert share(client, tokens, doc_id, "edit").status_code == 200
    v = tokens["viewer"]
    r = client.put(f"/documents/{doc_id}", headers=v, json={"name": "by-viewer.txt"})
    assert r.status_code == 200
    assert r.json()["name"] == "by-viewer.txt"
    assert client.delete(f"/documents/{doc_id}", headers=v).status_code == 404
    assert share(client, tokens, doc_id, "edit", who="viewer").status_code == 404


def test_revoke_takes_effect_immediately(client, tokens, doc_id):
    v = tokens["viewer"]
    share(client, tokens, doc_id, "edit")
    assert client.get(f"/documents/{doc_id}/download", headers=v).status_code == 200

    viewer_id = client.get("/auth/me", headers=v).json()["id"]
    r = client.delete(f"/documents/{doc_id}/share/{viewer_id}", headers=tokens["owner"])
    assert r.status_code == 200

    assert client.get(f"/documents/{doc_id}/download", headers=v).status_code == 404
    assert client.put(f"/documents/{doc_id}", headers=v, json={"name": "x.txt"}).status_code == 404
    assert doc_id not in [d["id"] for d in client.get("/documents", headers=v).json()]


def test_share_list_visible_to_owner_only(client, tokens, doc_id):
    share(client, tokens, doc_id, "read")
    r = client.get(f"/documents/{doc_id}/shares", headers=tokens["owner"])
    assert r.status_code == 200
    assert r.json()[0]["email"] == "viewer@sealtrail.test"
    assert client.get(f"/documents/{doc_id}/shares", headers=tokens["viewer"]).status_code == 404


def test_cannot_share_with_admin(client, tokens, doc_id):
    r = client.post(f"/documents/{doc_id}/share", headers=tokens["owner"],
                    json={"email": "admin@sealtrail.test", "level": "read"})
    assert r.status_code == 400


def test_invalid_level_rejected(client, tokens, doc_id):
    assert share(client, tokens, doc_id, "superuser").status_code == 400


# ---------- audit log ----------

def test_audit_is_admin_only(client, tokens):
    assert client.get("/admin/audit", headers=tokens["viewer"]).status_code == 403
    assert client.get("/admin/audit", headers=tokens["owner"]).status_code == 403
    assert client.get("/admin/audit", headers=tokens["admin"]).status_code == 200


def test_denied_attempts_are_logged(client, tokens, doc_id):
    client.get(f"/documents/{doc_id}/download", headers=tokens["viewer"])
    rows = client.get("/admin/audit", headers=tokens["admin"]).json()
    assert any(r["actor"] == "viewer@sealtrail.test" and r["action"] == "download"
               and r["result"] == "denied" and r["document_id"] == doc_id for r in rows)


# ---------- login rate limiting ----------

def test_login_lockout_after_five_failures(client):
    from app import auth
    auth._failed.clear()
    bad = {"username": "lockout-test@sealtrail.test", "password": "wrong"}
    for _ in range(5):
        assert client.post("/auth/login", data=bad).status_code == 401
    assert client.post("/auth/login", data=bad).status_code == 429
    # A different account is unaffected
    ok = client.post("/auth/login", data={"username": "owner@sealtrail.test",
                                          "password": "Owner#Demo2026"})
    assert ok.status_code == 200
    auth._failed.clear()
# ---------- restore and history ----------

def test_restore_deleted_document(client, tokens, doc_id):
    o = tokens["owner"]
    assert client.delete(f"/documents/{doc_id}", headers=o).status_code == 200
    assert doc_id in [d["id"] for d in client.get("/documents/deleted/list", headers=o).json()]
    assert client.post(f"/documents/{doc_id}/restore", headers=o).status_code == 200
    assert client.get(f"/documents/{doc_id}/download", headers=o).status_code == 200


def test_viewer_cannot_restore(client, tokens, doc_id):
    client.delete(f"/documents/{doc_id}", headers=tokens["owner"])
    assert client.post(f"/documents/{doc_id}/restore", headers=tokens["viewer"]).status_code == 404
    assert client.get(f"/documents/{doc_id}/download", headers=tokens["owner"]).status_code == 404


def test_restore_of_live_document_is_404(client, tokens, doc_id):
    assert client.post(f"/documents/{doc_id}/restore", headers=tokens["owner"]).status_code == 404


def test_history_is_owner_only_and_shows_denials(client, tokens, doc_id):
    client.get(f"/documents/{doc_id}/download", headers=tokens["viewer"])  # denied
    r = client.get(f"/documents/{doc_id}/history", headers=tokens["owner"])
    assert r.status_code == 200
    assert any(h["result"] == "denied" and h["action"] == "download" for h in r.json())
    assert client.get(f"/documents/{doc_id}/history", headers=tokens["viewer"]).status_code == 404
    assert client.get(f"/documents/{doc_id}/history", headers=tokens["admin"]).status_code == 404

# ---------- audit chain (keep this LAST) ----------

def test_zz_audit_chain_is_valid(client, tokens):
    # Runs last (file order): after all the activity above, the chain must still verify.
    r = client.get("/admin/audit/verify", headers=tokens["admin"])
    assert r.status_code == 200
    assert r.json()["valid"] is True
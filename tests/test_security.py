import os
from pathlib import Path
import pytest

os.environ["ATLAS_DB_PATH"] = str(Path(__file__).parent / "test.db")
os.environ["ATLAS_BOOTSTRAP_PASSWORD"] = "TestPassword!234"

from fastapi.testclient import TestClient
from atlas.main import app, db, login_limiter, enrollment_limiter, register_limiter
from atlas.security import hash_secret, verify_secret, utcnow

client = TestClient(app)


@pytest.fixture(autouse=True)
def reset_limiters():
    login_limiter.history.clear()
    enrollment_limiter.history.clear()
    register_limiter.history.clear()


def login():
    r = client.post("/api/auth/login", json={"username": "admin", "password": "TestPassword!234"})
    assert r.status_code == 200
    r = client.get("/api/csrf")
    assert r.status_code == 200
    return client.cookies.get("atlas_csrf")


def teardown_module():
    try:
        Path(db.path).unlink()
    except FileNotFoundError:
        pass


def test_password_hashing_and_verification():
    secret = "SuperSecretPassword123!"
    encoded = hash_secret(secret)
    assert encoded.startswith("scrypt$")
    assert verify_secret(secret, encoded) is True
    assert verify_secret("WrongPassword!", encoded) is False
    assert verify_secret(secret, "invalid_format") is False


def test_login_csrf_and_enrollment():
    csrf = login()
    r = client.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    token = r.json()["token"]
    second = client.post("/api/agent/register", json={"enrollment_token": token, "name": "srv-a", "hostname": "srv-a", "platform": "Linux", "arch": "x86_64", "os_version": "test"})
    assert second.status_code == 200
    again = client.post("/api/agent/register", json={"enrollment_token": token, "name": "srv-b", "hostname": "srv-b", "platform": "Linux", "arch": "x86_64", "os_version": "test"})
    assert again.status_code == 401


def test_mutation_requires_csrf():
    login()
    assert client.post("/api/enrollment-tokens").status_code == 403


def test_heartbeat_and_approval_gate():
    csrf = login()
    token = client.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf}).json()["token"]
    reg = client.post("/api/agent/register", json={"enrollment_token": token, "name": "srv-c", "hostname": "srv-c", "platform": "Linux", "arch": "x86_64", "os_version": "test"}).json()
    hb = client.post("/api/agent/heartbeat", headers={"X-Atlas-Agent-Key": reg["agent_key"]}, json={"hostname": "srv-c", "platform": "Linux", "arch": "x86_64", "os_version": "test", "cpu": 15, "memory": 22, "disk": 31, "uptime": 100, "inventory": {}, "posture": {}})
    assert hb.status_code == 200
    job = client.post(f"/api/servers/{reg['server_id']}/jobs", headers={"X-CSRF-Token": csrf}, json={"action": "reboot", "params": {}})
    assert job.status_code == 200 and job.json()["requires_approval"]
    polled = client.post("/api/agent/jobs/poll", headers={"X-Atlas-Agent-Key": reg["agent_key"]})
    assert polled.json()["job"] is None


def test_service_validation():
    csrf = login()
    token = client.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf}).json()["token"]
    sid = client.post("/api/agent/register", json={"enrollment_token": token, "name": "srv-d", "hostname": "srv-d", "platform": "Linux", "arch": "x86_64", "os_version": "test"}).json()["server_id"]
    r = client.post(f"/api/servers/{sid}/jobs", headers={"X-CSRF-Token": csrf}, json={"action": "service_restart", "params": {"service": "bad service; rm -rf /"}})
    assert r.status_code == 422


def test_login_rate_limiting_and_failed_audit():
    uname = "ratelimit_user"
    for _ in range(5):
        r = client.post("/api/auth/login", json={"username": uname, "password": "WrongPassword"})
        assert r.status_code in (401, 429)

    r = client.post("/api/auth/login", json={"username": uname, "password": "WrongPassword"})
    assert r.status_code == 429

    csrf = login()
    audit_res = client.get("/api/audit")
    assert audit_res.status_code == 200
    logs = audit_res.json()
    failed_logs = [l for l in logs if l["action"] == "auth.login_failed" and l["target"] == uname]
    assert len(failed_logs) > 0


def test_audit_hash_chain_verification_and_tampering():
    csrf = login()
    v = client.get("/api/audit/verify")
    assert v.status_code == 200
    assert v.json()["status"] == "verified"

    db.execute("UPDATE audit_log SET target='tampered_target' WHERE id=(SELECT id FROM audit_log LIMIT 1)")

    v_tampered = client.get("/api/audit/verify")
    assert v_tampered.status_code == 200
    assert v_tampered.json()["status"] == "tampered"


def test_role_based_authorization_boundaries():
    op_pass = hash_secret("OpPassword!234")
    view_pass = hash_secret("ViewPassword!234")
    now = utcnow().isoformat()
    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", ("op_user", op_pass, "operator", now))
    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", ("view_user", view_pass, "viewer", now))

    c_view = TestClient(app)
    r = c_view.post("/api/auth/login", json={"username": "view_user", "password": "ViewPassword!234"})
    assert r.status_code == 200
    r_csrf = c_view.get("/api/csrf")
    csrf_view = r_csrf.json()["csrf_token"]

    r = c_view.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf_view})
    assert r.status_code == 403

    r = c_view.post("/api/servers/some-id/jobs", headers={"X-CSRF-Token": csrf_view}, json={"action": "collect_diagnostics", "params": {}})
    assert r.status_code == 403

    c_op = TestClient(app)
    c_op.post("/api/auth/login", json={"username": "op_user", "password": "OpPassword!234"})
    csrf_op = c_op.get("/api/csrf").json()["csrf_token"]

    r = c_op.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf_op})
    assert r.status_code == 403

    r = c_op.get("/api/audit")
    assert r.status_code == 403


def test_security_response_headers():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in r.headers
    assert r.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_agent_authentication_failure():
    r = client.post("/api/agent/heartbeat", headers={"X-Atlas-Agent-Key": "invalid_key_123"}, json={"hostname": "fake", "platform": "Linux", "arch": "x86_64", "cpu": 0, "memory": 0, "disk": 0, "uptime": 0})
    assert r.status_code == 401

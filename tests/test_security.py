import os
from pathlib import Path

os.environ["ATLAS_DB_PATH"] = str(Path(__file__).parent / "test.db")
os.environ["ATLAS_BOOTSTRAP_PASSWORD"] = "TestPassword!234"

from atlas.config import settings
from atlas.security import hash_secret, encrypt_secret, decrypt_secret, utcnow
from atlas.db import Database

test_db_file = Path(__file__).parent / "test.db"
if test_db_file.exists():
    try:
        test_db_file.unlink()
    except OSError:
        pass

from fastapi.testclient import TestClient
from atlas.main import app, db

# Ensure admin user is seeded with known password in test db
with db.connect() as conn:
    conn.execute("DELETE FROM users WHERE username='admin'")
    conn.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", ("admin", hash_secret("TestPassword!234"), "admin", utcnow().isoformat()))

client = TestClient(app)


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
    r = client.post(f"/api/servers/{sid}/jobs", headers={"X-CSRF-Token": csrf}, json={"action": "service_restart", "params": {"service": "bad service"}})
    assert r.status_code == 422


def test_separation_of_duties_and_encryption():
    enc = encrypt_secret("my-super-secret-password")
    assert enc != "my-super-secret-password"
    assert decrypt_secret(enc) == "my-super-secret-password"

    csrf = login()
    token = client.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf}).json()["token"]
    sid = client.post("/api/agent/register", json={"enrollment_token": token, "name": "srv-sod", "hostname": "srv-sod", "platform": "Linux", "arch": "x86_64", "os_version": "test"}).json()["server_id"]

    # Create high impact job as admin
    job = client.post(f"/api/servers/{sid}/jobs", headers={"X-CSRF-Token": csrf}, json={"action": "reboot", "params": {}}).json()
    jid = job["id"]

    # Get approval ID
    appr = client.get("/api/approvals").json()
    approval = [a for a in appr if a["job_id"] == jid][0]
    aid = approval["id"]

    # Trying to approve own job should fail (403 separation of duties)
    fail_res = client.post(f"/api/approvals/{aid}/approve", headers={"X-CSRF-Token": csrf})
    assert fail_res.status_code == 403
    assert "separation of duties" in fail_res.json()["detail"].lower()

    # Create a second admin user to approve
    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", ("admin2", hash_secret("TestPassword!234"), "admin", utcnow().isoformat()))

    # Login as admin2
    client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    r = client.post("/api/auth/login", json={"username": "admin2", "password": "TestPassword!234"})
    assert r.status_code == 200
    csrf2 = client.get("/api/csrf").json()["csrf_token"]

    # Approve as admin2 should succeed
    succ_res = client.post(f"/api/approvals/{aid}/approve", headers={"X-CSRF-Token": csrf2})
    assert succ_res.status_code == 200


def test_durable_jobs_and_maintenance_windows():
    csrf = login()
    token = client.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf}).json()["token"]
    sid = client.post("/api/agent/register", json={"enrollment_token": token, "name": "srv-jobs", "hostname": "srv-jobs", "platform": "Linux", "arch": "x86_64", "os_version": "test"}).json()["server_id"]

    # Idempotency key test
    j1 = client.post(f"/api/servers/{sid}/jobs", headers={"X-CSRF-Token": csrf}, json={"action": "refresh_inventory", "idempotency_key": "idemp-001"}).json()
    j2 = client.post(f"/api/servers/{sid}/jobs", headers={"X-CSRF-Token": csrf}, json={"action": "refresh_inventory", "idempotency_key": "idemp-001"}).json()
    assert j1["id"] == j2["id"]
    assert j2.get("idempotent") is True

    # Cancel job test
    cancel_res = client.post(f"/api/jobs/{j1['id']}/cancel", headers={"X-CSRF-Token": csrf})
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "cancelled"

    # Maintenance window creation test
    mw_res = client.post("/api/maintenance-windows", headers={"X-CSRF-Token": csrf}, json={
        "name": "Standard Window",
        "starts_at": "2020-01-01T00:00:00Z",
        "ends_at": "2099-01-01T00:00:00Z",
        "is_blackout": False
    })
    assert mw_res.status_code == 200
    assert len(client.get("/api/maintenance-windows").json()) >= 1


def test_linux_adapters():
    import agent.__main__ as ag
    mgr = ag.linux_package_manager()
    fw = ag.linux_firewall_status()
    assert "firewall" in fw
    pkgs = ag.linux_package_list()
    assert "manager" in pkgs
    st, res = ag.execute({"action": "inspect_firewall"})
    assert st in ("succeeded", "failed")


def test_windows_adapter_unsupported_reporting():
    import agent.__main__ as ag
    st, res = ag.execute({"action": "windows_event_log", "params": {"log_name": "System"}})
    if os.name != "nt":
        assert st == "failed"
        assert "unsupported_reason" in res


def test_bmc_and_provisioning():
    csrf = login()

    # Register BMC Node
    bmc = client.post("/api/hardware/bmc", headers={"X-CSRF-Token": csrf}, json={
        "name": "bmc-rack1-01",
        "address": "127.0.0.1:29999",
        "bmc_type": "redfish",
        "username": "admin",
        "password": "BmcPassword123"
    }).json()
    bmc_id = bmc["id"]

    # Power action against unreachable BMC should return 502 with unsupported_reason
    p_res = client.post(f"/api/hardware/bmc/{bmc_id}/power", headers={"X-CSRF-Token": csrf}, json={"action": "on"})
    assert p_res.status_code == 502
    assert "unsupported_reason" in p_res.json()

    # Create provisioning profile
    prof = client.post("/api/provisioning/profiles", headers={"X-CSRF-Token": csrf}, json={
        "name": "Ubuntu 24.04 LTS",
        "os_family": "linux",
        "image_url": "https://images.example.com/ubuntu-24.04.iso"
    }).json()
    prof_id = prof["id"]

    # Provisioning job without confirm_destructive should fail (400)
    fail_pjob = client.post("/api/provisioning/jobs", headers={"X-CSRF-Token": csrf}, json={
        "profile_id": prof_id,
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "target_hostname": "baremetal-01",
        "confirm_destructive": False
    })
    assert fail_pjob.status_code == 400

    # With confirm_destructive should succeed
    succ_pjob = client.post("/api/provisioning/jobs", headers={"X-CSRF-Token": csrf}, json={
        "profile_id": prof_id,
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "target_hostname": "baremetal-01",
        "confirm_destructive": True
    })
    assert succ_pjob.status_code == 200


def test_vulnerabilities_drift_and_compliance():
    csrf = login()

    # 1. Ingest CVE
    cve_res = client.post("/api/vulnerabilities/cves", headers={"X-CSRF-Token": csrf}, json={
        "cve_id": "CVE-2025-1234",
        "title": "OpenSSL Remote Code Execution",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected_packages": [{"package": "openssl", "fixed_version": "3.0.2"}]
    })
    assert cve_res.status_code == 200

    # 2. Register server with openssl 1.0.0
    token = client.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf}).json()["token"]
    reg = client.post("/api/agent/register", json={"enrollment_token": token, "name": "srv-vuln", "hostname": "srv-vuln", "platform": "Linux", "arch": "x86_64", "os_version": "test"}).json()
    sid = reg["server_id"]
    client.post("/api/agent/heartbeat", headers={"X-Atlas-Agent-Key": reg["agent_key"]}, json={
        "hostname": "srv-vuln", "platform": "Linux", "arch": "x86_64", "os_version": "test",
        "cpu": 10, "memory": 20, "disk": 30, "uptime": 500,
        "inventory": {"packages": {"openssl": "1.0.0"}},
        "posture": {"firewall": False}
    })

    # Scan for vulnerabilities
    scan_res = client.post(f"/api/vulnerabilities/scan/{sid}", headers={"X-CSRF-Token": csrf})
    assert scan_res.status_code == 200
    assert scan_res.json()["vulnerabilities_found"] == 1

    # 3. Create Desired State Policy & Evaluate Drift
    pol = client.post("/api/policies", headers={"X-CSRF-Token": csrf}, json={
        "name": "Firewall Enabled Policy",
        "kind": "firewall",
        "definition": {"enabled": True}
    }).json()
    pol_id = pol["id"]

    drift_res = client.post(f"/api/policies/{pol_id}/evaluate/{sid}", headers={"X-CSRF-Token": csrf})
    assert drift_res.status_code == 200
    assert drift_res.json()["status"] == "drifted"

    # 4. Compliance Baseline & Scan
    base = client.post("/api/compliance/baselines", headers={"X-CSRF-Token": csrf}, json={
        "name": "CIS Benchmark v1",
        "framework": "CIS",
        "rules": [{"rule": "require_firewall"}, {"rule": "custom_audit_control"}]
    }).json()
    base_id = base["id"]

    cscan = client.post(f"/api/compliance/scan/{sid}?baseline_id={base_id}", headers={"X-CSRF-Token": csrf})
    assert cscan.status_code == 200
    assert "score" in cscan.json()


def test_rollouts_metrics_and_health():
    # Health checks
    assert client.get("/liveness").status_code == 200
    assert client.get("/readiness").status_code == 200
    m = client.get("/metrics")
    assert m.status_code == 200
    assert "atlas_managed_servers_total" in m.text

    # Rollout rings
    csrf = login()
    r1 = client.post("/api/rollouts/rings", headers={"X-CSRF-Token": csrf}, json={"name": "Canary Ring", "ring_order": 1, "target_group": "canary"}).json()
    r2 = client.post("/api/rollouts/rings", headers={"X-CSRF-Token": csrf}, json={"name": "Ring 1 - Staging", "ring_order": 2, "target_group": "staging"}).json()

    p_res = client.post(f"/api/rollouts/promote/{r1['id']}", headers={"X-CSRF-Token": csrf})
    assert p_res.status_code == 200
    assert p_res.json()["next_ring"] == "Ring 1 - Staging"

    rb_res = client.post(f"/api/rollouts/rollback/{r1['id']}", headers={"X-CSRF-Token": csrf})
    assert rb_res.status_code == 200
    assert rb_res.json()["status"] == "rolled_back"


def test_agent_security_and_cli():
    csrf = login()

    # Register server
    token = client.post("/api/enrollment-tokens", headers={"X-CSRF-Token": csrf}).json()["token"]
    reg = client.post("/api/agent/register", json={"enrollment_token": token, "name": "srv-cli", "hostname": "srv-cli", "platform": "Linux", "arch": "x86_64", "os_version": "test"}).json()
    sid = reg["server_id"]
    agent_key = reg["agent_key"]

    # Rotate agent key
    rot_res = client.post("/api/agent/rotate", headers={"X-Atlas-Agent-Key": agent_key})
    assert rot_res.status_code == 200
    new_key = rot_res.json()["agent_key"]
    assert new_key != agent_key

    # Old key should now fail (401)
    old_fail = client.post("/api/agent/heartbeat", headers={"X-Atlas-Agent-Key": agent_key}, json={"hostname": "srv-cli", "platform": "Linux", "arch": "x86_64", "os_version": "test", "cpu": 5, "memory": 10, "disk": 15, "uptime": 100, "inventory": {}, "posture": {}})
    assert old_fail.status_code == 401

    # New key should succeed (200)
    new_succ = client.post("/api/agent/heartbeat", headers={"X-Atlas-Agent-Key": new_key}, json={"hostname": "srv-cli", "platform": "Linux", "arch": "x86_64", "os_version": "test", "cpu": 5, "memory": 10, "disk": 15, "uptime": 100, "inventory": {}, "posture": {}})
    assert new_succ.status_code == 200

    # Quarantine server
    q_res = client.post(f"/api/servers/{sid}/quarantine?quarantined=true", headers={"X-CSRF-Token": csrf})
    assert q_res.status_code == 200

    # Quarantined server heartbeat should fail with 403
    q_fail = client.post("/api/agent/heartbeat", headers={"X-Atlas-Agent-Key": new_key}, json={"hostname": "srv-cli", "platform": "Linux", "arch": "x86_64", "os_version": "test", "cpu": 5, "memory": 10, "disk": 15, "uptime": 100, "inventory": {}, "posture": {}})
    assert q_fail.status_code == 403

    # Unquarantine
    client.post(f"/api/servers/{sid}/quarantine?quarantined=false", headers={"X-CSRF-Token": csrf})

    # Test CLI invocation
    import atlas.cli as cli
    assert hasattr(cli, "main")

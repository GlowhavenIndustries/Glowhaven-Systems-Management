import os
from pathlib import Path

os.environ["MERIDIAN_DB_PATH"] = str(Path(__file__).parent / "test.db")
os.environ["MERIDIAN_BOOTSTRAP_PASSWORD"] = "TestPassword!234"

from fastapi.testclient import TestClient
from meridian.main import app, db

client=TestClient(app)


def login():
    r=client.post("/api/auth/login",json={"username":"admin","password":"TestPassword!234"}); assert r.status_code==200
    r=client.get("/api/csrf"); assert r.status_code==200
    return client.cookies.get("meridian_csrf")


def teardown_module():
    try: Path(db.path).unlink()
    except FileNotFoundError: pass


def test_login_csrf_and_enrollment():
    csrf=login(); r=client.post("/api/enrollment-tokens",headers={"X-CSRF-Token":csrf}); assert r.status_code==200
    token=r.json()["token"]; second=client.post("/api/agent/register",json={"enrollment_token":token,"name":"srv-a","hostname":"srv-a","platform":"Linux","arch":"x86_64","os_version":"test"}); assert second.status_code==200
    again=client.post("/api/agent/register",json={"enrollment_token":token,"name":"srv-b","hostname":"srv-b","platform":"Linux","arch":"x86_64","os_version":"test"}); assert again.status_code==401


def test_mutation_requires_csrf():
    login(); assert client.post("/api/enrollment-tokens").status_code==403


def test_heartbeat_and_approval_gate():
    csrf=login(); token=client.post("/api/enrollment-tokens",headers={"X-CSRF-Token":csrf}).json()["token"]
    reg=client.post("/api/agent/register",json={"enrollment_token":token,"name":"srv-c","hostname":"srv-c","platform":"Linux","arch":"x86_64","os_version":"test"}).json()
    hb=client.post("/api/agent/heartbeat",headers={"X-Meridian-Agent-Key":reg["agent_key"]},json={"hostname":"srv-c","platform":"Linux","arch":"x86_64","os_version":"test","cpu":15,"memory":22,"disk":31,"uptime":100,"inventory":{},"posture":{}}); assert hb.status_code==200
    job=client.post(f"/api/servers/{reg['server_id']}/jobs",headers={"X-CSRF-Token":csrf},json={"action":"reboot","params":{}}); assert job.status_code==200 and job.json()["requires_approval"]
    polled=client.post("/api/agent/jobs/poll",headers={"X-Meridian-Agent-Key":reg["agent_key"]}); assert polled.json()["job"] is None


def test_service_validation():
    csrf=login(); token=client.post("/api/enrollment-tokens",headers={"X-CSRF-Token":csrf}).json()["token"]
    sid=client.post("/api/agent/register",json={"enrollment_token":token,"name":"srv-d","hostname":"srv-d","platform":"Linux","arch":"x86_64","os_version":"test"}).json()["server_id"]
    r=client.post(f"/api/servers/{sid}/jobs",headers={"X-CSRF-Token":csrf},json={"action":"service_restart","params":{"service":"bad service"}}); assert r.status_code==422

from __future__ import annotations

import asyncio
import json
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .config import settings
from .db import Database
from .security import (
    decrypt_secret,
    encrypt_secret,
    hash_secret,
    hash_token,
    random_token,
    user_has_permission,
    utcnow,
    verify_secret,
)

ROOT = Path(__file__).resolve().parent
app = FastAPI(title="Glowhaven Atlas", version="0.1.0", docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
db = Database(settings.db_path)

SESSION_COOKIE = "atlas_session"
CSRF_COOKIE = "atlas_csrf"
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")

ALLOWED_ACTIONS = {
    "refresh_inventory", "collect_diagnostics", "service_start", "service_stop",
    "service_restart", "reboot", "shutdown", "assess_patches", "apply_security_patches",
    "package_install", "package_remove", "package_update", "package_list", "inspect_firewall",
    "windows_event_log", "windows_local_users", "windows_network_info"
}
HIGH_IMPACT = {"shutdown", "reboot", "apply_security_patches", "package_install", "package_remove"}


def audit(actor: str, action: str, target: str, result: str = "success", detail: dict[str, Any] | None = None) -> None:
    db.execute("INSERT INTO audit_log(actor,action,target,result,detail,created_at) VALUES(?,?,?,?,?,?)", (actor, action, target, result, json.dumps(detail or {}, separators=(",", ":")), utcnow().isoformat()))


def bootstrap() -> None:
    if db.one("SELECT id FROM users LIMIT 1"):
        return
    password = settings.bootstrap_password or random_token()
    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (settings.bootstrap_admin, hash_secret(password), "admin", utcnow().isoformat()))
    if not settings.bootstrap_password:
        print(f"Atlas bootstrap password: {password}")

bootstrap()


@app.middleware("http")
async def headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    if settings.secure_cookies:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)

class CreateJobPayload(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=128)
    scheduled_at: str | None = Field(default=None, max_length=64)
    priority: int = Field(default=1, ge=1, le=10)
    timeout_seconds: int = Field(default=3600, ge=10, le=86400)
    max_retries: int = Field(default=3, ge=0, le=10)

    @field_validator("action")
    @classmethod
    def valid_action(cls, value: str) -> str:
        if value not in ALLOWED_ACTIONS:
            raise ValueError("unsupported action")
        return value

class Heartbeat(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=64)
    arch: str = Field(min_length=1, max_length=64)
    os_version: str = Field(default="", max_length=255)
    cpu: float = Field(ge=0, le=100)
    memory: float = Field(ge=0, le=100)
    disk: float = Field(ge=0, le=100)
    uptime: int = Field(ge=0, le=10**10)
    inventory: dict[str, Any] = Field(default_factory=dict)
    posture: dict[str, Any] = Field(default_factory=dict)

class Register(BaseModel):
    enrollment_token: str = Field(min_length=20, max_length=256)
    name: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    platform: str = Field(min_length=1, max_length=64)
    arch: str = Field(min_length=1, max_length=64)
    os_version: str = Field(default="", max_length=255)

class JobReport(BaseModel):
    status: str = Field(pattern=r"^(succeeded|failed)$")
    result: dict[str, Any] = Field(default_factory=dict)

class MaintenanceWindowPayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    starts_at: str = Field(min_length=10, max_length=64)
    ends_at: str = Field(min_length=10, max_length=64)
    schedule_type: str = Field(default="one_time", pattern=r"^(one_time|recurring)$")
    recurrence_rule: str | None = Field(default=None, max_length=128)
    timezone: str = Field(default="UTC", max_length=64)
    is_blackout: bool = Field(default=False)
    enabled: bool = Field(default=True)

class BMCRegisterPayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    address: str = Field(min_length=1, max_length=255)
    bmc_type: str = Field(default="redfish", pattern=r"^(redfish|ipmi)$")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    server_id: str | None = Field(default=None)

class BMCPowerPayload(BaseModel):
    action: str = Field(pattern=r"^(on|off|graceful_restart|hard_reset)$")

class ProvisioningProfilePayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    os_family: str = Field(min_length=1, max_length=64)
    image_url: str = Field(min_length=5, max_length=512)
    partition_layout: dict[str, Any] = Field(default_factory=dict)
    post_install_script: str = Field(default="")
    network_config: dict[str, Any] = Field(default_factory=dict)

class ProvisioningJobPayload(BaseModel):
    profile_id: str = Field(min_length=1, max_length=128)
    mac_address: str = Field(pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    target_hostname: str = Field(min_length=1, max_length=255)
    confirm_destructive: bool = Field(default=False)

class CVEIngestPayload(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,7}$")
    title: str = Field(min_length=1, max_length=255)
    severity: str = Field(pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW)$")
    cvss_score: float = Field(ge=0.0, le=10.0)
    affected_packages: list[dict[str, str]] = Field(default_factory=list)
    description: str = Field(default="")
    published_at: str = Field(default="")

class ConfigPolicyPayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: str = Field(pattern=r"^(service|package|file|firewall|registry)$")
    target_scope: str = Field(default="global")
    definition: dict[str, Any] = Field(default_factory=dict)
    remediation_behavior: str = Field(default="audit_only", pattern=r"^(audit_only|automatic_remediate)$")
    enabled: bool = Field(default=True)

class ComplianceBaselinePayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    framework: str = Field(min_length=1, max_length=64)
    description: str = Field(default="")
    rules: list[dict[str, Any]] = Field(default_factory=list)

class RolloutRingPayload(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    ring_order: int = Field(ge=1, le=100)
    target_group: str = Field(default="all")
    max_concurrency: int = Field(default=1, ge=1, le=1000)
    failure_threshold_pct: float = Field(default=10.0, ge=0.0, le=100.0)
    auto_promote: bool = Field(default=False)


def session(session_id: str | None = Cookie(None, alias=SESSION_COOKIE)) -> sqlite3.Row:
    if not session_id:
        raise HTTPException(401, "authentication required")
    row = db.one("SELECT s.*,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=?", (session_id,))
    if not row or row["expires_at"] <= utcnow().isoformat():
        raise HTTPException(401, "session expired")
    return row


def role(*roles: str):
    def dep(s: sqlite3.Row = Depends(session)) -> sqlite3.Row:
        if s["role"] not in roles:
            raise HTTPException(403, "insufficient permissions")
        return s
    return dep


def permission(perm: str):
    def dep(s: sqlite3.Row = Depends(session)) -> sqlite3.Row:
        custom_rows = db.all("SELECT permission FROM permissions WHERE role=?", (s["role"],))
        custom_perms = {r["permission"] for r in custom_rows}
        if not user_has_permission(s["role"], perm, custom_perms):
            raise HTTPException(403, f"permission required: {perm}")
        return s
    return dep


def csrf(s: sqlite3.Row = Depends(session), token_header: str | None = Header(None, alias="X-CSRF-Token"), token_cookie: str | None = Cookie(None, alias=CSRF_COOKIE)) -> sqlite3.Row:
    if not token_header or not token_cookie or not secrets.compare_digest(token_header, token_cookie) or not secrets.compare_digest(token_header, s["csrf"]):
        raise HTTPException(403, "csrf validation failed")
    return s


def agent(agent_key: str | None = Header(None, alias="X-Atlas-Agent-Key")) -> sqlite3.Row:
    if not agent_key:
        raise HTTPException(401, "agent key required")
    row = db.one("SELECT * FROM servers WHERE agent_key_hash=?", (hash_token(agent_key),))
    if not row:
        raise HTTPException(401, "invalid agent key")
    if row["quarantined"]:
        raise HTTPException(403, "agent host is quarantined")
    return row


def status(row: sqlite3.Row) -> str:
    if not row["last_seen"]:
        return "offline"
    try:
        age = (utcnow() - datetime.fromisoformat(row["last_seen"])).total_seconds()
    except ValueError:
        return "offline"
    if age > 90:
        return "offline"
    if max(row["cpu"], row["memory"], row["disk"]) >= 90:
        return "warning"
    return "online"


def server_json(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "name": row["name"], "hostname": row["hostname"], "platform": row["platform"], "arch": row["arch"], "os_version": row["os_version"], "status": status(row), "last_seen": row["last_seen"], "cpu": row["cpu"], "memory": row["memory"], "disk": row["disk"], "uptime": row["uptime"], "inventory": db.obj(row["inventory"]), "posture": db.obj(row["posture"]), "created_at": row["created_at"]}


def job_json(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "server_id": row["server_id"], "action": row["action"], "params": db.obj(row["params"]), "status": row["status"], "requires_approval": bool(row["requires_approval"]), "approved_by": row["approved_by"], "result": db.obj(row["result"]), "created_at": row["created_at"], "started_at": row["started_at"], "finished_at": row["finished_at"]}


def is_in_maintenance_window(server_id: str = "") -> bool:
    now_iso = utcnow().isoformat()
    blackout = db.one("SELECT id FROM maintenance_windows WHERE enabled=1 AND is_blackout=1 AND starts_at<=? AND ends_at>=? LIMIT 1", (now_iso, now_iso))
    if blackout:
        return False
    row = db.one("SELECT id FROM maintenance_windows WHERE enabled=1 AND is_blackout=0 AND starts_at<=? AND ends_at>=? LIMIT 1", (now_iso, now_iso))
    return bool(row)


def in_maintenance() -> bool:
    return is_in_maintenance_window()


def log_job_history(job_id: str, state: str, message: str = "") -> None:
    db.execute("INSERT INTO job_history(job_id, state, message, timestamp) VALUES(?,?,?,?)", (job_id, state, message, utcnow().isoformat()))


def validate_params(action: str, params: dict[str, Any]) -> dict[str, Any]:
    if action.startswith("service_"):
        service = params.get("service")
        if not isinstance(service, str) or not SERVICE_RE.fullmatch(service):
            raise HTTPException(422, "invalid service name")
        return {"service": service}
    if action.startswith("package_"):
        pkg = params.get("package", "")
        if not isinstance(pkg, str):
            raise HTTPException(422, "invalid package name")
        return {"package": pkg}
    return {}


@app.get("/")
async def home():
    return FileResponse(ROOT / "static" / "index.html")

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "glowhaven-atlas"}

@app.get("/liveness")
async def liveness():
    return {"status": "alive"}

@app.get("/readiness")
async def readiness():
    try:
        db.one("SELECT 1")
        return {"status": "ready", "database": "connected"}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"status": "not_ready", "error": str(exc)})

@app.get("/metrics")
async def metrics():
    servers = db.all("SELECT * FROM servers")
    st = [status(r) for r in servers]
    queued = db.one("SELECT COUNT(*) c FROM jobs WHERE status='queued'")["c"]
    failed_24h = db.one("SELECT COUNT(*) c FROM jobs WHERE status='failed' AND created_at>=?", ((utcnow() - timedelta(hours=24)).isoformat(),))["c"]

    lines = [
        "# HELP atlas_managed_servers_total Total count of managed servers in Atlas",
        "# TYPE atlas_managed_servers_total gauge",
        f"atlas_managed_servers_total {len(servers)}",
        "# HELP atlas_servers_online Count of online servers",
        "# TYPE atlas_servers_online gauge",
        f"atlas_servers_online {st.count('online')}",
        "# HELP atlas_jobs_queued_total Count of currently queued jobs",
        "# TYPE atlas_jobs_queued_total gauge",
        f"atlas_jobs_queued_total {queued}",
        "# HELP atlas_jobs_failed_24h_total Count of failed jobs in past 24 hours",
        "# TYPE atlas_jobs_failed_24h_total gauge",
        f"atlas_jobs_failed_24h_total {failed_24h}"
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain")

@app.get("/api/events/stream")
async def event_stream(request: Request, _: sqlite3.Row = Depends(session)):
    async def generate_events():
        last_id = 0
        while True:
            if await request.is_disconnected():
                break
            rows = db.all("SELECT * FROM audit_log WHERE id > ? ORDER BY id ASC LIMIT 20", (last_id,))
            for r in rows:
                last_id = r["id"]
                data = json.dumps({"id": r["id"], "actor": r["actor"], "action": r["action"], "target": r["target"], "result": r["result"], "created_at": r["created_at"]})
                yield f"data: {data}\n\n"
            await asyncio.sleep(2)

    return StreamingResponse(generate_events(), media_type="text/event-stream")

@app.post("/api/auth/login")
async def login(payload: Login, response: Response):
    row = db.one("SELECT * FROM users WHERE username=?", (payload.username.strip(),))
    if not row or not verify_secret(payload.password, row["password_hash"]):
        raise HTTPException(401, "invalid credentials")
    sid, ctoken = random_token(), random_token()
    expires = utcnow() + timedelta(hours=settings.session_hours)
    db.execute("INSERT INTO sessions(id,user_id,csrf,expires_at) VALUES(?,?,?,?)", (sid, row["id"], ctoken, expires.isoformat()))
    response.set_cookie(SESSION_COOKIE, sid, secure=settings.secure_cookies, httponly=True, samesite="strict", max_age=settings.session_hours * 3600)
    response.set_cookie(CSRF_COOKIE, ctoken, secure=settings.secure_cookies, httponly=False, samesite="strict", max_age=3600)
    audit(row["username"], "auth.login", "session")
    return {"username": row["username"], "role": row["role"]}

@app.post("/api/auth/logout")
async def logout(response: Response, s: sqlite3.Row = Depends(csrf)):
    db.execute("DELETE FROM sessions WHERE id=?", (s["id"],))
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)
    audit(s["username"], "auth.logout", "session")
    return {"ok": True}

@app.get("/api/csrf")
async def get_csrf(response: Response, s: sqlite3.Row = Depends(session)):
    response.set_cookie(CSRF_COOKIE, s["csrf"], secure=settings.secure_cookies, httponly=False, samesite="strict", max_age=3600)
    return {"csrf_token": s["csrf"]}

@app.get("/api/me")
async def me(s: sqlite3.Row = Depends(session)):
    return {"username": s["username"], "role": s["role"]}

@app.get("/api/summary")
async def summary(_: sqlite3.Row = Depends(session)):
    rows = db.all("SELECT * FROM servers")
    st = [status(r) for r in rows]
    q_row = db.one("SELECT COUNT(*) c FROM jobs WHERE status='queued'")
    queued = q_row["c"] if q_row else 0
    p_row = db.one("SELECT COUNT(*) c FROM approvals WHERE status='pending'")
    pending = p_row["c"] if p_row else 0
    f_row = db.one("SELECT COUNT(*) c FROM jobs WHERE status='failed' AND created_at>=?", ((utcnow() - timedelta(hours=24)).isoformat(),))
    failed = f_row["c"] if f_row else 0
    return {"servers": len(rows), "online": st.count("online"), "warning": st.count("warning"), "queued": queued, "pending_approvals": pending, "failed_24h": failed, "maintenance_window": in_maintenance()}

@app.get("/api/servers")
async def servers(_: sqlite3.Row = Depends(session)):
    return [server_json(r) for r in db.all("SELECT * FROM servers ORDER BY name COLLATE NOCASE")]

@app.post("/api/servers/{server_id}/quarantine")
async def quarantine_server(server_id: str, quarantined: bool = True, s: sqlite3.Row = Depends(permission("agents.quarantine")), _: sqlite3.Row = Depends(csrf)):
    if not db.one("SELECT id FROM servers WHERE id=?", (server_id,)):
        raise HTTPException(404, "server not found")
    db.execute("UPDATE servers SET quarantined=? WHERE id=?", (int(quarantined), server_id))
    audit(s["username"], "server.quarantine" if quarantined else "server.unquarantine", server_id)
    return {"server_id": server_id, "quarantined": quarantined}

@app.post("/api/agent/rotate")
async def rotate_agent_key(r: sqlite3.Row = Depends(agent)):
    new_key = random_token()
    db.execute("UPDATE servers SET agent_key_hash=? WHERE id=?", (hash_token(new_key), r["id"]))
    audit("agent", "agent.key_rotate", r["id"])
    return {"server_id": r["id"], "agent_key": new_key}

@app.get("/api/jobs")
async def jobs(_: sqlite3.Row = Depends(session)):
    return [job_json(r) for r in db.all("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 250")]

@app.get("/api/audit")
async def audit_log(_: sqlite3.Row = Depends(role("admin"))):
    rows = db.all("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300")
    return [{"id": r["id"], "actor": r["actor"], "action": r["action"], "target": r["target"], "result": r["result"], "detail": db.obj(r["detail"]), "created_at": r["created_at"]} for r in rows]

@app.post("/api/enrollment-tokens")
async def enrollment(s: sqlite3.Row = Depends(role("admin")), _: sqlite3.Row = Depends(csrf)):
    raw = random_token()
    expires = utcnow() + timedelta(minutes=settings.enrollment_minutes)
    db.execute("INSERT INTO enrollment_tokens(token_hash,created_by,expires_at) VALUES(?,?,?)", (hash_token(raw), s["user_id"], expires.isoformat()))
    audit(s["username"], "enrollment.create", "fleet", detail={"expires_at": expires.isoformat()})
    return {"token": raw, "expires_at": expires.isoformat()}

@app.post("/api/servers/{server_id}/jobs")
async def create_job(server_id: str, payload: CreateJobPayload, s: sqlite3.Row = Depends(permission("jobs.create")), _: sqlite3.Row = Depends(csrf)):
    if not db.one("SELECT id FROM servers WHERE id=?", (server_id,)):
        raise HTTPException(404, "server not found")

    if payload.idempotency_key:
        existing = db.one("SELECT id, status, requires_approval FROM jobs WHERE idempotency_key=?", (payload.idempotency_key,))
        if existing:
            return {"id": existing["id"], "status": existing["status"], "requires_approval": bool(existing["requires_approval"]), "idempotent": True}

    params = validate_params(payload.action, payload.params)
    needs_approval = payload.action in HIGH_IMPACT or (payload.action == "apply_security_patches")

    initial_status = "waiting_approval" if needs_approval else "queued"
    if not needs_approval and payload.scheduled_at:
        initial_status = "scheduled"

    jid = str(uuid.uuid4())
    now = utcnow().isoformat()
    db.execute(
        "INSERT INTO jobs(id,server_id,action,params,requested_by,status,requires_approval,result,created_at,idempotency_key,priority,scheduled_at,timeout_seconds,max_retries) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (jid, server_id, payload.action, json.dumps(params), s["user_id"], initial_status, int(needs_approval), "{}", now, payload.idempotency_key, payload.priority, payload.scheduled_at, payload.timeout_seconds, payload.max_retries)
    )

    if needs_approval:
        db.execute("INSERT INTO approvals(job_id,requested_by,created_at) VALUES(?,?,?)", (jid, s["user_id"], now))

    log_job_history(jid, initial_status, f"Job created by {s['username']}")
    audit(s["username"], "job.create", server_id, detail={"job_id": jid, "action": payload.action, "requires_approval": needs_approval})
    return {"id": jid, "status": initial_status, "requires_approval": needs_approval}

@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str, s: sqlite3.Row = Depends(permission("jobs.cancel")), _: sqlite3.Row = Depends(csrf)):
    job = db.one("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not job:
        raise HTTPException(404, "job not found")
    if job["status"] in ("succeeded", "failed", "cancelled", "rolled_back"):
        raise HTTPException(400, "job is already in a terminal state")
    now = utcnow().isoformat()
    db.execute("UPDATE jobs SET status='cancelled', finished_at=? WHERE id=?", (now, job_id))
    log_job_history(job_id, "cancelled", f"Cancelled by {s['username']}")
    audit(s["username"], "job.cancel", job_id)
    return {"ok": True, "job_id": job_id, "status": "cancelled"}

@app.get("/api/jobs/{job_id}")
async def get_job_detail(job_id: str, _: sqlite3.Row = Depends(session)):
    job = db.one("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not job:
        raise HTTPException(404, "job not found")
    history = db.all("SELECT * FROM job_history WHERE job_id=? ORDER BY id ASC", (job_id,))
    res = job_json(job)
    res["history"] = [dict(h) for h in history]
    return res

@app.get("/api/maintenance-windows")
async def list_maintenance_windows(_: sqlite3.Row = Depends(permission("policies.read"))):
    rows = db.all("SELECT * FROM maintenance_windows ORDER BY starts_at DESC")
    return [dict(r) for r in rows]

@app.post("/api/maintenance-windows")
async def create_maintenance_window(payload: MaintenanceWindowPayload, s: sqlite3.Row = Depends(permission("policies.write")), _: sqlite3.Row = Depends(csrf)):
    mw_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO maintenance_windows(id,name,starts_at,ends_at,enabled,created_by,schedule_type,recurrence_rule,timezone,is_blackout) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (mw_id, payload.name, payload.starts_at, payload.ends_at, int(payload.enabled), s["user_id"], payload.schedule_type, payload.recurrence_rule, payload.timezone, int(payload.is_blackout))
    )
    audit(s["username"], "maintenance.create", mw_id, detail={"name": payload.name, "is_blackout": payload.is_blackout})
    return {"id": mw_id, "name": payload.name}

@app.delete("/api/maintenance-windows/{mw_id}")
async def delete_maintenance_window(mw_id: str, s: sqlite3.Row = Depends(permission("policies.write")), _: sqlite3.Row = Depends(csrf)):
    if not db.one("SELECT id FROM maintenance_windows WHERE id=?", (mw_id,)):
        raise HTTPException(404, "maintenance window not found")
    db.execute("DELETE FROM maintenance_windows WHERE id=?", (mw_id,))
    audit(s["username"], "maintenance.delete", mw_id)
    return {"ok": True}

@app.get("/api/approvals")
async def approvals(_: sqlite3.Row = Depends(role("admin","operator"))):
    rows = db.all("SELECT a.*,j.action,j.server_id,j.status job_status FROM approvals a JOIN jobs j ON j.id=a.job_id WHERE a.status='pending' ORDER BY a.created_at")
    return [dict(r) for r in rows]

@app.post("/api/approvals/{approval_id}/approve")
async def approve(approval_id: int, s: sqlite3.Row = Depends(permission("approvals.approve")), _: sqlite3.Row = Depends(csrf)):
    row = db.one("SELECT * FROM approvals WHERE id=? AND status='pending'", (approval_id,))
    if not row:
        raise HTTPException(404, "approval not found")
    if row["requested_by"] == s["user_id"]:
        raise HTTPException(403, "separation of duties: requester cannot approve their own change request")
    now = utcnow().isoformat()
    db.execute("UPDATE approvals SET status='approved',approved_by=?,decided_at=? WHERE id=?", (s["user_id"], now, approval_id))
    db.execute("UPDATE jobs SET requires_approval=0,approved_by=? WHERE id=?", (s["user_id"], row["job_id"]))
    audit(s["username"], "approval.approve", row["job_id"])
    return {"ok": True}

@app.get("/api/vulnerabilities/cves")
async def list_cves(q: str | None = None, _: sqlite3.Row = Depends(permission("vulnerabilities.read"))):
    if q:
        rows = db.all("SELECT * FROM cve_database WHERE cve_id LIKE ? OR title LIKE ? ORDER BY cvss_score DESC", (f"%{q}%", f"%{q}%"))
    else:
        rows = db.all("SELECT * FROM cve_database ORDER BY cvss_score DESC LIMIT 100")
    return [{"cve_id": r["cve_id"], "title": r["title"], "severity": r["severity"], "cvss_score": r["cvss_score"], "affected_packages": db.obj(r["affected_packages"]), "description": r["description"], "published_at": r["published_at"]} for r in rows]

@app.post("/api/vulnerabilities/cves")
async def ingest_cve(payload: CVEIngestPayload, s: sqlite3.Row = Depends(permission("compliance.manage")), _: sqlite3.Row = Depends(csrf)):
    pub = payload.published_at or utcnow().isoformat()
    db.execute(
        "INSERT INTO cve_database(cve_id, title, severity, cvss_score, affected_packages, description, published_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(cve_id) DO UPDATE SET title=excluded.title, severity=excluded.severity, cvss_score=excluded.cvss_score, affected_packages=excluded.affected_packages, description=excluded.description",
        (payload.cve_id, payload.title, payload.severity, payload.cvss_score, json.dumps(payload.affected_packages), payload.description, pub)
    )
    audit(s["username"], "cve.ingest", payload.cve_id, detail={"severity": payload.severity, "cvss_score": payload.cvss_score})
    return {"cve_id": payload.cve_id, "title": payload.title}

@app.post("/api/vulnerabilities/scan/{server_id}")
async def scan_server_vulnerabilities(server_id: str, s: sqlite3.Row = Depends(permission("compliance.manage")), _: sqlite3.Row = Depends(csrf)):
    srv = db.one("SELECT * FROM servers WHERE id=?", (server_id,))
    if not srv:
        raise HTTPException(404, "server not found")

    inv = db.obj(srv["inventory"])
    pkgs = inv.get("packages", {}) if isinstance(inv, dict) else {}
    cves = db.all("SELECT * FROM cve_database")
    now = utcnow().isoformat()
    vuln_count = 0

    for cve in cves:
        aff_list = db.obj(cve["affected_packages"])
        if isinstance(aff_list, list):
            for aff in aff_list:
                pkg_name = aff.get("package")
                fixed_ver = aff.get("fixed_version", "0.0.0")
                if pkg_name in pkgs:
                    inst_ver = pkgs[pkg_name]
                    if inst_ver != fixed_ver:
                        vid = str(uuid.uuid4())
                        db.execute(
                            "INSERT INTO vulnerabilities(id, server_id, cve_id, package_name, installed_version, fixed_version, severity, status, first_seen, last_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (vid, server_id, cve["cve_id"], pkg_name, str(inst_ver), fixed_ver, cve["severity"], "vulnerable", now, now)
                        )
                        vuln_count += 1

    audit(s["username"], "vulnerability.scan", server_id, detail={"vulnerabilities_found": vuln_count})
    return {"server_id": server_id, "vulnerabilities_found": vuln_count, "scanned_at": now}

@app.get("/api/vulnerabilities/servers/{server_id}")
async def server_vulnerabilities(server_id: str, _: sqlite3.Row = Depends(permission("vulnerabilities.read"))):
    rows = db.all("SELECT v.*, c.title, c.cvss_score FROM vulnerabilities v JOIN cve_database c ON c.cve_id=v.cve_id WHERE v.server_id=? ORDER BY c.cvss_score DESC", (server_id,))
    return [dict(r) for r in rows]

@app.get("/api/policies")
async def list_policies(_: sqlite3.Row = Depends(permission("policies.read"))):
    rows = db.all("SELECT * FROM configuration_policies ORDER BY created_at DESC")
    return [{"id": r["id"], "name": r["name"], "kind": r["kind"], "target_scope": r["target_scope"], "definition": db.obj(r["definition"]), "remediation_behavior": r["remediation_behavior"], "enabled": bool(r["enabled"]), "version": r["version"], "created_at": r["created_at"]} for r in rows]

@app.post("/api/policies")
async def create_policy(payload: ConfigPolicyPayload, s: sqlite3.Row = Depends(permission("policies.write")), _: sqlite3.Row = Depends(csrf)):
    pid = str(uuid.uuid4())
    now = utcnow().isoformat()
    db.execute(
        "INSERT INTO configuration_policies(id, name, kind, target_scope, definition, remediation_behavior, enabled, created_by, version, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (pid, payload.name, payload.kind, payload.target_scope, json.dumps(payload.definition), payload.remediation_behavior, int(payload.enabled), s["username"], 1, now)
    )
    audit(s["username"], "policy.create", pid, detail={"name": payload.name, "kind": payload.kind})
    return {"id": pid, "name": payload.name}

@app.post("/api/policies/{policy_id}/evaluate/{server_id}")
async def evaluate_policy_drift(policy_id: str, server_id: str, s: sqlite3.Row = Depends(permission("policies.write")), _: sqlite3.Row = Depends(csrf)):
    pol = db.one("SELECT * FROM configuration_policies WHERE id=?", (policy_id,))
    srv = db.one("SELECT * FROM servers WHERE id=?", (server_id,))
    if not pol or not srv:
        raise HTTPException(404, "policy or server not found")

    defn = db.obj(pol["definition"])
    posture_data = db.obj(srv["posture"])
    now = utcnow().isoformat()

    status_str = "compliant"
    diff_str = "No drift detected."

    if pol["kind"] == "service":
        target_service = defn.get("service_name")
        expected_state = defn.get("desired_state", "running")
        observed_state = posture_data.get("services", {}).get(target_service, "unknown")
        if observed_state != expected_state:
            status_str = "drifted"
            diff_str = f"Service '{target_service}' state is '{observed_state}', expected '{expected_state}'"
    elif pol["kind"] == "firewall":
        expected_fw = defn.get("enabled", True)
        observed_fw = posture_data.get("firewall", False)
        if observed_fw != expected_fw:
            status_str = "drifted"
            diff_str = f"Firewall state is {observed_fw}, expected {expected_fw}"

    drec_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO drift_records(id, server_id, policy_id, resource_type, status, desired_state, observed_state, difference, last_evaluated) VALUES(?,?,?,?,?,?,?,?,?)",
        (drec_id, server_id, policy_id, pol["kind"], status_str, json.dumps(defn), json.dumps(posture_data), diff_str, now)
    )
    audit(s["username"], "policy.evaluate", policy_id, detail={"server_id": server_id, "status": status_str})
    return {"id": drec_id, "status": status_str, "difference": diff_str, "last_evaluated": now}

@app.get("/api/policies/drift")
async def list_drift_records(_: sqlite3.Row = Depends(permission("policies.read"))):
    rows = db.all("SELECT d.*, s.name server_name, p.name policy_name FROM drift_records d JOIN servers s ON s.id=d.server_id JOIN configuration_policies p ON p.id=d.policy_id ORDER BY d.last_evaluated DESC LIMIT 100")
    return [dict(r) for r in rows]

@app.get("/api/compliance/baselines")
async def list_compliance_baselines(_: sqlite3.Row = Depends(permission("compliance.read"))):
    rows = db.all("SELECT * FROM compliance_baselines ORDER BY name")
    return [{"id": r["id"], "name": r["name"], "framework": r["framework"], "description": r["description"], "rules": db.obj(r["rules"]), "enabled": bool(r["enabled"]), "created_at": r["created_at"]} for r in rows]

@app.post("/api/compliance/baselines")
async def create_compliance_baseline(payload: ComplianceBaselinePayload, s: sqlite3.Row = Depends(permission("compliance.manage")), _: sqlite3.Row = Depends(csrf)):
    bid = str(uuid.uuid4())
    now = utcnow().isoformat()
    db.execute(
        "INSERT INTO compliance_baselines(id, name, framework, description, rules, enabled, created_at) VALUES(?,?,?,?,?,?,?)",
        (bid, payload.name, payload.framework, payload.description, json.dumps(payload.rules), 1, now)
    )
    audit(s["username"], "compliance.baseline_create", bid, detail={"name": payload.name, "framework": payload.framework})
    return {"id": bid, "name": payload.name}

@app.post("/api/compliance/scan/{server_id}")
async def run_compliance_scan(server_id: str, baseline_id: str, s: sqlite3.Row = Depends(permission("compliance.manage")), _: sqlite3.Row = Depends(csrf)):
    srv = db.one("SELECT * FROM servers WHERE id=?", (server_id,))
    base = db.one("SELECT * FROM compliance_baselines WHERE id=?", (baseline_id,))
    if not srv or not base:
        raise HTTPException(404, "server or baseline not found")

    rules = db.obj(base["rules"])
    posture_data = db.obj(srv["posture"])
    now = utcnow().isoformat()

    passed, total = 0, len(rules) if isinstance(rules, list) else 0
    rule_results = []

    if isinstance(rules, list):
        for r in rules:
            r_name = r.get("rule", "unknown")
            if r_name == "require_firewall":
                ok = posture_data.get("firewall") is True
                passed += 1 if ok else 0
                rule_results.append({"rule": r_name, "status": "passed" if ok else "failed"})
            elif r_name == "non_root_execution":
                ok = posture_data.get("admin_user") is False
                passed += 1 if ok else 0
                rule_results.append({"rule": r_name, "status": "passed" if ok else "failed"})
            else:
                rule_results.append({"rule": r_name, "status": "not_evaluable", "reason": "No automated scanner for this control"})

    score = (passed / max(total, 1)) * 100.0
    cres_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO compliance_results(id, server_id, baseline_id, score, status, evidence, evaluated_at) VALUES(?,?,?,?,?,?,?)",
        (cres_id, server_id, baseline_id, score, "passed" if score >= 80.0 else "non_compliant", json.dumps(rule_results), now)
    )
    audit(s["username"], "compliance.scan", server_id, detail={"baseline_id": baseline_id, "score": score})
    return {"id": cres_id, "score": score, "status": "passed" if score >= 80.0 else "non_compliant", "evaluated_at": now}

@app.get("/api/compliance/reports")
async def list_compliance_reports(_: sqlite3.Row = Depends(permission("compliance.read"))):
    rows = db.all("SELECT c.*, s.name server_name, b.name baseline_name, b.framework FROM compliance_results c JOIN servers s ON s.id=c.server_id JOIN compliance_baselines b ON b.id=c.baseline_id ORDER BY c.evaluated_at DESC LIMIT 100")
    return [dict(r) for r in rows]

@app.get("/api/rollouts/rings")
async def list_rollout_rings(_: sqlite3.Row = Depends(session)):
    rows = db.all("SELECT * FROM rollout_rings ORDER BY ring_order ASC")
    return [{"id": r["id"], "name": r["name"], "ring_order": r["ring_order"], "target_group": r["target_group"], "max_concurrency": r["max_concurrency"], "failure_threshold_pct": r["failure_threshold_pct"], "auto_promote": bool(r["auto_promote"]), "created_at": r["created_at"]} for r in rows]

@app.post("/api/rollouts/rings")
async def create_rollout_ring(payload: RolloutRingPayload, s: sqlite3.Row = Depends(permission("rollouts.manage")), _: sqlite3.Row = Depends(csrf)):
    rid = str(uuid.uuid4())
    now = utcnow().isoformat()
    db.execute(
        "INSERT INTO rollout_rings(id, name, ring_order, target_group, max_concurrency, failure_threshold_pct, auto_promote, created_at) VALUES(?,?,?,?,?,?,?,?)",
        (rid, payload.name, payload.ring_order, payload.target_group, payload.max_concurrency, payload.failure_threshold_pct, int(payload.auto_promote), now)
    )
    audit(s["username"], "rollout.ring_create", rid, detail={"name": payload.name, "ring_order": payload.ring_order})
    return {"id": rid, "name": payload.name}

@app.post("/api/rollouts/promote/{ring_id}")
async def promote_rollout_ring(ring_id: str, s: sqlite3.Row = Depends(permission("rollouts.manage")), _: sqlite3.Row = Depends(csrf)):
    ring = db.one("SELECT * FROM rollout_rings WHERE id=?", (ring_id,))
    if not ring:
        raise HTTPException(404, "rollout ring not found")
    next_ring = db.one("SELECT * FROM rollout_rings WHERE ring_order > ? ORDER BY ring_order ASC LIMIT 1", (ring["ring_order"],))
    audit(s["username"], "rollout.promote", ring_id, detail={"next_ring_id": next_ring["id"] if next_ring else None})
    return {"promoted_ring_id": ring_id, "next_ring": next_ring["name"] if next_ring else "complete"}

@app.post("/api/rollouts/rollback/{ring_id}")
async def rollback_rollout_ring(ring_id: str, s: sqlite3.Row = Depends(permission("rollouts.manage")), _: sqlite3.Row = Depends(csrf)):
    ring = db.one("SELECT * FROM rollout_rings WHERE id=?", (ring_id,))
    if not ring:
        raise HTTPException(404, "rollout ring not found")
    audit(s["username"], "rollout.rollback", ring_id)
    return {"status": "rolled_back", "ring_id": ring_id}

@app.get("/api/hardware/bmc")
async def list_bmc_nodes(_: sqlite3.Row = Depends(permission("hardware.read"))):
    rows = db.all("SELECT id, server_id, name, address, bmc_type, username, power_state, health_status, created_at FROM bmc_nodes ORDER BY name")
    return [dict(r) for r in rows]

@app.post("/api/hardware/bmc")
async def register_bmc_node(payload: BMCRegisterPayload, s: sqlite3.Row = Depends(permission("hardware.manage")), _: sqlite3.Row = Depends(csrf)):
    bmc_id = str(uuid.uuid4())
    enc_pass = encrypt_secret(payload.password)
    now = utcnow().isoformat()
    db.execute(
        "INSERT INTO bmc_nodes(id, server_id, name, address, bmc_type, username, encrypted_password, power_state, health_status, created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (bmc_id, payload.server_id, payload.name, payload.address, payload.bmc_type, payload.username, enc_pass, "unknown", "unknown", now)
    )
    audit(s["username"], "bmc.register", bmc_id, detail={"name": payload.name, "address": payload.address})
    return {"id": bmc_id, "name": payload.name}

@app.delete("/api/hardware/bmc/{bmc_id}")
async def delete_bmc_node(bmc_id: str, s: sqlite3.Row = Depends(permission("hardware.manage")), _: sqlite3.Row = Depends(csrf)):
    if not db.one("SELECT id FROM bmc_nodes WHERE id=?", (bmc_id,)):
        raise HTTPException(404, "bmc node not found")
    db.execute("DELETE FROM bmc_nodes WHERE id=?", (bmc_id,))
    audit(s["username"], "bmc.delete", bmc_id)
    return {"ok": True}

@app.post("/api/hardware/bmc/{bmc_id}/power")
async def bmc_power_action(bmc_id: str, payload: BMCPowerPayload, s: sqlite3.Row = Depends(permission("power.manage")), _: sqlite3.Row = Depends(csrf)):
    node = db.one("SELECT * FROM bmc_nodes WHERE id=?", (bmc_id,))
    if not node:
        raise HTTPException(404, "bmc node not found")

    decrypted_pass = decrypt_secret(node["encrypted_password"])
    if not decrypted_pass:
        raise HTTPException(500, "failed to decrypt bmc credentials")

    import urllib.request
    import urllib.error
    import base64

    redfish_url = f"https://{node['address']}/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"
    req_body = json.dumps({"ResetType": payload.action.title()}).encode("utf-8")
    req = urllib.request.Request(redfish_url, data=req_body, method="POST", headers={"Content-Type": "application/json"})

    auth_str = base64.b64encode(f"{node['username']}:{decrypted_pass}".encode("utf-8")).decode("utf-8")
    req.add_header("Authorization", f"Basic {auth_str}")

    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            new_power = "On" if payload.action in ("on", "graceful_restart", "hard_reset") else "Off"
            db.execute("UPDATE bmc_nodes SET power_state=? WHERE id=?", (new_power, bmc_id))
            audit(s["username"], "bmc.power", bmc_id, detail={"action": payload.action, "status": "success"})
            return {"status": "success", "power_state": new_power, "action": payload.action}
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        audit(s["username"], "bmc.power", bmc_id, result="unreachable", detail={"action": payload.action, "error": str(exc)})
        return JSONResponse(status_code=502, content={"status": "unreachable", "action": payload.action, "unsupported_reason": f"BMC at {node['address']} is unreachable or returned error: {exc!s}"})

@app.get("/api/hardware/bmc/{bmc_id}/inventory")
async def bmc_inventory(bmc_id: str, _: sqlite3.Row = Depends(permission("hardware.read"))):
    node = db.one("SELECT id, name, address, bmc_type, username, power_state, health_status FROM bmc_nodes WHERE id=?", (bmc_id,))
    if not node:
        raise HTTPException(404, "bmc node not found")
    return {
        "bmc_id": node["id"],
        "name": node["name"],
        "address": node["address"],
        "bmc_type": node["bmc_type"],
        "power_state": node["power_state"],
        "health_status": node["health_status"],
        "sensors": {"temperature_celsius": 24.5, "fan_rpm": 3200, "power_watts": 180}
    }

@app.get("/api/provisioning/profiles")
async def list_provisioning_profiles(_: sqlite3.Row = Depends(permission("provisioning.read"))):
    rows = db.all("SELECT * FROM provisioning_profiles ORDER BY name")
    return [{"id": r["id"], "name": r["name"], "os_family": r["os_family"], "image_url": r["image_url"], "partition_layout": db.obj(r["partition_layout"]), "post_install_script": r["post_install_script"], "network_config": db.obj(r["network_config"]), "created_at": r["created_at"]} for r in rows]

@app.post("/api/provisioning/profiles")
async def create_provisioning_profile(payload: ProvisioningProfilePayload, s: sqlite3.Row = Depends(permission("provisioning.manage")), _: sqlite3.Row = Depends(csrf)):
    pid = str(uuid.uuid4())
    now = utcnow().isoformat()
    db.execute(
        "INSERT INTO provisioning_profiles(id, name, os_family, image_url, partition_layout, post_install_script, network_config, created_at) VALUES(?,?,?,?,?,?,?,?)",
        (pid, payload.name, payload.os_family, payload.image_url, json.dumps(payload.partition_layout), payload.post_install_script, json.dumps(payload.network_config), now)
    )
    audit(s["username"], "provisioning.profile_create", pid, detail={"name": payload.name, "os_family": payload.os_family})
    return {"id": pid, "name": payload.name}

@app.get("/api/provisioning/jobs")
async def list_provisioning_jobs(_: sqlite3.Row = Depends(permission("provisioning.read"))):
    rows = db.all("SELECT j.*, p.name profile_name FROM provisioning_jobs j JOIN provisioning_profiles p ON p.id=j.profile_id ORDER BY j.created_at DESC")
    return [dict(r) for r in rows]

@app.post("/api/provisioning/jobs")
async def create_provisioning_job(payload: ProvisioningJobPayload, s: sqlite3.Row = Depends(permission("provisioning.manage")), _: sqlite3.Row = Depends(csrf)):
    if not payload.confirm_destructive:
        raise HTTPException(400, "destructive operation confirmation required for bare-metal OS provisioning")
    profile = db.one("SELECT id FROM provisioning_profiles WHERE id=?", (payload.profile_id,))
    if not profile:
        raise HTTPException(404, "provisioning profile not found")

    pjob_id = str(uuid.uuid4())
    now = utcnow().isoformat()
    db.execute(
        "INSERT INTO provisioning_jobs(id, profile_id, mac_address, target_hostname, status, progress, log, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (pjob_id, payload.profile_id, payload.mac_address, payload.target_hostname, "provisioning_queued", 0, "Provisioning job initialized", now, now)
    )
    audit(s["username"], "provisioning.job_create", pjob_id, detail={"mac_address": payload.mac_address, "target_hostname": payload.target_hostname})
    return {"id": pjob_id, "status": "provisioning_queued", "target_hostname": payload.target_hostname}

@app.post("/api/agent/register")
async def register(payload: Register):
    row = db.one("SELECT * FROM enrollment_tokens WHERE token_hash=?", (hash_token(payload.enrollment_token),))
    if not row or row["used_at"] or row["expires_at"] <= utcnow().isoformat():
        raise HTTPException(401, "invalid or expired enrollment token")
    sid, key = str(uuid.uuid4()), random_token()
    now = utcnow().isoformat()
    db.execute("UPDATE enrollment_tokens SET used_at=? WHERE token_hash=?", (now, row["token_hash"]))
    db.execute("INSERT INTO servers(id,name,hostname,platform,arch,os_version,status,last_seen,agent_key_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)", (sid, payload.name, payload.hostname, payload.platform, payload.arch, payload.os_version, "online", now, hash_token(key), now))
    audit("agent", "server.register", sid, detail={"hostname": payload.hostname, "platform": payload.platform})
    return {"server_id": sid, "agent_key": key, "heartbeat_seconds": 15}

@app.post("/api/agent/heartbeat")
async def heartbeat(payload: Heartbeat, r: sqlite3.Row = Depends(agent)):
    now = utcnow().isoformat()
    db.execute("UPDATE servers SET hostname=?,platform=?,arch=?,os_version=?,status='online',last_seen=?,cpu=?,memory=?,disk=?,uptime=?,inventory=?,posture=? WHERE id=?", (payload.hostname, payload.platform, payload.arch, payload.os_version, now, payload.cpu, payload.memory, payload.disk, payload.uptime, json.dumps(payload.inventory, separators=(",", ":")), json.dumps(payload.posture, separators=(",", ":")), r["id"]))
    return {"ok": True}

@app.post("/api/agent/jobs/poll")
async def poll(r: sqlite3.Row = Depends(agent)):
    now = utcnow()
    now_iso = now.isoformat()

    running_jobs = db.all("SELECT * FROM jobs WHERE server_id=? AND status='running'", (r["id"],))
    for rjob in running_jobs:
        if rjob["started_at"]:
            try:
                started = datetime.fromisoformat(rjob["started_at"])
                timeout = rjob.get("timeout_seconds") or 3600
                if (now - started).total_seconds() > timeout:
                    db.execute("UPDATE jobs SET status='failed', result=?, finished_at=? WHERE id=?", (json.dumps({"error": "job execution timeout exceeded"}), now_iso, rjob["id"]))
                    log_job_history(rjob["id"], "failed", "Execution timeout exceeded")
            except ValueError:
                pass

    if db.one("SELECT id FROM jobs WHERE server_id=? AND status='running' LIMIT 1", (r["id"],)):
        return {"job": None}

    candidates = db.all(
        "SELECT * FROM jobs WHERE server_id=? AND status IN ('queued', 'scheduled', 'waiting_maintenance_window', 'retrying') AND requires_approval=0 ORDER BY priority DESC, created_at ASC",
        (r["id"],)
    )

    for cand in candidates:
        if cand["scheduled_at"] and cand["scheduled_at"] > now_iso:
            if cand["status"] != "scheduled":
                db.execute("UPDATE jobs SET status='scheduled' WHERE id=?", (cand["id"],))
            continue

        requires_mw = cand["action"] in HIGH_IMPACT or cand["action"] == "apply_security_patches"
        if requires_mw and not is_in_maintenance_window(r["id"]):
            if cand["status"] != "waiting_maintenance_window":
                db.execute("UPDATE jobs SET status='waiting_maintenance_window' WHERE id=?", (cand["id"],))
                log_job_history(cand["id"], "waiting_maintenance_window", "Waiting for active maintenance window")
            continue

        db.execute("UPDATE jobs SET status='running', started_at=? WHERE id=?", (now_iso, cand["id"]))
        log_job_history(cand["id"], "running", f"Dispatched to agent on host {r['hostname']}")
        return {"job": {"id": cand["id"], "action": cand["action"], "params": db.obj(cand["params"])}}

    return {"job": None}

@app.post("/api/agent/jobs/{job_id}/report")
async def report(job_id: str, payload: JobReport, r: sqlite3.Row = Depends(agent)):
    job = db.one("SELECT * FROM jobs WHERE id=? AND server_id=?", (job_id, r["id"]))
    if not job:
        raise HTTPException(404, "job not found")

    now = utcnow()
    now_iso = now.isoformat()

    if payload.status == "failed" and job["retries"] < job["max_retries"]:
        next_retries = job["retries"] + 1
        backoff_seconds = (2 ** next_retries) * 5
        retry_at = (now + timedelta(seconds=backoff_seconds)).isoformat()
        db.execute(
            "UPDATE jobs SET status='retrying', retries=?, scheduled_at=?, result=? WHERE id=?",
            (next_retries, retry_at, json.dumps(payload.result, separators=(",", ":")), job_id)
        )
        log_job_history(job_id, "retrying", f"Failed attempt {next_retries}/{job['max_retries']}. Retrying in {backoff_seconds}s")
        audit("agent", "job.retry", r["id"], detail={"job_id": job_id, "action": job["action"], "retry": next_retries})
        return {"ok": True, "retrying": True}

    db.execute("UPDATE jobs SET status=?, result=?, finished_at=? WHERE id=?", (payload.status, json.dumps(payload.result, separators=(",", ":")), now_iso, job_id))
    log_job_history(job_id, payload.status, f"Completed with status {payload.status}")
    audit("agent", f"job.{payload.status}", r["id"], detail={"job_id": job_id, "action": job["action"]})
    return {"ok": True}

@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    print(f"Unhandled error: {exc!r}")
    return JSONResponse(status_code=500, content={"detail": "internal server error"})

from __future__ import annotations

import json
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from fastapi import Cookie, Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .config import settings
from .db import Database
from .security import hash_secret, hash_token, random_token, utcnow, verify_secret

ROOT = Path(__file__).resolve().parent
app = FastAPI(title="Glowhaven Meridian", version="0.1.0", docs_url="/api/docs", redoc_url=None)
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
db = Database(settings.db_path)
SESSION_COOKIE = "meridian_session"
CSRF_COOKIE = "meridian_csrf"
SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,128}$")
ALLOWED_ACTIONS = {"refresh_inventory", "collect_diagnostics", "service_start", "service_stop", "service_restart", "reboot", "shutdown", "assess_patches", "apply_security_patches"}
HIGH_IMPACT = {"shutdown", "reboot", "apply_security_patches"}


def audit(actor: str, action: str, target: str, result: str = "success", detail: dict[str, Any] | None = None) -> None:
    db.execute("INSERT INTO audit_log(actor,action,target,result,detail,created_at) VALUES(?,?,?,?,?,?)", (actor, action, target, result, json.dumps(detail or {}, separators=(",", ":")), utcnow().isoformat()))


def bootstrap() -> None:
    if db.one("SELECT id FROM users LIMIT 1"):
        return
    password = settings.bootstrap_password or random_token()
    db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (settings.bootstrap_admin, hash_secret(password), "admin", utcnow().isoformat()))
    if not settings.bootstrap_password:
        print(f"Meridian bootstrap password: {password}")

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

class JobRequest(BaseModel):
    action: str = Field(min_length=1, max_length=64)
    params: dict[str, Any] = Field(default_factory=dict)
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


def csrf(s: sqlite3.Row = Depends(session), token_header: str | None = Header(None, alias="X-CSRF-Token"), token_cookie: str | None = Cookie(None, alias=CSRF_COOKIE)) -> sqlite3.Row:
    if not token_header or not token_cookie or not secrets.compare_digest(token_header, token_cookie) or not secrets.compare_digest(token_header, s["csrf"]):
        raise HTTPException(403, "csrf validation failed")
    return s


def agent(agent_key: str | None = Header(None, alias="X-Meridian-Agent-Key")) -> sqlite3.Row:
    if not agent_key:
        raise HTTPException(401, "agent key required")
    row = db.one("SELECT * FROM servers WHERE agent_key_hash=?", (hash_token(agent_key),))
    if not row:
        raise HTTPException(401, "invalid agent key")
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
    return {"id":row["id"],"name":row["name"],"hostname":row["hostname"],"platform":row["platform"],"arch":row["arch"],"os_version":row["os_version"],"status":status(row),"last_seen":row["last_seen"],"cpu":row["cpu"],"memory":row["memory"],"disk":row["disk"],"uptime":row["uptime"],"inventory":db.obj(row["inventory"]),"posture":db.obj(row["posture"]),"created_at":row["created_at"]}


def job_json(row: sqlite3.Row) -> dict[str, Any]:
    return {"id":row["id"],"server_id":row["server_id"],"action":row["action"],"params":db.obj(row["params"]),"status":row["status"],"requires_approval":bool(row["requires_approval"]),"approved_by":row["approved_by"],"result":db.obj(row["result"]),"created_at":row["created_at"],"started_at":row["started_at"],"finished_at":row["finished_at"]}


def in_maintenance() -> bool:
    now = utcnow().isoformat()
    row = db.one("SELECT id FROM maintenance_windows WHERE enabled=1 AND starts_at<=? AND ends_at>=? LIMIT 1", (now, now))
    return bool(row)


def validate_params(action: str, params: dict[str, Any]) -> dict[str, Any]:
    if action.startswith("service_"):
        service = params.get("service")
        if not isinstance(service, str) or not SERVICE_RE.fullmatch(service):
            raise HTTPException(422, "invalid service name")
        return {"service": service}
    if params:
        raise HTTPException(422, "action accepts no parameters")
    return {}


@app.get("/")
async def home():
    return FileResponse(ROOT / "static" / "index.html")

@app.get("/healthz")
async def healthz():
    return {"status":"ok","service":"glowhaven-meridian"}

@app.post("/api/auth/login")
async def login(payload: Login, response: Response):
    row = db.one("SELECT * FROM users WHERE username=?", (payload.username.strip(),))
    if not row or not verify_secret(payload.password, row["password_hash"]):
        raise HTTPException(401, "invalid credentials")
    sid, ctoken = random_token(), random_token()
    expires = utcnow() + timedelta(hours=settings.session_hours)
    db.execute("INSERT INTO sessions(id,user_id,csrf,expires_at) VALUES(?,?,?,?)", (sid,row["id"],ctoken,expires.isoformat()))
    response.set_cookie(SESSION_COOKIE,sid,secure=settings.secure_cookies,httponly=True,samesite="strict",max_age=settings.session_hours*3600)
    response.set_cookie(CSRF_COOKIE,ctoken,secure=settings.secure_cookies,httponly=False,samesite="strict",max_age=3600)
    audit(row["username"],"auth.login","session")
    return {"username":row["username"],"role":row["role"]}

@app.post("/api/auth/logout")
async def logout(response: Response, s: sqlite3.Row = Depends(csrf)):
    db.execute("DELETE FROM sessions WHERE id=?",(s["id"],))
    response.delete_cookie(SESSION_COOKIE); response.delete_cookie(CSRF_COOKIE)
    audit(s["username"],"auth.logout","session")
    return {"ok":True}

@app.get("/api/csrf")
async def get_csrf(response: Response, s: sqlite3.Row = Depends(session)):
    response.set_cookie(CSRF_COOKIE,s["csrf"],secure=settings.secure_cookies,httponly=False,samesite="strict",max_age=3600)
    return {"csrf_token":s["csrf"]}

@app.get("/api/me")
async def me(s: sqlite3.Row = Depends(session)): return {"username":s["username"],"role":s["role"]}

@app.get("/api/summary")
async def summary(_: sqlite3.Row = Depends(session)):
    rows=db.all("SELECT * FROM servers")
    st=[status(r) for r in rows]
    queued=db.one("SELECT COUNT(*) c FROM jobs WHERE status='queued'")["c"]
    pending=db.one("SELECT COUNT(*) c FROM approvals WHERE status='pending'")["c"]
    failed=db.one("SELECT COUNT(*) c FROM jobs WHERE status='failed' AND created_at>=?",((utcnow()-timedelta(hours=24)).isoformat(),))["c"]
    return {"servers":len(rows),"online":st.count("online"),"warning":st.count("warning"),"queued":queued,"pending_approvals":pending,"failed_24h":failed,"maintenance_window":in_maintenance()}

@app.get("/api/servers")
async def servers(_: sqlite3.Row = Depends(session)):
    return [server_json(r) for r in db.all("SELECT * FROM servers ORDER BY name COLLATE NOCASE")]

@app.get("/api/jobs")
async def jobs(_: sqlite3.Row = Depends(session)):
    return [job_json(r) for r in db.all("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 250")]

@app.get("/api/audit")
async def audit_log(_: sqlite3.Row = Depends(role("admin"))):
    rows=db.all("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300")
    return [{"id":r["id"],"actor":r["actor"],"action":r["action"],"target":r["target"],"result":r["result"],"detail":db.obj(r["detail"]),"created_at":r["created_at"]} for r in rows]

@app.post("/api/enrollment-tokens")
async def enrollment(s: sqlite3.Row = Depends(role("admin")), _: sqlite3.Row = Depends(csrf)):
    raw=random_token(); expires=utcnow()+timedelta(minutes=settings.enrollment_minutes)
    db.execute("INSERT INTO enrollment_tokens(token_hash,created_by,expires_at) VALUES(?,?,?)",(hash_token(raw),s["user_id"],expires.isoformat()))
    audit(s["username"],"enrollment.create","fleet",detail={"expires_at":expires.isoformat()})
    return {"token":raw,"expires_at":expires.isoformat()}

@app.post("/api/servers/{server_id}/jobs")
async def create_job(server_id: str, payload: JobRequest, s: sqlite3.Row = Depends(role("admin","operator")), _: sqlite3.Row = Depends(csrf)):
    if not db.one("SELECT id FROM servers WHERE id=?",(server_id,)): raise HTTPException(404,"server not found")
    params=validate_params(payload.action,payload.params)
    needs=payload.action in HIGH_IMPACT or (payload.action=="apply_security_patches")
    if needs and not in_maintenance():
        needs=True
    jid=str(uuid.uuid4()); now=utcnow().isoformat()
    db.execute("INSERT INTO jobs(id,server_id,action,params,requested_by,status,requires_approval,result,created_at) VALUES(?,?,?,?,?,?,?,?,?)",(jid,server_id,payload.action,json.dumps(params),s["user_id"],"queued",int(needs),"{}",now))
    if needs: db.execute("INSERT INTO approvals(job_id,requested_by,created_at) VALUES(?,?,?)",(jid,s["user_id"],now))
    audit(s["username"],"job.create",server_id,detail={"job_id":jid,"action":payload.action,"requires_approval":needs})
    return {"id":jid,"status":"queued","requires_approval":needs}

@app.get("/api/approvals")
async def approvals(_: sqlite3.Row = Depends(role("admin","operator"))):
    rows=db.all("SELECT a.*,j.action,j.server_id,j.status job_status FROM approvals a JOIN jobs j ON j.id=a.job_id WHERE a.status='pending' ORDER BY a.created_at")
    return [dict(r) for r in rows]

@app.post("/api/approvals/{approval_id}/approve")
async def approve(approval_id: int, s: sqlite3.Row = Depends(role("admin")), _: sqlite3.Row = Depends(csrf)):
    row=db.one("SELECT * FROM approvals WHERE id=? AND status='pending'",(approval_id,))
    if not row: raise HTTPException(404,"approval not found")
    now=utcnow().isoformat(); db.execute("UPDATE approvals SET status='approved',approved_by=?,decided_at=? WHERE id=?",(s["user_id"],now,approval_id)); db.execute("UPDATE jobs SET requires_approval=0,approved_by=? WHERE id=?",(s["user_id"],row["job_id"]))
    audit(s["username"],"approval.approve",row["job_id"]); return {"ok":True}

@app.post("/api/agent/register")
async def register(payload: Register):
    row=db.one("SELECT * FROM enrollment_tokens WHERE token_hash=?",(hash_token(payload.enrollment_token),))
    if not row or row["used_at"] or row["expires_at"]<=utcnow().isoformat(): raise HTTPException(401,"invalid or expired enrollment token")
    sid,key=str(uuid.uuid4()),random_token(); now=utcnow().isoformat()
    db.execute("UPDATE enrollment_tokens SET used_at=? WHERE token_hash=?",(now,row["token_hash"]))
    db.execute("INSERT INTO servers(id,name,hostname,platform,arch,os_version,status,last_seen,agent_key_hash,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",(sid,payload.name,payload.hostname,payload.platform,payload.arch,payload.os_version,"online",now,hash_token(key),now))
    audit("agent","server.register",sid,detail={"hostname":payload.hostname,"platform":payload.platform})
    return {"server_id":sid,"agent_key":key,"heartbeat_seconds":15}

@app.post("/api/agent/heartbeat")
async def heartbeat(payload: Heartbeat, r: sqlite3.Row = Depends(agent)):
    now=utcnow().isoformat(); db.execute("UPDATE servers SET hostname=?,platform=?,arch=?,os_version=?,status='online',last_seen=?,cpu=?,memory=?,disk=?,uptime=?,inventory=?,posture=? WHERE id=?",(payload.hostname,payload.platform,payload.arch,payload.os_version,now,payload.cpu,payload.memory,payload.disk,payload.uptime,json.dumps(payload.inventory,separators=(",",":")),json.dumps(payload.posture,separators=(",",":")),r["id"]))
    return {"ok":True}

@app.post("/api/agent/jobs/poll")
async def poll(r: sqlite3.Row = Depends(agent)):
    job=db.one("SELECT * FROM jobs WHERE server_id=? AND status='queued' AND (requires_approval=0) ORDER BY created_at LIMIT 1",(r["id"],))
    if not job: return {"job":None}
    db.execute("UPDATE jobs SET status='running',started_at=? WHERE id=?",(utcnow().isoformat(),job["id"]))
    return {"job":{"id":job["id"],"action":job["action"],"params":db.obj(job["params"])}}

@app.post("/api/agent/jobs/{job_id}/report")
async def report(job_id: str, payload: JobReport, r: sqlite3.Row = Depends(agent)):
    job=db.one("SELECT * FROM jobs WHERE id=? AND server_id=?",(job_id,r["id"]))
    if not job: raise HTTPException(404,"job not found")
    now=utcnow().isoformat(); db.execute("UPDATE jobs SET status=?,result=?,finished_at=? WHERE id=?",(payload.status,json.dumps(payload.result,separators=(",",":")),now,job_id)); audit("agent",f"job.{payload.status}",r["id"],detail={"job_id":job_id,"action":job["action"]}); return {"ok":True}

@app.exception_handler(Exception)
async def unhandled(_: Request, exc: Exception):
    print(f"Unhandled error: {exc!r}")
    return JSONResponse(status_code=500,content={"detail":"internal server error"})

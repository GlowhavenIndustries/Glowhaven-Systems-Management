from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrollment_tokens (token_hash TEXT PRIMARY KEY, created_by INTEGER NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL, used_at TEXT);
CREATE TABLE IF NOT EXISTS servers (id TEXT PRIMARY KEY, name TEXT NOT NULL, hostname TEXT NOT NULL, platform TEXT NOT NULL, arch TEXT NOT NULL, os_version TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'offline', last_seen TEXT, cpu REAL NOT NULL DEFAULT 0, memory REAL NOT NULL DEFAULT 0, disk REAL NOT NULL DEFAULT 0, uptime INTEGER NOT NULL DEFAULT 0, inventory TEXT NOT NULL DEFAULT '{}', posture TEXT NOT NULL DEFAULT '{}', agent_key_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, action TEXT NOT NULL, params TEXT NOT NULL DEFAULT '{}', requested_by INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'queued', requires_approval INTEGER NOT NULL DEFAULT 0, approved_by INTEGER REFERENCES users(id), result TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT);
CREATE TABLE IF NOT EXISTS approvals (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE CASCADE, requested_by INTEGER NOT NULL REFERENCES users(id), approved_by INTEGER REFERENCES users(id), status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, decided_at TEXT);
CREATE TABLE IF NOT EXISTS maintenance_windows (id TEXT PRIMARY KEY, name TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL REFERENCES users(id));
CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, definition TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_servers_last_seen ON servers(last_seen);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
"""

class Database:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def one(self, sql: str, args: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(sql, args).fetchone()

    def all(self, sql: str, args: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(sql, args).fetchall()

    def execute(self, sql: str, args: tuple[Any, ...] = ()) -> None:
        with self.connect() as conn:
            conn.execute(sql, args)

    @staticmethod
    def obj(value: str | None) -> Any:
        try:
            return json.loads(value or "{}")
        except json.JSONDecodeError:
            return {}

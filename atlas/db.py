from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

INITIAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')), created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, csrf TEXT NOT NULL, expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS enrollment_tokens (token_hash TEXT PRIMARY KEY, created_by INTEGER NOT NULL REFERENCES users(id), expires_at TEXT NOT NULL, used_at TEXT);
CREATE TABLE IF NOT EXISTS servers (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, hostname TEXT NOT NULL, platform TEXT NOT NULL, arch TEXT NOT NULL, os_version TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'offline', last_seen TEXT, cpu REAL NOT NULL DEFAULT 0, memory REAL NOT NULL DEFAULT 0, disk REAL NOT NULL DEFAULT 0, uptime INTEGER NOT NULL DEFAULT 0, inventory TEXT NOT NULL DEFAULT '{}', posture TEXT NOT NULL DEFAULT '{}', agent_key_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,
    quarantined INTEGER NOT NULL DEFAULT 0, group_name TEXT NOT NULL DEFAULT 'default', site TEXT NOT NULL DEFAULT 'default', environment TEXT NOT NULL DEFAULT 'production', agent_version TEXT NOT NULL DEFAULT '1.0.0', rollout_ring_id TEXT
);
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, action TEXT NOT NULL, params TEXT NOT NULL DEFAULT '{}', requested_by INTEGER NOT NULL REFERENCES users(id), status TEXT NOT NULL DEFAULT 'queued', requires_approval INTEGER NOT NULL DEFAULT 0, approved_by INTEGER REFERENCES users(id), result TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
    idempotency_key TEXT, priority INTEGER NOT NULL DEFAULT 1, retries INTEGER NOT NULL DEFAULT 0, max_retries INTEGER NOT NULL DEFAULT 3, timeout_seconds INTEGER NOT NULL DEFAULT 3600, scheduled_at TEXT, rollout_ring_id TEXT, audit_correlation_id TEXT
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL UNIQUE REFERENCES jobs(id) ON DELETE CASCADE, requested_by INTEGER NOT NULL REFERENCES users(id), approved_by INTEGER REFERENCES users(id), status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, decided_at TEXT,
    approval_reason TEXT, policy_id TEXT, risk_level TEXT NOT NULL DEFAULT 'HIGH'
);
CREATE TABLE IF NOT EXISTS maintenance_windows (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, starts_at TEXT NOT NULL, ends_at TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL REFERENCES users(id),
    schedule_type TEXT NOT NULL DEFAULT 'one_time', recurrence_rule TEXT, timezone TEXT NOT NULL DEFAULT 'UTC', is_blackout INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, definition TEXT NOT NULL DEFAULT '{}', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
    prev_hash TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS permissions (id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL, permission TEXT NOT NULL, UNIQUE(role, permission));
CREATE TABLE IF NOT EXISTS job_history (id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, state TEXT NOT NULL, message TEXT, timestamp TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cve_database (cve_id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, cvss_score REAL NOT NULL DEFAULT 0.0, affected_packages TEXT NOT NULL DEFAULT '[]', description TEXT, fixed_version TEXT, published_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS vulnerabilities (id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, cve_id TEXT NOT NULL REFERENCES cve_database(cve_id) ON DELETE CASCADE, package_name TEXT NOT NULL, installed_version TEXT NOT NULL, fixed_version TEXT, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'vulnerable', first_seen TEXT NOT NULL, last_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS configuration_policies (id TEXT PRIMARY KEY, name TEXT NOT NULL, kind TEXT NOT NULL, target_scope TEXT NOT NULL DEFAULT 'global', definition TEXT NOT NULL DEFAULT '{}', remediation_behavior TEXT NOT NULL DEFAULT 'audit_only', enabled INTEGER NOT NULL DEFAULT 1, created_by TEXT, version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS drift_records (id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, policy_id TEXT NOT NULL REFERENCES configuration_policies(id) ON DELETE CASCADE, resource_type TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'compliant', desired_state TEXT NOT NULL DEFAULT '{}', observed_state TEXT NOT NULL DEFAULT '{}', difference TEXT NOT NULL DEFAULT '{}', last_evaluated TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS compliance_baselines (id TEXT PRIMARY KEY, name TEXT NOT NULL, framework TEXT NOT NULL, description TEXT, rules TEXT NOT NULL DEFAULT '[]', enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS compliance_results (id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE, baseline_id TEXT NOT NULL REFERENCES compliance_baselines(id) ON DELETE CASCADE, score REAL NOT NULL DEFAULT 0.0, status TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '{}', evaluated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS bmc_nodes (id TEXT PRIMARY KEY, server_id TEXT REFERENCES servers(id) ON DELETE SET NULL, name TEXT NOT NULL, address TEXT NOT NULL, bmc_type TEXT NOT NULL DEFAULT 'redfish', username TEXT NOT NULL, encrypted_password TEXT NOT NULL, power_state TEXT NOT NULL DEFAULT 'unknown', health_status TEXT NOT NULL DEFAULT 'unknown', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS provisioning_profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL, os_family TEXT NOT NULL, image_url TEXT NOT NULL, partition_layout TEXT NOT NULL DEFAULT '{}', post_install_script TEXT NOT NULL DEFAULT '', network_config TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS provisioning_jobs (id TEXT PRIMARY KEY, profile_id TEXT NOT NULL REFERENCES provisioning_profiles(id), mac_address TEXT NOT NULL, target_hostname TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', progress INTEGER NOT NULL DEFAULT 0, log TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rollout_rings (id TEXT PRIMARY KEY, name TEXT NOT NULL, ring_order INTEGER NOT NULL, target_group TEXT NOT NULL DEFAULT 'all', max_concurrency INTEGER NOT NULL DEFAULT 1, failure_threshold_pct REAL NOT NULL DEFAULT 10.0, auto_promote INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (id TEXT PRIMARY KEY, key_name TEXT NOT NULL UNIQUE, encrypted_value TEXT NOT NULL, scope TEXT NOT NULL DEFAULT 'global', created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (id TEXT PRIMARY KEY, server_id TEXT REFERENCES servers(id) ON DELETE CASCADE, severity TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, source TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL, resolved_at TEXT);
CREATE INDEX IF NOT EXISTS idx_servers_last_seen ON servers(last_seen);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
"""


class Database:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(INITIAL_SCHEMA)

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

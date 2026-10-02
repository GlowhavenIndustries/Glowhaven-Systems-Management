from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str = os.getenv("ATLAS_DB_PATH", "./atlas.db")
    bootstrap_admin: str = os.getenv("ATLAS_BOOTSTRAP_ADMIN", "admin")
    bootstrap_password: str = os.getenv("ATLAS_BOOTSTRAP_PASSWORD", "")
    session_hours: int = int(os.getenv("ATLAS_SESSION_HOURS", "8"))
    secure_cookies: bool = os.getenv("ATLAS_SECURE_COOKIES", "false").lower() == "true"
    enrollment_minutes: int = int(os.getenv("ATLAS_ENROLLMENT_MINUTES", "30"))
    host: str = os.getenv("ATLAS_HOST", "127.0.0.1")
    port: int = int(os.getenv("ATLAS_PORT", "8800"))


settings = Settings()

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
KEY_BYTES = 32
SALT_BYTES = 16


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def hash_secret(secret: str) -> str:
    salt = os.urandom(SALT_BYTES)
    digest = hashlib.scrypt(secret.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_BYTES)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


class RateLimiter:
    def __init__(self, max_requests: int, window_seconds: int, max_entries: int = 10000):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self.history: dict[str, list[float]] = {}

    def is_allowed(self, key: str) -> bool:
        now = utcnow().timestamp()
        cutoff = now - self.window_seconds

        if len(self.history) > self.max_entries:
            expired_keys = [k for k, v in self.history.items() if not v or v[-1] < cutoff]
            for k in expired_keys:
                del self.history[k]

        timestamps = [t for t in self.history.get(key, []) if t > cutoff]
        if len(timestamps) >= self.max_requests:
            self.history[key] = timestamps
            return False

        timestamps.append(now)
        self.history[key] = timestamps
        return True


def verify_secret(secret: str, encoded: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = encoded.split("$", 5)
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(secret.encode(), salt=bytes.fromhex(salt_hex), n=int(n), r=int(r), p=int(p), dklen=KEY_BYTES)
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def random_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()

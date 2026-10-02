from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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


def verify_secret(secret: str, encoded: str) -> bool:
    try:
        parts = encoded.split("$", 5)
        if len(parts) != 6:
            return False
        scheme, n, r, p, salt_hex, digest_hex = parts
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


DEFAULT_ROLE_PERMISSIONS: dict[str, set[str]] = {
    "admin": {
        "servers.read", "servers.create", "servers.edit", "servers.delete",
        "agents.enroll", "agents.rotate", "agents.quarantine",
        "inventory.read", "telemetry.read",
        "jobs.read", "jobs.create", "jobs.cancel",
        "services.read", "services.manage",
        "packages.read", "packages.manage",
        "patches.assess", "patches.deploy",
        "configuration.read", "configuration.write",
        "compliance.read", "compliance.manage",
        "hardware.read", "hardware.manage", "power.manage",
        "provisioning.read", "provisioning.manage",
        "network.read", "network.manage", "storage.read", "storage.manage",
        "approvals.request", "approvals.approve",
        "audit.read", "policies.read", "policies.write", "secrets.manage",
        "rollouts.manage", "vulnerabilities.read", "system.admin"
    },
    "operator": {
        "servers.read", "inventory.read", "telemetry.read",
        "jobs.read", "jobs.create", "jobs.cancel",
        "services.read", "services.manage",
        "packages.read", "patches.assess", "patches.deploy",
        "configuration.read", "compliance.read",
        "hardware.read", "power.manage",
        "network.read", "storage.read",
        "approvals.request", "policies.read", "vulnerabilities.read"
    },
    "viewer": {
        "servers.read", "inventory.read", "telemetry.read", "jobs.read",
        "services.read", "packages.read", "configuration.read",
        "compliance.read", "hardware.read", "policies.read", "vulnerabilities.read"
    }
}


def user_has_permission(role: str, permission: str, custom_permissions: set[str] | None = None) -> bool:
    if role == "admin":
        return True
    role_perms = DEFAULT_ROLE_PERMISSIONS.get(role, set())
    if permission in role_perms:
        return True
    if custom_permissions and permission in custom_permissions:
        return True
    return False


def _get_cipher() -> AESGCM:
    master_key = os.getenv("ATLAS_SECRET_KEY", "glowhaven-atlas-master-key-32-bytes-long!")
    key = hashlib.pbkdf2_hmac("sha256", master_key.encode("utf-8"), b"atlas_salt_2025", 100000, 32)
    return AESGCM(key)


def encrypt_secret(plaintext: str) -> str:
    cipher = _get_cipher()
    nonce = os.urandom(12)
    ct = cipher.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")


def decrypt_secret(encrypted_b64: str) -> str:
    try:
        raw = base64.b64decode(encrypted_b64)
        nonce, ct = raw[:12], raw[12:]
        cipher = _get_cipher()
        pt = cipher.decrypt(nonce, ct, None)
        return pt.decode("utf-8")
    except Exception:
        return ""

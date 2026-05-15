from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.settings import settings


bearer_scheme = HTTPBearer(auto_error=False)
PASSWORD_ITERATIONS = 120_000
PASSWORD_ALGORITHM = "pbkdf2_sha256"

ROLE_PERMISSIONS = {
    "analyst": [
        "cases.read",
        "logs.write",
        "intel.read",
        "rag.search",
        "rag.ask",
        "anomalies.read",
        "streams.read",
    ],
    "senior_analyst": [
        "cases.read",
        "logs.write",
        "intel.read",
        "rag.search",
        "rag.ask",
        "rag.rebuild",
        "anomalies.read",
        "streams.read",
    ],
    "admin": [
        "cases.read",
        "logs.write",
        "intel.read",
        "rag.search",
        "rag.ask",
        "rag.rebuild",
        "anomalies.read",
        "streams.read",
        "audit.read",
        "users.read",
    ],
}


@dataclass(slots=True)
class CurrentUser:
    username: str
    role: str
    display_name: str
    is_active: bool = True
    permissions: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def permissions_for_role(role: str) -> list[str]:
    return list(ROLE_PERMISSIONS.get(role, []))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)
    salt_encoded = base64.urlsafe_b64encode(salt).decode("ascii").rstrip("=")
    digest_encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"{PASSWORD_ALGORITHM}${PASSWORD_ITERATIONS}${salt_encoded}${digest_encoded}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iterations_str, salt_encoded, digest_encoded = stored_hash.split("$", 3)
        if algorithm != PASSWORD_ALGORITHM:
            return False
        iterations = int(iterations_str)
        salt = base64.urlsafe_b64decode(salt_encoded + "=" * (-len(salt_encoded) % 4))
        expected = base64.urlsafe_b64decode(digest_encoded + "=" * (-len(digest_encoded) % 4))
    except (ValueError, TypeError, base64.binascii.Error):
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(candidate, expected)


def create_access_token(user: CurrentUser) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_minutes)
    payload = {
        "sub": user.username,
        "role": user.role,
        "display_name": user.display_name,
        "permissions": user.permissions,
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> CurrentUser:
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token") from exc

    username = str(payload.get("sub") or "")
    role = str(payload.get("role") or "")
    display_name = str(payload.get("display_name") or username)
    permissions = list(payload.get("permissions") or permissions_for_role(role))
    if not username or not role:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    return CurrentUser(
        username=username,
        role=role,
        display_name=display_name or username,
        permissions=permissions or permissions_for_role(role),
    )


def get_current_user(credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)) -> CurrentUser:
    if credentials is None or not credentials.credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return decode_access_token(credentials.credentials)


def require_roles(*allowed_roles: str) -> Callable:
    async def dependency(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if allowed_roles and user.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role")
        return user

    return dependency

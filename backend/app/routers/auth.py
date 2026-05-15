from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.core.auth import CurrentUser, create_access_token, get_current_user, permissions_for_role, require_roles, verify_password
from app.services.auth_store import get_user, list_users, record_audit_event

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(payload: LoginRequest) -> dict:
    user = get_user(payload.username.strip())
    if user is None or not bool(user.get("is_active", 1)):
        record_audit_event(payload.username.strip() or "unknown", "anonymous", "auth.login", "failure", metadata={"reason": "user_not_found"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not verify_password(payload.password, str(user["password_hash"])):
        record_audit_event(user["username"], str(user["role"]), "auth.login", "failure", metadata={"reason": "bad_password"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    current = CurrentUser(
        username=str(user["username"]),
        role=str(user["role"]),
        display_name=str(user["display_name"]),
        is_active=bool(user.get("is_active", 1)),
        permissions=permissions_for_role(str(user["role"])),
        created_at=str(user.get("created_at", "")),
        updated_at=str(user.get("updated_at", "")),
    )
    record_audit_event(current.username, current.role, "auth.login", "success", metadata={"permissions": current.permissions})
    token = create_access_token(current)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": 60 * 60 * 8,
        "user": current.to_dict(),
    }


@router.get("/me")
def me(user: CurrentUser = Depends(get_current_user)) -> dict:
    return user.to_dict()


@router.get("/users")
def users(_: CurrentUser = Depends(require_roles("admin"))) -> dict:
    items = []
    for user in list_users():
        items.append(
            {
                "username": user["username"],
                "role": user["role"],
                "display_name": user["display_name"],
                "is_active": bool(user["is_active"]),
                "created_at": user["created_at"],
                "updated_at": user["updated_at"],
            }
        )
    return {"items": items}

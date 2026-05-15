from __future__ import annotations

import uuid
from datetime import datetime, timezone

from app.core.auth import hash_password
from app.core.db import get_connection, json_dump, json_load, row_to_dict
from app.core.settings import settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def seed_default_users() -> None:
    defaults = [
        ("analyst", settings.demo_analyst_password, "analyst", "SOC Analyst"),
        ("senior", settings.demo_senior_password, "senior_analyst", "Senior Analyst"),
        ("admin", settings.demo_admin_password, "admin", "SOC Admin"),
    ]
    with get_connection() as conn:
        for username, password, role, display_name in defaults:
            existing = conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
            if existing is not None:
                continue
            conn.execute(
                """
                INSERT INTO users (username, password_hash, role, display_name, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    username,
                    hash_password(password),
                    role,
                    display_name,
                    1,
                    utc_now(),
                    utc_now(),
                ),
            )


def get_user(username: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT username, password_hash, role, display_name, is_active, created_at, updated_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
    return row_to_dict(row)


def list_users(limit: int = 100) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT username, role, display_name, is_active, created_at, updated_at
            FROM users
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def record_audit_event(
    actor_username: str,
    actor_role: str,
    action: str,
    outcome: str,
    *,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: dict | None = None,
) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO audit_events (
                id, actor_username, actor_role, action, resource_type, resource_id, outcome, metadata_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex,
                actor_username,
                actor_role,
                action,
                resource_type,
                resource_id,
                outcome,
                json_dump(metadata or {}),
                utc_now(),
            ),
        )


def list_audit_events(limit: int = 100) -> list[dict]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, actor_username, actor_role, action, resource_type, resource_id, outcome, metadata_json, created_at
            FROM audit_events
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    events: list[dict] = []
    for row in rows:
        event = row_to_dict(row)
        if event is None:
            continue
        event["metadata"] = json_load(event.pop("metadata_json"))
        events.append(event)
    return events

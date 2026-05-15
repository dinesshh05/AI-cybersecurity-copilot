from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.core.auth import decode_access_token
from app.core.config import settings
from app.core.db import init_db
from app.core.events import event_bus
from app.routers.audit import router as audit_router
from app.routers.auth import router as auth_router
from app.routers.cases import router as cases_router
from app.routers.anomalies import router as anomalies_router
from app.routers.health import router as health_router
from app.routers.intel import router as intel_router
from app.routers.logs import router as logs_router
from app.routers.rag import router as rag_router
from app.routers.streams import mount_stream_routes
from app.services.auth_store import record_audit_event, seed_default_users
from app.services.rag import rebuild_knowledge_base
from app.services.storage import seed_demo_case

app = FastAPI(title=settings.app_name, version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router, prefix=settings.api_prefix)
app.include_router(auth_router, prefix=settings.api_prefix)
app.include_router(audit_router, prefix=settings.api_prefix)
app.include_router(cases_router, prefix=settings.api_prefix)
app.include_router(anomalies_router, prefix=settings.api_prefix)
app.include_router(logs_router, prefix=settings.api_prefix)
app.include_router(intel_router, prefix=settings.api_prefix)
app.include_router(rag_router, prefix=settings.api_prefix)
app.include_router(mount_stream_routes(event_bus), prefix=settings.api_prefix)


@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if not path.startswith(settings.api_prefix):
        return response
    if path in {
        f"{settings.api_prefix}/health",
        f"{settings.api_prefix}/ready",
        f"{settings.api_prefix}/auth/login",
    }:
        return response

    actor_username = "anonymous"
    actor_role = "anonymous"
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token:
            try:
                user = decode_access_token(token)
                actor_username = user.username
                actor_role = user.role
            except Exception:
                actor_username = "invalid-token"
                actor_role = "unknown"

    record_audit_event(
        actor_username,
        actor_role,
        "http.request",
        "success" if response.status_code < 400 else "failure",
        resource_type="http",
        metadata={
            "method": request.method,
            "path": path,
            "query": request.url.query,
            "status_code": response.status_code,
        },
    )
    return response


@app.on_event("startup")
def startup() -> None:
    init_db()
    seed_default_users()
    seed_demo_case()
    try:
        rebuild_knowledge_base()
    except Exception:
        # Keep the app available even if a public free source is temporarily unreachable.
        pass


@app.get("/")
def root() -> dict:
    return {
        "service": settings.app_name,
        "version": "0.1.0",
        "api_prefix": settings.api_prefix,
    }

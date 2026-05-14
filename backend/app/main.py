from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.db import init_db
from app.core.events import event_bus
from app.routers.cases import router as cases_router
from app.routers.anomalies import router as anomalies_router
from app.routers.health import router as health_router
from app.routers.intel import router as intel_router
from app.routers.logs import router as logs_router
from app.routers.rag import router as rag_router
from app.routers.streams import mount_stream_routes
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
app.include_router(cases_router, prefix=settings.api_prefix)
app.include_router(anomalies_router, prefix=settings.api_prefix)
app.include_router(logs_router, prefix=settings.api_prefix)
app.include_router(intel_router, prefix=settings.api_prefix)
app.include_router(rag_router, prefix=settings.api_prefix)
app.include_router(mount_stream_routes(event_bus), prefix=settings.api_prefix)


@app.on_event("startup")
def startup() -> None:
    init_db()
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

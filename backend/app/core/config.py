from __future__ import annotations

import os
from pathlib import Path


class Settings:
    project_root = Path(__file__).resolve().parents[3]
    backend_root = project_root / "backend"
    data_root = project_root / "backend_data"
    database_path = Path(os.getenv("DATABASE_PATH", str(data_root / "copilot.sqlite3")))
    ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
    app_name = "AI Cybersecurity Copilot"
    api_prefix = "/api/v1"
    cors_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]


settings = Settings()


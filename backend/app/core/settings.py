from __future__ import annotations

import os
from pathlib import Path


class Settings:
    project_root = Path(__file__).resolve().parents[3]
    data_root = project_root / "backend_data"
    app_name = "AI Cybersecurity Copilot"
    database_path = Path(os.getenv("DATABASE_PATH", str(data_root / "copilot.sqlite3")))
    vector_dir = Path(os.getenv("VECTOR_DIR", str(data_root / "vectorstore")))
    ollama_base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    ollama_model = os.getenv("OLLAMA_MODEL", "llama3.2")
    embedding_model = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    nvd_api = os.getenv("NVD_API", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    cisa_kev_url = os.getenv("CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    mitre_attack_url = os.getenv("MITRE_ATTACK_URL", "https://attack.mitre.org/")
    api_prefix = "/api/v1"
    cors_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]


settings = Settings()

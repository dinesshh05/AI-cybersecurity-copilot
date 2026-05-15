from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(dotenv_path=PROJECT_ROOT / ".env", override=False)
load_dotenv(dotenv_path=PROJECT_ROOT / "backend" / ".env", override=False)


class Settings:
    project_root = PROJECT_ROOT
    data_root = project_root / "backend_data"
    app_name = "AI Cybersecurity Copilot"
    database_path = Path(os.getenv("DATABASE_PATH", str(data_root / "copilot.sqlite3")))
    vector_dir = Path(os.getenv("VECTOR_DIR", str(data_root / "vectorstore")))
    groq_api_key = os.getenv("GROQ_API_KEY", "")
    groq_api_base = os.getenv("GROQ_API_BASE", "https://api.groq.com/openai/v1")
    groq_model = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    embedding_model = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
    nvd_api = os.getenv("NVD_API", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    cisa_kev_url = os.getenv("CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    mitre_attack_url = os.getenv("MITRE_ATTACK_URL", "https://attack.mitre.org/")
    api_prefix = "/api/v1"
    cors_origins = ["http://localhost:3000", "http://127.0.0.1:3000"]


settings = Settings()

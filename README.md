# AI Cybersecurity Copilot

AI Cybersecurity Copilot is a production-style security operations assistant built as a working vertical slice with free and open-source tools.

It combines:

- FastAPI backend APIs
- Next.js dashboard
- live WebSocket updates
- heuristic log analysis
- case management
- anomaly scoring
- threat-intel enrichment
- retrieval-backed cybersecurity Q&A
- local-first LLM-compatible summarization

## What Is Working Right Now

The current build already supports an end-to-end SOC-style workflow:

1. Upload or seed a security log.
2. Analyze the log on the backend.
3. Create a case in storage.
4. Generate an incident summary.
5. Push a live `analysis.completed` event to the dashboard.
6. Review the case, anomaly score, intel lookup, and retrieval results in the UI.

### Working Features

- log upload
- demo case seeding
- case list and case detail views
- live event stream over WebSocket
- heuristic detection of suspicious activity
- anomaly scoring
- free RAG search over cybersecurity knowledge
- NVD-backed CVE lookup
- retrieval-backed copilot Q&A

## Free Stack Choices

This project intentionally uses free or open-source tooling:

- FastAPI for the backend
- Next.js for the frontend
- Tailwind CSS for styling
- SQLite for the current baseline persistence layer
- ChromaDB or a local fallback vector store for retrieval
- SentenceTransformers or a local fallback embedding path
- Ollama for local model inference
- NVD, CISA KEV, and MITRE ATT&CK as public intel sources
- Redis later for job coordination and event fan-out

## Repository Layout

```text
ai-cybersecurity-copilot/
  backend/
    app/
      core/
      models/
      routers/
      services/
    tests/
  web/
    app/
    components/
    lib/
  docs/
  .github/
  compose.yaml
  README.md
```

## Local Setup

### 1. Create the conda environment

```powershell
conda create -n ai-cybersec-copilot python=3.11 -y
conda activate ai-cybersec-copilot
```

### 2. Start the backend

```powershell
cd "E:\ai-cybersecurity-copilot\backend"
pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

### 3. Start the frontend

Open a second terminal:

```powershell
cd "E:\ai-cybersecurity-copilot\web"
npm install
npm run dev
```

### 4. Open the app

- Frontend: [http://localhost:3000](http://localhost:3000)
- Backend API: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- Swagger docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

## Backend API Surface

All application routes are mounted under `/api/v1`.

- `GET /api/v1/health`
- `GET /api/v1/ready`
- `GET /api/v1/cases`
- `GET /api/v1/cases/{case_id}`
- `POST /api/v1/cases/demo`
- `POST /api/v1/logs/upload`
- `GET /api/v1/anomalies/case/{case_id}`
- `GET /api/v1/intel/cve/{cve_id}`
- `GET /api/v1/rag/search`
- `POST /api/v1/rag/ask`
- `POST /api/v1/rag/rebuild`
- `WS /api/v1/ws/events`

## Roadmap

The project is being built in production-style milestones.

### Milestone 1: Working Vertical Slice

Completed:

- backend API
- frontend dashboard
- log upload
- case creation
- summary generation
- live event streaming

### Milestone 2: Free-Only Intelligence Layer

In progress:

- better RAG over cyber knowledge
- MITRE ATT&CK and CISA KEV enrichment
- CVE lookup and citation support
- grounded security Q&A

### Milestone 3: Security Product Hardening

Next:

- authentication
- RBAC
- audit logging
- background jobs
- Redis fan-out

### Milestone 4: Stronger AI Orchestration

Later:

- LangGraph workflows
- intent routing
- tool calling
- multi-step analyst workflows

### Milestone 5: Production Readiness

Later:

- Postgres migration
- observability
- rate limiting
- CI/CD
- deployment hardening

## Demo Flow

1. Open the dashboard.
2. Click `Load demo case`.
3. Or paste a log and click `Analyze log`.
4. Review the summary, anomaly score, and evidence.
5. Use the Knowledge Base, Copilot Q&A, and Threat Intel panels.

## Why This Project Matters

This is meant to feel like an internal SOC copilot or startup security product, not a student demo.

It demonstrates:

- backend architecture
- AI system design
- security engineering thinking
- retrieval and enrichment workflows
- real-time UI engineering
- product-minded implementation

## Notes

- The backend root endpoint returns JSON by design.
- The correct health endpoint is `/api/v1/health`, not `/health`.
- The project uses free and open-source tools where possible.
- The current codebase is intentionally designed for iterative expansion.

## License

Add your preferred license here.

# AI Cybersecurity Copilot

AI Cybersecurity Copilot is a production-style security operations assistant built as a working vertical slice with free and open-source tools.

It combines:

- FastAPI backend APIs
- Next.js dashboard
- live WebSocket updates
- JWT authentication and RBAC
- audit logging
- heuristic log analysis
- ML anomaly scoring
- case management
- threat-intel enrichment
- semantic retrieval over cyber knowledge
- optional Groq-backed incident summaries

## What Is Working Right Now

The current build already supports an end-to-end SOC-style workflow:

1. Upload or seed a security log.
2. Analyze the log on the backend.
3. Create a case in storage.
4. Score the log with an ML anomaly baseline.
5. Generate an incident summary.
6. Push a live `analysis.completed` event to the dashboard.
7. Record audit events for the analyst actions.
8. Review the case, anomaly score, intel lookup, and retrieval results in the UI.

### Working Features

- log upload
- demo case seeding
- case list and case detail views
- live event stream over WebSocket
- JWT-authenticated dashboard sessions
- audit trail storage and admin viewing
- heuristic detection of suspicious activity
- ML-backed anomaly scoring with deterministic fallback
- semantic retrieval over cybersecurity knowledge
- NVD-backed CVE lookup
- optional Groq incident summaries
- retrieval-backed copilot Q&A

## Free Stack Choices

This project intentionally uses free or open-source tooling:

- FastAPI for the backend
- Next.js for the frontend
- Tailwind CSS for styling
- SQLite for the current baseline persistence layer
- local fallback vector search for retrieval
- local fallback embedding path for retrieval
- Groq for the optional LLM summary path
- scikit-learn for ML anomaly detection
- NVD, CISA KEV, and MITRE ATT&CK as public intel sources
- Redis later for job coordination and event fan-out
- PyJWT for compact JWT auth

The default install is intentionally lightweight on Windows:

- no native vector database build is required
- no sentence-transformer download is required to start the app
- the heavier retrieval stack can be added later as an optional upgrade

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

## Project Progress

### Overall Status

- Core product: ~85% complete
- Production-ready version: ~70% complete

### Completed

| Area | Status | Notes |
|---|---:|---|
| Backend API foundation | Done | FastAPI app, routers, health, case APIs |
| Frontend dashboard | Done | Next.js UI, live panels, case views |
| Log ingestion | Done | Upload, demo seeding, parsing path |
| Heuristic detection | Done | Rule-based suspicious pattern detection |
| ML anomaly detection | Done | IsolationForest scoring with fallback |
| Semantic retrieval / RAG | Done | Retrieval-backed knowledge search and Q&A |
| Threat intel enrichment | Done | NVD / MITRE / CISA context |
| Incident summarization | Done | Groq optional, deterministic fallback |
| JWT auth + RBAC | Done | Login, roles, protected routes |
| Audit logging | Done | Audit trail storage and admin view |
| Real-time streaming | Done | WebSocket events to dashboard |

### In Progress

| Area | Status | Notes |
|---|---:|---|
| Persistence layer | Partial | SQLite works now, Postgres still pending |
| Strong orchestration / intent routing | Partial | Basic flow exists, LangGraph-style routing still pending |
| Security hardening | Partial | Auth exists, but rate limiting and upload hardening remain |
| CI/CD hardening | Partial | Repo structure exists, but pipeline can be improved |
| Deployment polish | Partial | Docker exists, but production packaging can be tightened |

### Remaining

| Area | Status | Notes |
|---|---:|---|
| Background jobs / Redis | Not started | Needed for scalable async processing |
| Observability / metrics | Not started | Logging, tracing, performance metrics still needed |

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

If you want AI-generated summaries instead of the deterministic fallback, set `GROQ_API_KEY` in your environment or `.env` file first.
For authentication, the backend seeds demo users on startup:

- analyst / `DEMO_ANALYST_PASSWORD` or `analyst123`
- senior / `DEMO_SENIOR_PASSWORD` or `senior123`
- admin / `DEMO_ADMIN_PASSWORD` or `admin123`

The backend automatically loads `E:\ai-cybersecurity-copilot\.env` and `E:\ai-cybersecurity-copilot\backend\.env` if they exist.
The current install path only needs the lightweight dependencies in `backend/requirements.txt`.

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
- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `GET /api/v1/auth/users`
- `GET /api/v1/audit/events`
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

| Milestone | Priority | Recruiter Impact | Status |
|---|---:|---:|---|
| Working Vertical Slice | High | Very High | Complete |
| Free-Only Intelligence Layer | High | Very High | In progress |
| Security Product Hardening | High | Very High | In progress |
| Stronger AI Orchestration | Medium | High | Next |
| Production Readiness | Medium | High | Next |

### Milestone Details

#### Milestone 1: Working Vertical Slice

- backend API
- frontend dashboard
- log upload
- case creation
- summary generation
- live event streaming

#### Milestone 2: Free-Only Intelligence Layer

- better semantic retrieval over cyber knowledge
- MITRE ATT&CK and CISA KEV enrichment
- CVE lookup and citation support
- grounded security Q&A
- ML anomaly detection improvements

#### Milestone 3: Security Product Hardening

- authentication
- RBAC
- audit logging
- background jobs
- Redis fan-out

#### Milestone 4: Stronger AI Orchestration

- LangGraph workflows
- intent routing
- tool calling
- multi-step analyst workflows

#### Milestone 5: Production Readiness

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
6. Sign in with a demo user and inspect the admin audit trail if needed.

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
- The backend ships with built-in fallback embeddings and vector search so it can run without native build tooling on Windows.
- The backend now uses JWT auth plus role-based access control for protected actions.
- The current codebase is intentionally designed for iterative expansion.

## License

Add your preferred license here.

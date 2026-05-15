# Architecture Overview

## Current Slice

The current application is a vertical slice:

1. A log is uploaded through the dashboard.
2. The FastAPI backend analyzes the log heuristically.
3. A case is written to SQLite.
4. The log is scored with an ML anomaly baseline.
5. A summary is created with the optional Groq path, with a deterministic fallback if Groq is unavailable.
6. A JWT-authenticated request is recorded in the audit trail.
7. An `analysis.completed` event is pushed over WebSocket.
8. The dashboard refreshes and shows the result.

## Free Stack Choices

The project intentionally uses free and open-source components:

- FastAPI for the API layer
- Next.js for the UI
- SQLite for local persistence
- JWT auth for secured analyst sessions
- a local fallback vector search implementation for retrieval
- a local fallback embedding implementation for retrieval
- scikit-learn for ML anomaly detection
- Groq for the optional summary generation path
- NVD, CISA KEV, and MITRE ATT&CK as free public intelligence sources
- repo-root `.env` auto-loading for local development

The initial Windows-friendly install path keeps the dependency set lightweight and avoids native build tooling.

## Next Milestones

- Retrieval-backed security Q&A
- CVE enrichment endpoints
- threat-intel correlation
- anomaly detection improvements
- authentication and audit logging
- Redis for queueing and event fan-out

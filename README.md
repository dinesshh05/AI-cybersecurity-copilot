# AI Cybersecurity Copilot

Vertical slice for a production-style AI SOC assistant.

## What this slice includes

- Log upload
- Heuristic log analysis
- Case persistence in SQLite
- AI-style incident summary with local Ollama fallback
- Threat-intel enrichment hooks
- Live event stream over WebSocket
- Next.js analyst dashboard shell

## Stack

- Backend: FastAPI
- Orchestration: lightweight vertical slice, ready for LangGraph integration
- Vector search: planned for the next milestone
- LLM runtime: Ollama-compatible interface
- Frontend: Next.js + Tailwind
- Storage: SQLite for the slice, Postgres later
- Realtime: WebSocket now, Redis fan-out next

## Run locally

1. Start the backend.

```bash
cd ai-cybersecurity-copilot/backend
python -m uvicorn app.main:app --reload --port 8000
```

2. Start the frontend.

```bash
cd ai-cybersecurity-copilot/web
npm run dev
```

3. Open the dashboard.

```text
http://localhost:3000
```

## Demo behavior

- The backend seeds one demo incident on first startup if the database is empty.
- Uploading a new log pushes an `analysis.completed` event to the live stream.
- The case detail panel always focuses the most recent uploaded case.

## Quick test

From `ai-cybersecurity-copilot/backend`:

```bash
python -m unittest discover -s tests
```

## Why this structure

This slice is intentionally case-centric:

- logs become evidence
- evidence becomes a case
- a case gets summarized and streamed live

That keeps the product aligned with how real SOC teams work.

"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import {
  askCopilot,
  fetchCaseAnomaly,
  fetchCases,
  getWebSocketUrl,
  lookupCve,
  rebuildKnowledgeBase,
  searchKnowledge,
  seedDemoCase,
  uploadLog,
  type CaseSummary,
  type IntelCveResult,
  type AnomalyResult,
  type RetrievedChunk,
} from "@/lib/api"

const defaultLog = `Jan 14 08:15:11 auth host sshd[2321]: Failed password for invalid user admin from 185.220.101.1 port 52144 ssh2
Jan 14 08:15:12 auth host sshd[2321]: Failed password for invalid user root from 185.220.101.1 port 52145 ssh2
Jan 14 08:15:14 auth host sshd[2321]: Failed password for invalid user test from 185.220.101.1 port 52146 ssh2
Jan 14 08:16:03 endpoint powershell.exe -enc SQBFAFgAIAA=
Jan 14 08:16:06 endpoint kernel: malware beaconing to 203.0.113.42
Jan 14 08:16:07 scanner found CVE-2024-3094 on package xz-utils`

export function Dashboard() {
  const [cases, setCases] = useState<CaseSummary[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [logText, setLogText] = useState(defaultLog)
  const [sourceName, setSourceName] = useState("demo-log.txt")
  const [status, setStatus] = useState("Booting analyst workspace")
  const [stream, setStream] = useState<Array<{ type: string; payload: Record<string, unknown> }>>([])
  const [ragQuery, setRagQuery] = useState("PowerShell suspicious activity")
  const [ragResults, setRagResults] = useState<RetrievedChunk[]>([])
  const [copilotQuestion, setCopilotQuestion] = useState("What does CVE-2024-3094 mean for this incident?")
  const [copilotAnswer, setCopilotAnswer] = useState<string>("")
  const [copilotCitations, setCopilotCitations] = useState<Array<Record<string, unknown>>>([])
  const [intelCve, setIntelCve] = useState("CVE-2024-3094")
  const [intelResult, setIntelResult] = useState<IntelCveResult | null>(null)
  const [anomalyResult, setAnomalyResult] = useState<AnomalyResult | null>(null)
  const selectedIdRef = useRef<string | null>(selectedId)
  const selectedCase = useMemo(() => cases.find((item) => item.id === selectedId) ?? cases[0] ?? null, [cases, selectedId])

  useEffect(() => {
    selectedIdRef.current = selectedId
  }, [selectedId])

  useEffect(() => {
    void loadCases()
  }, [])

  useEffect(() => {
    const socket = new WebSocket(getWebSocketUrl())
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data) as { type: string; payload: Record<string, unknown> }
      setStream((current) => [message, ...current].slice(0, 12))
      if (message.type === "analysis.completed") {
        void loadCases()
      }
    }
    socket.onopen = () => setStatus("Connected to live analysis stream")
    socket.onerror = () => setStatus("Live stream unavailable, using pull refresh")
    return () => socket.close()
  }, [])

  useEffect(() => {
    if (!selectedCase) {
      setAnomalyResult(null)
      return
    }
    void (async () => {
      try {
        const result = await fetchCaseAnomaly(selectedCase.id)
        setAnomalyResult(result)
      } catch {
        setAnomalyResult(null)
      }
    })()
  }, [selectedCase?.id])

  async function loadCases(preferredSelectedId: string | null = null) {
    try {
      const items = await fetchCases()
      setCases(items)
      const currentSelectedId = preferredSelectedId ?? selectedIdRef.current
      if (items.length > 0 && (!currentSelectedId || !items.some((item) => item.id === currentSelectedId))) {
        setSelectedId(items[0].id)
      } else if (preferredSelectedId && items.some((item) => item.id === preferredSelectedId)) {
        setSelectedId(preferredSelectedId)
      }
      if (items.length > 0) {
        setStatus(`Loaded ${items.length} case(s)`)
      } else {
        setStatus("Backend reachable, but no cases found")
      }
    } catch {
      setCases([])
      setStatus("Backend is not reachable. Start FastAPI on port 8000 and refresh.")
    }
  }

  async function handleSeed() {
    setStatus("Loading demo incident")
    await seedDemoCase()
    await loadCases()
  }

  async function handleUpload() {
    setStatus("Analyzing uploaded log")
    const response = await uploadLog(logText, sourceName)
    await loadCases(response.case_id)
    setStatus("Analysis complete")
  }

  async function handleRebuildKnowledgeBase() {
    try {
      setStatus("Rebuilding knowledge base")
      await rebuildKnowledgeBase()
      const items = await searchKnowledge(ragQuery)
      setRagResults(items)
      setStatus("Knowledge base rebuilt")
    } catch {
      setStatus("Knowledge base rebuild failed")
    }
  }

  async function handleSearchKnowledge() {
    try {
      setStatus("Searching knowledge base")
      const items = await searchKnowledge(ragQuery)
      setRagResults(items)
      setStatus(`Found ${items.length} knowledge hit(s)`)
    } catch {
      setStatus("Knowledge search failed")
    }
  }

  async function handleAskCopilot() {
    try {
      setStatus("Asking copilot")
      const result = await askCopilot(copilotQuestion)
      setCopilotAnswer(result.answer)
      setCopilotCitations(result.citations)
      setStatus("Copilot response ready")
    } catch {
      setStatus("Copilot question failed")
    }
  }

  async function handleLookupCve() {
    try {
      setStatus("Looking up CVE")
      const result = await lookupCve(intelCve)
      setIntelResult(result)
      setStatus(`Loaded intel for ${intelCve}`)
    } catch {
      setStatus("CVE lookup failed")
    }
  }

  const severityLabel = selectedCase?.severity ?? "unknown"

  return (
    <main className="min-h-screen px-4 py-6 text-text md:px-8 lg:px-12">
      <div className="mx-auto flex max-w-7xl flex-col gap-6">
        <section className="rounded-3xl border border-white/10 bg-panel/90 p-6 shadow-neon backdrop-blur">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div className="max-w-3xl">
              <div className="mb-3 inline-flex rounded-full border border-accent/25 bg-accent/10 px-3 py-1 text-xs font-medium uppercase tracking-[0.25em] text-accent">
                AI SOC Copilot
              </div>
              <h1 className="text-3xl font-semibold tracking-tight md:text-5xl">
                Log upload, enrichment, and incident summary in one workflow.
              </h1>
              <p className="mt-3 max-w-2xl text-sm leading-6 text-muted md:text-base">
                This vertical slice turns raw telemetry into a case, runs heuristic analysis, streams the result live,
                and produces a grounded incident summary with an Ollama fallback.
              </p>
            </div>
            <div className="rounded-2xl border border-white/10 bg-panel2 px-4 py-3 text-sm text-muted">
              <div>Status</div>
              <div className="mt-1 font-medium text-text">{status}</div>
            </div>
          </div>
        </section>

        <section className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
          <div className="rounded-3xl border border-white/10 bg-panel/90 p-5 shadow-neon">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-lg font-semibold">Log Intake</h2>
              <button
                onClick={handleSeed}
                className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm hover:bg-white/10"
              >
                Load demo case
              </button>
            </div>
            <div className="grid gap-4">
              <label className="grid gap-2 text-sm text-muted">
                Source name
                <input
                  value={sourceName}
                  onChange={(event) => setSourceName(event.target.value)}
                  className="rounded-2xl border border-white/10 bg-bg/70 px-4 py-3 text-text outline-none ring-0"
                />
              </label>
              <label className="grid gap-2 text-sm text-muted">
                Log text
                <textarea
                  value={logText}
                  onChange={(event) => setLogText(event.target.value)}
                  rows={10}
                  className="rounded-2xl border border-white/10 bg-bg/70 px-4 py-3 font-mono text-xs leading-5 text-text outline-none"
                />
              </label>
              <div className="flex flex-wrap gap-3">
                <button
                  onClick={handleUpload}
                  className="rounded-full bg-accent px-5 py-2.5 text-sm font-semibold text-slate-950 transition hover:brightness-110"
                >
                  Analyze log
                </button>
                <button
                  onClick={() => void loadCases()}
                  className="rounded-full border border-white/10 bg-white/5 px-5 py-2.5 text-sm transition hover:bg-white/10"
                >
                  Refresh cases
                </button>
              </div>
            </div>
          </div>

          <div className="grid gap-4">
            <div className="grid grid-cols-2 gap-4">
              <StatCard label="Cases" value={cases.length.toString()} />
              <StatCard label="Severity" value={severityLabel.toUpperCase()} />
            </div>
            <div className="rounded-3xl border border-white/10 bg-panel/90 p-5 shadow-neon">
              <h2 className="text-lg font-semibold">Live Stream</h2>
              <div className="mt-4 space-y-3">
                {stream.length === 0 ? (
                  <p className="text-sm text-muted">Waiting for analysis events...</p>
                ) : (
                  stream.map((event, index) => (
                    <div key={`${event.type}-${index}`} className="rounded-2xl border border-white/10 bg-bg/70 p-3">
                      <div className="text-xs uppercase tracking-[0.2em] text-accent">{event.type}</div>
                      <pre className="mt-2 overflow-x-auto text-xs text-muted">
                        {JSON.stringify(event.payload, null, 2)}
                      </pre>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </section>

        <section className="grid gap-6 lg:grid-cols-[0.9fr_1.1fr]">
          <div className="rounded-3xl border border-white/10 bg-panel/90 p-5 shadow-neon">
            <h2 className="text-lg font-semibold">Cases</h2>
            <div className="mt-4 space-y-3">
              {cases.length === 0 ? (
                <p className="text-sm text-muted">No cases yet. Upload a log or seed the demo incident.</p>
              ) : (
                cases.map((item) => (
                  <button
                    key={item.id}
                    onClick={() => setSelectedId(item.id)}
                    className={`w-full rounded-2xl border p-4 text-left transition ${
                      item.id === selectedCase?.id
                        ? "border-accent/50 bg-accent/10"
                        : "border-white/10 bg-bg/60 hover:bg-white/5"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div>
                        <div className="font-semibold">{item.title}</div>
                        <div className="text-xs uppercase tracking-[0.2em] text-muted">{item.source_name}</div>
                      </div>
                      <div className="rounded-full border border-white/10 px-3 py-1 text-xs uppercase tracking-[0.2em]">
                        {item.severity}
                      </div>
                    </div>
                    <p className="mt-3 max-h-12 overflow-hidden text-sm text-muted">{item.summary}</p>
                  </button>
                ))
              )}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-panel/90 p-5 shadow-neon">
            <h2 className="text-lg font-semibold">Case Detail</h2>
            {selectedCase ? (
              <div className="mt-4 grid gap-4">
                <div className="grid gap-2 md:grid-cols-3">
                  <DetailPill label="Risk" value={`${selectedCase.risk_score}/100`} />
                  <DetailPill label="Severity" value={selectedCase.severity} />
                  <DetailPill label="Status" value={selectedCase.status} />
                </div>
                <div className="rounded-2xl border border-white/10 bg-bg/70 p-4">
                  <div className="text-xs uppercase tracking-[0.2em] text-muted">Anomaly Score</div>
                  {anomalyResult ? (
                    <>
                      <div className="mt-2 text-3xl font-semibold">{anomalyResult.score}</div>
                      <div className="mt-1 text-sm uppercase tracking-[0.2em] text-accent">{anomalyResult.severity}</div>
                      <ul className="mt-3 space-y-1 text-sm text-muted">
                        {anomalyResult.signals.map((signal) => (
                          <li key={signal}>- {signal}</li>
                        ))}
                      </ul>
                    </>
                  ) : (
                    <p className="mt-2 text-sm text-muted">No anomaly score loaded.</p>
                  )}
                </div>
                <div className="rounded-2xl border border-white/10 bg-bg/70 p-4">
                  <div className="text-xs uppercase tracking-[0.2em] text-muted">Summary</div>
                  <p className="mt-2 text-sm leading-6 text-text">{selectedCase.summary}</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-bg/70 p-4">
                  <div className="text-xs uppercase tracking-[0.2em] text-muted">Analysis</div>
                  <pre className="mt-2 overflow-x-auto text-xs leading-5 text-muted">
                    {JSON.stringify(
                      {
                        analysis: selectedCase.analysis,
                        events: selectedCase.events,
                      },
                      null,
                      2,
                    )}
                  </pre>
                </div>
              </div>
            ) : (
              <p className="mt-4 text-sm text-muted">Select a case to inspect the analysis payload.</p>
            )}
          </div>
        </section>

        <section className="grid gap-6 lg:grid-cols-3">
          <div className="rounded-3xl border border-white/10 bg-panel/90 p-5 shadow-neon">
            <h2 className="text-lg font-semibold">Knowledge Base</h2>
            <p className="mt-2 text-sm text-muted">Search the free RAG corpus backed by MITRE ATT&CK notes and CISA KEV data.</p>
            <div className="mt-4 grid gap-3">
              <input
                value={ragQuery}
                onChange={(event) => setRagQuery(event.target.value)}
                className="rounded-2xl border border-white/10 bg-bg/70 px-4 py-3 text-sm text-text outline-none"
              />
              <div className="flex flex-wrap gap-2">
                <button onClick={handleSearchKnowledge} className="rounded-full bg-accent px-4 py-2 text-sm font-semibold text-slate-950">
                  Search
                </button>
                <button onClick={handleRebuildKnowledgeBase} className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-sm">
                  Rebuild
                </button>
              </div>
              <div className="space-y-3">
                {ragResults.length === 0 ? (
                  <p className="text-sm text-muted">No retrieval results yet.</p>
                ) : (
                  ragResults.map((item) => (
                    <div key={item.doc_id} className="rounded-2xl border border-white/10 bg-bg/70 p-3">
                      <div className="flex items-center justify-between gap-2">
                        <div className="font-semibold">{item.title}</div>
                        <div className="text-xs uppercase tracking-[0.2em] text-accent">{item.source}</div>
                      </div>
                      <p className="mt-2 text-sm text-muted">{item.text}</p>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-panel/90 p-5 shadow-neon">
            <h2 className="text-lg font-semibold">Copilot Q&A</h2>
            <p className="mt-2 text-sm text-muted">Ask a grounded cybersecurity question and inspect citations.</p>
            <div className="mt-4 grid gap-3">
              <textarea
                value={copilotQuestion}
                onChange={(event) => setCopilotQuestion(event.target.value)}
                rows={5}
                className="rounded-2xl border border-white/10 bg-bg/70 px-4 py-3 text-sm text-text outline-none"
              />
              <button onClick={handleAskCopilot} className="rounded-full bg-accent px-4 py-2 text-sm font-semibold text-slate-950">
                Ask Copilot
              </button>
              {copilotAnswer ? (
                <div className="rounded-2xl border border-white/10 bg-bg/70 p-3">
                  <div className="text-xs uppercase tracking-[0.2em] text-muted">Answer</div>
                  <p className="mt-2 text-sm leading-6 text-text">{copilotAnswer}</p>
                  <div className="mt-3 text-xs uppercase tracking-[0.2em] text-muted">Citations</div>
                  <pre className="mt-2 overflow-x-auto text-xs text-muted">{JSON.stringify(copilotCitations, null, 2)}</pre>
                </div>
              ) : (
                <p className="text-sm text-muted">No answer yet.</p>
              )}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-panel/90 p-5 shadow-neon">
            <h2 className="text-lg font-semibold">Threat Intel</h2>
            <p className="mt-2 text-sm text-muted">Lookup a CVE with the free NVD-backed endpoint.</p>
            <div className="mt-4 grid gap-3">
              <input
                value={intelCve}
                onChange={(event) => setIntelCve(event.target.value)}
                className="rounded-2xl border border-white/10 bg-bg/70 px-4 py-3 text-sm text-text outline-none"
              />
              <button onClick={handleLookupCve} className="rounded-full bg-accent px-4 py-2 text-sm font-semibold text-slate-950">
                Lookup CVE
              </button>
              {intelResult ? (
                <div className="rounded-2xl border border-white/10 bg-bg/70 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="font-semibold">{intelResult.title}</div>
                    <div className="text-xs uppercase tracking-[0.2em] text-accent">{intelResult.severity}</div>
                  </div>
                  <p className="mt-2 text-sm text-muted">{intelResult.summary}</p>
                  <pre className="mt-3 overflow-x-auto text-xs text-muted">{JSON.stringify(intelResult.references, null, 2)}</pre>
                </div>
              ) : (
                <p className="text-sm text-muted">No intel loaded yet.</p>
              )}
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-panel/90 p-5 shadow-neon">
      <div className="text-xs uppercase tracking-[0.25em] text-muted">{label}</div>
      <div className="mt-3 text-3xl font-semibold">{value}</div>
    </div>
  )
}

function DetailPill({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-bg/70 px-4 py-3">
      <div className="text-xs uppercase tracking-[0.2em] text-muted">{label}</div>
      <div className="mt-1 font-semibold">{value}</div>
    </div>
  )
}

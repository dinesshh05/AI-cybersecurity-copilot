"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import { fetchCases, getWebSocketUrl, seedDemoCase, uploadLog, type CaseSummary } from "@/lib/api"

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

  async function loadCases(preferredSelectedId: string | null = null) {
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

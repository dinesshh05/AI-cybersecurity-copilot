export type CaseSummary = {
  id: string
  title: string
  status: string
  severity: string
  risk_score: number
  source_name: string
  summary: string
  created_at: string
  updated_at: string
}

export type CaseDetail = CaseSummary & {
  raw_text: string
  analysis: {
    detection_summary: string
    indicators: Array<Record<string, unknown>>
    evidence: Array<Record<string, unknown>>
    remediation: string[]
    model_notes: string
    created_at: string
  } | null
  events: Array<{
    event_type: string
    payload: Record<string, unknown>
    created_at: string
  }>
}

const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"

export async function fetchCases(): Promise<CaseSummary[]> {
  const response = await fetch(`${apiBase}/api/v1/cases`, { cache: "no-store" })
  if (!response.ok) {
    return []
  }
  const payload = await response.json()
  return payload.items ?? []
}

export async function fetchCase(caseId: string): Promise<CaseDetail | null> {
  const response = await fetch(`${apiBase}/api/v1/cases/${caseId}`, { cache: "no-store" })
  if (!response.ok) {
    return null
  }
  return response.json()
}

export async function uploadLog(logText: string, sourceName: string): Promise<{ case_id: string }> {
  const formData = new FormData()
  formData.append("log_text", logText)
  formData.append("source_name", sourceName)
  const response = await fetch(`${apiBase}/api/v1/logs/upload`, {
    method: "POST",
    body: formData,
  })
  if (!response.ok) {
    throw new Error("Upload failed")
  }
  return response.json()
}

export async function seedDemoCase(): Promise<void> {
  await fetch(`${apiBase}/api/v1/cases/demo`, { method: "POST" })
}

export function getWebSocketUrl(): string {
  const url = new URL(apiBase)
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:"
  url.pathname = "/api/v1/ws/events"
  return url.toString()
}


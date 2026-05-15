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

export type RetrievedChunk = {
  doc_id: string
  title: string
  source: string
  score: number
  text: string
  metadata: Record<string, unknown>
}

export type IntelCveResult = {
  source: string
  title: string
  severity: string
  confidence: number
  summary: string
  references: string[]
  payload: Record<string, unknown>
}

export type AnomalyResult = {
  case_id: string
  title: string
  score: number
  severity: string
  signals: string[]
  features: Record<string, number>
  model_notes?: string
}

export type AuthUser = {
  username: string
  role: string
  display_name: string
  is_active: boolean
  permissions: string[]
  created_at: string
  updated_at: string
}

export type AuthLoginResponse = {
  access_token: string
  token_type: string
  expires_in: number
  user: AuthUser
}

export type AuditEvent = {
  id: string
  actor_username: string
  actor_role: string
  action: string
  resource_type: string | null
  resource_id: string | null
  outcome: string
  metadata: Record<string, unknown>
  created_at: string
}

const apiBase = process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000"
const authTokenKey = "ai-cybersecurity-copilot.token"

export function getStoredAuthToken(): string | null {
  if (typeof window === "undefined") {
    return null
  }
  return window.localStorage.getItem(authTokenKey)
}

export function setStoredAuthToken(token: string): void {
  if (typeof window === "undefined") {
    return
  }
  window.localStorage.setItem(authTokenKey, token)
}

export function clearStoredAuthToken(): void {
  if (typeof window === "undefined") {
    return
  }
  window.localStorage.removeItem(authTokenKey)
}

function withAuth(init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers ?? {})
  const token = getStoredAuthToken()
  if (token) {
    headers.set("Authorization", `Bearer ${token}`)
  }
  return {
    ...init,
    headers,
  }
}

export async function login(username: string, password: string): Promise<AuthLoginResponse> {
  const response = await fetch(`${apiBase}/api/v1/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  })
  if (!response.ok) {
    throw new Error("Login failed")
  }
  return response.json()
}

export async function fetchMe(): Promise<AuthUser | null> {
  const response = await fetch(`${apiBase}/api/v1/auth/me`, withAuth({ cache: "no-store" }))
  if (!response.ok) {
    return null
  }
  return response.json()
}

export async function fetchAuditEvents(limit = 50): Promise<AuditEvent[]> {
  const response = await fetch(`${apiBase}/api/v1/audit/events?limit=${limit}`, withAuth({ cache: "no-store" }))
  if (!response.ok) {
    return []
  }
  const payload = await response.json()
  return payload.items ?? []
}

export async function fetchCases(): Promise<CaseSummary[]> {
  const response = await fetch(`${apiBase}/api/v1/cases`, withAuth({ cache: "no-store" }))
  if (!response.ok) {
    return []
  }
  const payload = await response.json()
  return payload.items ?? []
}

export async function fetchCase(caseId: string): Promise<CaseDetail | null> {
  const response = await fetch(`${apiBase}/api/v1/cases/${caseId}`, withAuth({ cache: "no-store" }))
  if (!response.ok) {
    return null
  }
  return response.json()
}

export async function uploadLog(logText: string, sourceName: string): Promise<{ case_id: string }> {
  const formData = new FormData()
  formData.append("log_text", logText)
  formData.append("source_name", sourceName)
  const response = await fetch(
    `${apiBase}/api/v1/logs/upload`,
    withAuth({
      method: "POST",
      body: formData,
    }),
  )
  if (!response.ok) {
    throw new Error("Upload failed")
  }
  return response.json()
}

export async function seedDemoCase(): Promise<void> {
  await fetch(`${apiBase}/api/v1/cases/demo`, withAuth({ method: "POST" }))
}

export async function rebuildKnowledgeBase(): Promise<{ indexed: number }> {
  const response = await fetch(`${apiBase}/api/v1/rag/rebuild`, withAuth({ method: "POST" }))
  return response.json()
}

export async function searchKnowledge(query: string, limit = 5): Promise<RetrievedChunk[]> {
  const response = await fetch(
    `${apiBase}/api/v1/rag/search?query=${encodeURIComponent(query)}&limit=${limit}`,
    withAuth({ cache: "no-store" }),
  )
  if (!response.ok) {
    return []
  }
  const payload = await response.json()
  return payload.items ?? []
}

export async function askCopilot(question: string): Promise<{ answer: string; citations: Array<Record<string, unknown>>; mode: string }> {
  const response = await fetch(`${apiBase}/api/v1/rag/ask?question=${encodeURIComponent(question)}`, withAuth({ method: "POST" }))
  if (!response.ok) {
    throw new Error("Copilot question failed")
  }
  return response.json()
}

export async function lookupCve(cveId: string): Promise<IntelCveResult> {
  const response = await fetch(`${apiBase}/api/v1/intel/cve/${encodeURIComponent(cveId)}`, withAuth({ cache: "no-store" }))
  if (!response.ok) {
    throw new Error("CVE lookup failed")
  }
  return response.json()
}

export async function fetchCaseAnomaly(caseId: string): Promise<AnomalyResult | null> {
  const response = await fetch(`${apiBase}/api/v1/anomalies/case/${caseId}`, withAuth({ cache: "no-store" }))
  if (!response.ok) {
    return null
  }
  return response.json()
}

export function getWebSocketUrl(token?: string | null): string {
  const url = new URL(apiBase)
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:"
  url.pathname = "/api/v1/ws/events"
  const storedToken = token ?? getStoredAuthToken()
  if (storedToken) {
    url.searchParams.set("token", storedToken)
  }
  return url.toString()
}

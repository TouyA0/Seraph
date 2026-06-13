const BASE = '/api'

export interface DetectResponse {
  value: string
  type: string
  candidates: string[]
}

export interface Finding {
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  category: string
  label: string
  source: string
  evidence?: string
}

export interface ConnectorResult {
  connector: string
  status: 'ok' | 'error' | 'unconfigured' | 'skipped'
  artifact: string
  artifact_type: string
  raw?: Record<string, unknown>
  findings: Finding[]
  latency_ms?: number
  error?: string
}

export interface AIReport {
  summary: string
  score: number
  score_rationale: string
  recommendation: string
  contradictions: string[]
}

export interface InvestigateResponse {
  id: string
  artifact: string
  type: string
  results: ConnectorResult[]
  total_findings: number
  ai_report?: AIReport
}

export async function detectArtifact(value: string): Promise<DetectResponse> {
  const r = await fetch(`${BASE}/detect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ value }),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function runInvestigation(value: string, type?: string): Promise<InvestigateResponse> {
  const r = await fetch(`${BASE}/investigate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ value, type }),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function getInvestigations(): Promise<unknown[]> {
  const r = await fetch(`${BASE}/investigations`)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function getConnectorSettings(): Promise<unknown> {
  const r = await fetch(`${BASE}/settings/connectors`)
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

export async function fetchAIReport(investigationId: string): Promise<AIReport> {
  const r = await fetch(`${BASE}/ai/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ investigation_id: investigationId }),
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json()
}

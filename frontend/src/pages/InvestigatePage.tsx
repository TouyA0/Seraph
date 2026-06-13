import { useEffect, useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { runInvestigation, fetchAIReport, type InvestigateResponse, type ConnectorResult, type Finding } from '@/utils/api'
import AIReportCard, { type AIReport } from '@/components/AIReportCard'
import ChatPanel from '@/components/ChatPanel'
import styles from './InvestigatePage.module.css'

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP', domain: 'Domaine', url: 'URL', hash: 'Hash',
  email: 'Email', cve: 'CVE', asn: 'ASN', unknown: '—',
}

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_LABEL: Record<string, string> = {
  critical: 'Critique', high: 'Élevé', medium: 'Moyen', low: 'Faible', info: 'Info',
}

const CAT_LABELS: Record<string, string> = {
  reputation: 'Réputation', exposure: 'Exposition', vulnerability: 'Vulnérabilité',
  network: 'Réseau', leak: 'Fuite', behavior: 'Comportement',
}

const CONNECTOR_LABELS: Record<string, string> = {
  shodan_internetdb: 'Shodan InternetDB',
  ip_api: 'ip-api.com',
  abuseipdb: 'AbuseIPDB',
  censys: 'Censys',
  shodan: 'Shodan',
  rdap: 'RDAP / Whois',
  crtsh: 'crt.sh',
  threatfox: 'ThreatFox',
  pulsedive: 'Pulsedive',
  virustotal: 'VirusTotal',
  otx: 'AlienVault OTX',
  urlscan: 'URLScan.io',
}

function SeverityBadge({ sev }: { sev: string }) {
  return <span className={`${styles.sevBadge} ${styles[`sev_${sev}`]}`}>{SEV_LABEL[sev] ?? sev}</span>
}

function SourceCard({ result }: { result: ConnectorResult }) {
  const [open, setOpen] = useState(false)
  const label = CONNECTOR_LABELS[result.connector] ?? result.connector
  const isUnconfigured = result.status === 'unconfigured'

  return (
    <div className={`${styles.sourceCard} ${isUnconfigured ? styles.sourceUnconfigured : ''}`}>
      <div className={styles.sourceHeader} onClick={() => !isUnconfigured && setOpen(!open)}>
        <div className={styles.sourceLeft}>
          <span className={`${styles.sourceDot} ${styles[`dot_${result.status}`]}`} />
          <span className={styles.sourceName}>{label}</span>
          {result.latency_ms !== undefined && !isUnconfigured && (
            <span className={styles.sourceLatency}>{result.latency_ms}ms</span>
          )}
        </div>
        <div className={styles.sourceRight}>
          {isUnconfigured && <span className={styles.unconfiguredLabel}>Clé manquante — Réglages</span>}
          {!isUnconfigured && result.findings.length > 0 && (
            <span className={styles.findingCount}>{result.findings.length} finding{result.findings.length > 1 ? 's' : ''}</span>
          )}
          {result.status === 'error' && <span className={styles.errLabel}>Erreur</span>}
          {!isUnconfigured && <span className={styles.chevron}>{open ? '▴' : '▾'}</span>}
        </div>
      </div>

      {open && !isUnconfigured && (
        <div className={styles.sourceBody}>
          {result.error && <div className={styles.errorMsg}>{result.error}</div>}
          {result.raw && (
            <pre className={styles.raw}>{JSON.stringify(result.raw, null, 2)}</pre>
          )}
        </div>
      )}
    </div>
  )
}

function FindingRow({ f }: { f: Finding }) {
  return (
    <div className={styles.findingRow}>
      <SeverityBadge sev={f.severity} />
      <div className={styles.findingContent}>
        <div className={styles.findingLabel}>{f.label}</div>
        {f.evidence && <div className={styles.findingEvidence}>{f.evidence}</div>}
      </div>
      <div className={styles.findingSource}>{CONNECTOR_LABELS[f.source] ?? f.source}</div>
    </div>
  )
}

export default function InvestigatePage() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const q = params.get('q') ?? ''
  const t = params.get('t') ?? undefined

  const [data, setData] = useState<InvestigateResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [aiReport, setAiReport] = useState<AIReport | null>(null)
  const [aiLoading, setAiLoading] = useState(false)
  const [activeTab, setActiveTab] = useState<'findings' | 'sources'>('findings')
  const [chatOpen, setChatOpen] = useState(false)

  useEffect(() => {
    if (!q) { navigate('/'); return }
    setLoading(true)
    setError(null)
    setAiReport(null)
    runInvestigation(q, t)
      .then((res) => {
        setData(res)
        setAiLoading(true)
        fetchAIReport(res.id)
          .then(setAiReport)
          .catch(() => null)
          .finally(() => setAiLoading(false))
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [q, t])

  const allFindings: Finding[] = data
    ? data.results.filter((r) => r.status !== 'unconfigured').flatMap((r) => r.findings)
    : []

  const byCategory: Record<string, Finding[]> = {}
  for (const f of allFindings) {
    if (!byCategory[f.category]) byCategory[f.category] = []
    byCategory[f.category].push(f)
  }
  for (const cat of Object.keys(byCategory)) {
    byCategory[cat].sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity))
  }
  const categories = Object.keys(byCategory).sort()

  const globalSev = allFindings.length
    ? SEV_ORDER.find((s) => allFindings.some((f) => f.severity === s)) ?? 'info'
    : 'info'

  const okSources = data?.results.filter((r) => r.status === 'ok').length ?? 0
  const totalSources = data?.results.filter((r) => r.status !== 'unconfigured').length ?? 0

  return (
    <div className={styles.root}>
      {/* Header */}
      <div className={styles.header}>
        <button className={styles.back} onClick={() => navigate('/')}>← Retour</button>
        <div className={styles.headerContent}>
          <div className={styles.artifact}>
            <span className={styles.artifactValue}>{q}</span>
            {data && (
              <span className={styles.artifactType}>{TYPE_LABELS[data.type] ?? data.type}</span>
            )}
          </div>
          {data && !loading && (
            <div className={styles.summary}>
              <SeverityBadge sev={globalSev} />
              <span className={styles.summaryText}>
                {allFindings.length} finding{allFindings.length > 1 ? 's' : ''} · {okSources}/{totalSources} sources
              </span>
            </div>
          )}
        </div>
      </div>

      {loading && (
        <div className={styles.loadingState}>
          <div className={styles.spinner} />
          <span>Interrogation des sources en parallèle…</span>
        </div>
      )}

      {error && (
        <div className={styles.errorState}>
          <strong>Erreur :</strong> {error}
        </div>
      )}

      {data && !loading && (
        <div className={styles.mainLayout}>
          <div className={styles.mainContent}>
            <div className={styles.tabs}>
              <button
                className={`${styles.tab} ${activeTab === 'findings' ? styles.tabActive : ''}`}
                onClick={() => setActiveTab('findings')}
              >
                Findings ({allFindings.length})
              </button>
              <button
                className={`${styles.tab} ${activeTab === 'sources' ? styles.tabActive : ''}`}
                onClick={() => setActiveTab('sources')}
              >
                Sources ({data.results.length})
              </button>
            </div>

            <div className={styles.content}>
              {activeTab === 'findings' && (
                <div className={styles.findingsPanel}>
                  {/* Rapport IA en tête */}
                  {aiLoading && (
                    <div className={styles.noAi} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div className={styles.spinner} style={{ width: 14, height: 14, borderWidth: 2 }} />
                      Synthèse IA en cours…
                    </div>
                  )}
                  {!aiLoading && aiReport && (
                    <AIReportCard report={aiReport} onChatOpen={() => setChatOpen(true)} />
                  )}
                  {!aiLoading && !aiReport && (
                    <div className={styles.noAi}>
                      IA non disponible — configurez Ollama pour obtenir une synthèse automatique.
                    </div>
                  )}

                  {categories.length === 0 && (
                    <div className={styles.empty}>Aucun finding — artefact inconnu des sources interrogées.</div>
                  )}
                  {categories.map((cat) => (
                    <div key={cat} className={styles.category}>
                      <div className={styles.categoryTitle}>{CAT_LABELS[cat] ?? cat}</div>
                      {byCategory[cat].map((f, i) => <FindingRow key={i} f={f} />)}
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'sources' && (
                <div className={styles.sourcesPanel}>
                  {data.results.map((r) => <SourceCard key={r.connector} result={r} />)}
                </div>
              )}
            </div>
          </div>

          {/* Chat latéral */}
          {chatOpen && data && (
            <ChatPanel
              investigationId={data.id}
              onClose={() => setChatOpen(false)}
            />
          )}
        </div>
      )}
    </div>
  )
}

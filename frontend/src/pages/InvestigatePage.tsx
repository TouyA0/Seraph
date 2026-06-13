import { useEffect, useState } from 'react'
import { useSearchParams, useNavigate } from 'react-router-dom'
import { runInvestigation, type InvestigateResponse, type ConnectorResult, type Finding } from '@/utils/api'
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
  bgpview_ip: 'BGPView',
  rdap: 'RDAP / Whois',
  crtsh: 'crt.sh',
  threatfox: 'ThreatFox',
  pulsedive: 'Pulsedive',
}

function SeverityBadge({ sev }: { sev: string }) {
  return <span className={`${styles.sevBadge} ${styles[`sev_${sev}`]}`}>{SEV_LABEL[sev] ?? sev}</span>
}

function SourceCard({ result }: { result: ConnectorResult }) {
  const [open, setOpen] = useState(false)
  const label = CONNECTOR_LABELS[result.connector] ?? result.connector

  return (
    <div className={styles.sourceCard}>
      <div className={styles.sourceHeader} onClick={() => setOpen(!open)}>
        <div className={styles.sourceLeft}>
          <span className={`${styles.sourceDot} ${styles[`dot_${result.status}`]}`} />
          <span className={styles.sourceName}>{label}</span>
          {result.latency_ms !== undefined && (
            <span className={styles.sourceLatency}>{result.latency_ms}ms</span>
          )}
        </div>
        <div className={styles.sourceRight}>
          {result.findings.length > 0 && (
            <span className={styles.findingCount}>{result.findings.length} finding{result.findings.length > 1 ? 's' : ''}</span>
          )}
          {result.status === 'error' && <span className={styles.errLabel}>Erreur</span>}
          <span className={styles.chevron}>{open ? '▴' : '▾'}</span>
        </div>
      </div>

      {open && (
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
  const [activeTab, setActiveTab] = useState<'findings' | 'sources'>('findings')

  useEffect(() => {
    if (!q) { navigate('/'); return }
    setLoading(true)
    setError(null)
    runInvestigation(q, t)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false))
  }, [q, t])

  // Group findings by category, sorted by severity
  const allFindings: Finding[] = data
    ? data.results.flatMap((r) => r.findings)
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
                {allFindings.length} finding{allFindings.length > 1 ? 's' : ''} ·{' '}
                {data.results.filter((r) => r.status === 'ok').length}/{data.results.length} sources
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
        <>
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
        </>
      )}
    </div>
  )
}

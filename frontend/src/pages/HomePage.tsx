import { useState } from 'react'
import styles from './HomePage.module.css'

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP',
  domain: 'Domaine',
  url: 'URL',
  hash: 'Hash',
  email: 'Email',
  cve: 'CVE',
  asn: 'ASN',
  unknown: '—',
}

interface DetectResult {
  value: string
  type: string
  candidates: string[]
}

export default function HomePage() {
  const [input, setInput] = useState('')
  const [detected, setDetected] = useState<DetectResult | null>(null)
  const [loading, setLoading] = useState(false)

  const handleChange = async (value: string) => {
    setInput(value)
    if (!value.trim()) {
      setDetected(null)
      return
    }
    setLoading(true)
    try {
      const res = await fetch('/api/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
      })
      if (res.ok) setDetected(await res.json())
    } catch {
      // backend pas encore dispo — mode offline
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={styles.root}>
      <div className={styles.center}>
        <div className={styles.title}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" style={{ marginBottom: 12 }}>
            <path d="M3.5 5.5 L12 10 L20.5 5.5" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M3.5 11 L12 15.5 L20.5 11" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.65" />
            <path d="M3.5 16.5 L12 21 L20.5 16.5" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.3" />
          </svg>
          <h1 className={styles.heading}>Coller un artefact</h1>
          <p className={styles.sub}>IP, domaine, hash, URL, email, CVE — Seraph détecte automatiquement.</p>
        </div>

        <div className={styles.searchWrap}>
          <input
            className={styles.search}
            placeholder="185.220.101.5 · evil.com · CVE-2024-3094 · …"
            value={input}
            onChange={(e) => handleChange(e.target.value)}
            autoFocus
            spellCheck={false}
          />
          {detected && detected.type !== 'unknown' && (
            <div className={styles.badge}>
              {TYPE_LABELS[detected.type] ?? detected.type}
            </div>
          )}
          {loading && <div className={styles.loader} />}
        </div>

        {detected && (
          <div className={styles.hint}>
            {detected.type === 'unknown'
              ? 'Type non reconnu — coller un bloc de texte pour extraire les IOC.'
              : `Type détecté : ${TYPE_LABELS[detected.type]}. Appuyez sur Entrée pour lancer l'investigation.`}
          </div>
        )}
      </div>
    </div>
  )
}

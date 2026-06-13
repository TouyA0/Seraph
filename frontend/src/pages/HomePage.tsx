import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { detectArtifact } from '@/utils/api'
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

export default function HomePage() {
  const [input, setInput] = useState('')
  const [detectedType, setDetectedType] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()
  const debounceRef = useRef<ReturnType<typeof setTimeout>>()

  const handleChange = (value: string) => {
    setInput(value)
    setDetectedType(null)
    clearTimeout(debounceRef.current)
    if (!value.trim()) return
    debounceRef.current = setTimeout(async () => {
      try {
        const res = await detectArtifact(value)
        setDetectedType(res.type)
      } catch {
        // backend pas encore dispo
      }
    }, 300)
  }

  const handleSubmit = async () => {
    if (!input.trim() || loading) return
    setLoading(true)
    try {
      navigate(`/investigate?q=${encodeURIComponent(input.trim())}${detectedType ? `&t=${detectedType}` : ''}`)
    } finally {
      setLoading(false)
    }
  }

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSubmit()
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
            onKeyDown={handleKey}
            autoFocus
            spellCheck={false}
          />
          {detectedType && detectedType !== 'unknown' && (
            <div className={styles.badge}>{TYPE_LABELS[detectedType] ?? detectedType}</div>
          )}
          {loading && <div className={styles.loader} />}
        </div>

        <div className={styles.actions}>
          <button
            className={styles.btnPrimary}
            onClick={handleSubmit}
            disabled={!input.trim() || loading}
          >
            Lancer l'investigation
          </button>
        </div>

        {detectedType && (
          <div className={styles.hint}>
            {detectedType === 'unknown'
              ? 'Type non reconnu — coller un bloc de texte pour extraire les IOC.'
              : `Type détecté : ${TYPE_LABELS[detectedType]}. Appuyez sur Entrée pour lancer.`}
          </div>
        )}
      </div>
    </div>
  )
}

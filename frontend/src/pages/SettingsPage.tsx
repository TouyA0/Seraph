import { useEffect, useState } from 'react'
import styles from './SettingsPage.module.css'

interface ConnectorInfo {
  name: string
  label: string
  requires_key: boolean
  is_active: boolean
  configured: boolean
  supported_types: string[]
  key_url?: string
}

interface SettingsData {
  connectors: ConnectorInfo[]
  cache: { redis: boolean }
}

const TYPE_LABELS: Record<string, string> = {
  ip: 'IP', domain: 'Domaine', url: 'URL', hash: 'Hash',
  email: 'Email', cve: 'CVE', asn: 'ASN',
}

export default function SettingsPage() {
  const [data, setData] = useState<SettingsData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/settings/connectors')
      .then((r) => r.json())
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className={styles.loading}>Chargement…</div>
  if (!data) return <div className={styles.loading}>Erreur de chargement.</div>

  const free = data.connectors.filter((c) => !c.requires_key)
  const keyed = data.connectors.filter((c) => c.requires_key)

  return (
    <div className={styles.root}>
      <div className={styles.content}>
        <h1 className={styles.title}>Réglages</h1>

        {/* Statut infra */}
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Infrastructure</div>
          <div className={styles.infraGrid}>
            <div className={styles.infraCard}>
              <span className={`${styles.dot} ${data.cache.redis ? styles.dotOk : styles.dotErr}`} />
              <div>
                <div className={styles.infraName}>Cache Redis</div>
                <div className={styles.infraSub}>{data.cache.redis ? 'Connecté' : 'Non disponible'}</div>
              </div>
            </div>
          </div>
        </div>

        {/* Sources gratuites */}
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Sources gratuites — actives dès le lancement</div>
          <div className={styles.connectorList}>
            {free.map((c) => (
              <ConnectorRow key={c.name} connector={c} />
            ))}
          </div>
        </div>

        {/* Sources à clé */}
        <div className={styles.section}>
          <div className={styles.sectionTitle}>Sources à clé — à configurer dans <code>.env</code></div>
          <p className={styles.sectionHint}>
            Ajoutez les clés dans le fichier <code>.env</code> à la racine du projet, puis relancez <code>docker compose up</code>.
          </p>
          <div className={styles.connectorList}>
            {keyed.map((c) => (
              <ConnectorRow key={c.name} connector={c} />
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}

function ConnectorRow({ connector: c }: { connector: ConnectorInfo }) {
  return (
    <div className={`${styles.connectorRow} ${!c.configured ? styles.connectorUnconfigured : ''}`}>
      <div className={styles.connectorLeft}>
        <span className={`${styles.dot} ${c.configured ? styles.dotOk : styles.dotGray}`} />
        <div>
          <div className={styles.connectorName}>{c.label}</div>
          <div className={styles.connectorTypes}>
            {c.supported_types.map((t) => (
              <span key={t} className={styles.typeTag}>{TYPE_LABELS[t] ?? t}</span>
            ))}
            {c.is_active && <span className={styles.activeTag}>Actif</span>}
          </div>
        </div>
      </div>
      <div className={styles.connectorRight}>
        {c.configured ? (
          <span className={styles.statusOk}>Configuré</span>
        ) : c.requires_key ? (
          <a
            className={styles.getKeyLink}
            href={c.key_url ?? '#'}
            target="_blank"
            rel="noreferrer"
          >
            Obtenir une clé →
          </a>
        ) : (
          <span className={styles.statusOk}>Actif</span>
        )}
      </div>
    </div>
  )
}

import styles from './AIReportCard.module.css'

export interface AIReport {
  summary: string
  score: number
  score_rationale: string
  recommendation: string
  contradictions: string[]
}

const RECO_LABEL: Record<string, string> = {
  bloquer: 'Bloquer',
  surveiller: 'Surveiller',
  ignorer: 'Ignorer',
  approfondir: 'Approfondir',
}

const RECO_CLASS: Record<string, string> = {
  bloquer: 'recoCrit',
  surveiller: 'recoHigh',
  ignorer: 'recoOk',
  approfondir: 'recoMed',
}

function ScoreBar({ score }: { score: number }) {
  const pct = (score / 10) * 100
  const color =
    score >= 8 ? 'var(--sev-crit)' :
    score >= 6 ? 'var(--sev-high)' :
    score >= 4 ? 'var(--sev-med)' :
    score >= 2 ? 'var(--sev-low)' : 'var(--ok)'

  return (
    <div className={styles.scoreWrap}>
      <div className={styles.scoreNum} style={{ color }}>{score}<span className={styles.scoreMax}>/10</span></div>
      <div className={styles.bar}>
        <div className={styles.barFill} style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  )
}

interface Props {
  report: AIReport
  onChatOpen: () => void
}

export default function AIReportCard({ report, onChatOpen }: Props) {
  const recoClass = RECO_CLASS[report.recommendation] ?? 'recoMed'

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <div className={styles.iaLabel}>
            <span className={styles.iaDot} />
            Synthèse IA
          </div>
        </div>
        <div className={styles.headerRight}>
          <span className={`${styles.reco} ${styles[recoClass]}`}>
            {RECO_LABEL[report.recommendation] ?? report.recommendation}
          </span>
          <button className={styles.chatBtn} onClick={onChatOpen}>
            Poser une question →
          </button>
        </div>
      </div>

      <div className={styles.body}>
        <div className={styles.summary}>{report.summary}</div>

        <div className={styles.meta}>
          <ScoreBar score={report.score} />
          <div className={styles.rationale}>{report.score_rationale}</div>
        </div>

        {report.contradictions.length > 0 && (
          <div className={styles.contradictions}>
            <div className={styles.contraTitle}>Contradictions détectées</div>
            {report.contradictions.map((c, i) => (
              <div key={i} className={styles.contraItem}>⚠ {c}</div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

import { Outlet, NavLink } from 'react-router-dom'
import styles from './Layout.module.css'

const NAV = [
  { to: '/', label: 'Investigation' },
  { to: '/history', label: 'Historique' },
  { to: '/tools', label: 'Boîte à outils' },
  { to: '/settings', label: 'Réglages' },
]

export default function Layout() {
  return (
    <div className={styles.root}>
      <aside className={styles.sidebar}>
        <div className={styles.logo}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
            <path d="M3.5 5.5 L12 10 L20.5 5.5" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            <path d="M3.5 11 L12 15.5 L20.5 11" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.65" />
            <path d="M3.5 16.5 L12 21 L20.5 16.5" stroke="var(--accent)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" opacity="0.3" />
          </svg>
          <div className={styles.logoText}>
            <span className={styles.logoName}>seraph</span>
            <span className={styles.logoVersion}>v0.1</span>
          </div>
        </div>

        <div className={styles.navLabel}>Modules</div>
        <nav className={styles.nav}>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                [styles.navItem, isActive ? styles.navItemActive : ''].join(' ')
              }
            >
              <span className={styles.navDot} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div style={{ flex: 1 }} />

        <div className={styles.aiStatus}>
          <div className={styles.aiStatusHeader}>
            <span className={styles.aiDot} />
            <span style={{ fontSize: 12, fontWeight: 600 }}>IA locale</span>
          </div>
          <div className={styles.aiStatusLine}>Non configurée</div>
          <div className={styles.aiStatusNote}>Aucune donnée ne sort.</div>
        </div>
      </aside>

      <main className={styles.main}>
        <Outlet />
      </main>
    </div>
  )
}

import './ActivityBar.css'

const NAV_ITEMS = [
  {
    id: 'scanner',
    label: 'Scanner / Analysis',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="11" cy="11" r="7" />
        <line x1="21" y1="21" x2="16.65" y2="16.65" />
        <text x="7.5" y="13.5" fontSize="4.5" fill="currentColor" stroke="none" fontFamily="monospace" fontWeight="bold">01</text>
      </svg>
    ),
  },
  {
    id: 'reporting',
    label: 'Reporting',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2L4 6v6c0 5.55 3.84 10.74 8 12 4.16-1.26 8-6.45 8-12V6L12 2z" />
        <polyline points="9,12 11,14 15,10" />
        <line x1="8" y1="17" x2="11" y2="17" />
        <line x1="13" y1="17" x2="16" y2="17" />
      </svg>
    ),
  },
  {
    id: 'code-analysis',
    label: 'Code / APK Analysis',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="4,7 1,9 4,11"/>
        <polyline points="20,7 23,9 20,11"/>
        <line x1="14" y1="3" x2="10" y2="21"/>
        <circle cx="12" cy="9" r="2.5" fill="currentColor" stroke="none" opacity="0.6"/>
        <path d="M8 17h8" strokeWidth="1"/>
      </svg>
    ),
  },
  {
    id: 'orchestration',
    label: 'Orchestration',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="2" width="8" height="8" rx="1.5" />
        <rect x="14" y="2" width="8" height="8" rx="1.5" />
        <rect x="2" y="14" width="8" height="8" rx="1.5" />
        <rect x="14" y="14" width="8" height="8" rx="1.5" />
        <circle cx="18" cy="18" r="2.2" fill="currentColor" stroke="none" opacity="0.8" />
        <path d="M18 15.8v-.8M20.2 18h.8M18 20.2v.8M15.8 18h-.8" stroke="var(--bg-primary)" strokeWidth="0.8" />
      </svg>
    ),
  },
]

const BOTTOM_ITEMS = [
  {
    id: 'settings',
    label: 'Settings',
    icon: (
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
      </svg>
    ),
  },
]

export default function ActivityBar({ activeView, setActiveView }) {
  return (
    <aside className="activity-bar">
      <div className="activity-bar__logo" title="AlphaWeb Platform">
        <span className="activity-bar__logo-glyph">⍺</span>
      </div>

      <nav className="activity-bar__nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={`ab-btn ${activeView === item.id ? 'ab-btn--active' : ''}`}
            title={item.label}
            onClick={() => setActiveView(item.id)}
          >
            <span className="ab-btn__icon">{item.icon}</span>
            <span className="ab-btn__tooltip">{item.label}</span>
          </button>
        ))}
      </nav>

      <div className="activity-bar__bottom">
        {BOTTOM_ITEMS.map((item) => (
          <button key={item.id} className="ab-btn" title={item.label}>
            <span className="ab-btn__icon">{item.icon}</span>
          </button>
        ))}
      </div>
    </aside>
  )
}

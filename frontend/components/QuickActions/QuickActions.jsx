import './QuickActions.css'

export default function QuickActions() {
  return (
    <section className="quick-actions">
      <div className="qa-header">
        <span className="qa-title">QUICK ACTIONS</span>
        <span className="qa-subtitle">Mobile_Analysis</span>
      </div>

      <div className="qa-body">
        {/* Create New Folder */}
        <button className="qa-btn qa-btn--sec">
          <span className="qa-btn__icon">
            <svg viewBox="0 0 22 22" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M2 5.5A1.5 1.5 0 0 1 3.5 4h4l1.5 1.5H18A1.5 1.5 0 0 1 19.5 7v9a1.5 1.5 0 0 1-1.5 1.5H3.5A1.5 1.5 0 0 1 2 16V5.5z" />
              <line x1="11" y1="10" x2="11" y2="15" />
              <line x1="8.5" y1="12.5" x2="13.5" y2="12.5" />
            </svg>
          </span>
          <div className="qa-btn__text">
            <span className="qa-btn__label">Create New Folder</span>
            <span className="qa-btn__sub">Organise workspace</span>
          </div>
        </button>

        {/* Add Code Snippet */}
        <button className="qa-btn qa-btn--sec">
          <span className="qa-btn__icon">
            <svg viewBox="0 0 22 22" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 3.5h9l4 4V18a.5.5 0 0 1-.5.5H4a.5.5 0 0 1-.5-.5V4a.5.5 0 0 1 .5-.5z" />
              <path d="M13 3.5V8h4" />
              <path d="M7.5 12l2 2-2 2" />
              <line x1="12" y1="14" x2="14.5" y2="14" />
            </svg>
          </span>
          <div className="qa-btn__text">
            <span className="qa-btn__label">Add Code Snippet</span>
            <span className="qa-btn__sub">Attach analysis script</span>
          </div>
        </button>

        {/* Upload APK — primary CTA */}
        <button className="qa-btn qa-btn--primary">
          <span className="qa-btn__icon qa-btn__icon--primary">
            <svg viewBox="0 0 22 22" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
              <rect x="6" y="1.5" width="10" height="19" rx="2" />
              <line x1="9" y1="18.5" x2="13" y2="18.5" />
              <line x1="11" y1="7" x2="11" y2="13" />
              <polyline points="8.5,9.5 11,7 13.5,9.5" />
            </svg>
          </span>
          <div className="qa-btn__text">
            <span className="qa-btn__label">Upload APK File</span>
            <span className="qa-btn__sub">Drop .apk to analyze</span>
          </div>
          <span className="qa-btn__badge">NEW</span>
        </button>
      </div>
    </section>
  )
}

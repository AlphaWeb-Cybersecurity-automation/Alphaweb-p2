import './StatusBar.css'

const SCAN_PCT = 20

function langFromFile(name) {
  if (!name) return '—'
  const ext = name.split('.').pop().toLowerCase()
  return { yaml: 'YAML', json: 'JSON', html: 'HTML', log: 'LOG', apk: 'APK', txt: 'TEXT', pdf: 'PDF' }[ext] ?? ext.toUpperCase()
}

export default function StatusBar({ activeFile, termVisible, onReopenTerminal }) {
  const lang = langFromFile(activeFile)

  return (
    <footer className="status-bar">
      {/* Left */}
      <div className="sb-group sb-group--left">
        <span className="sb-seg sb-seg--clean" title="Errors / Warnings">
          <span className="sb-ok">✓</span><span>0</span>
          <span className="sb-warn">⚠</span><span>0</span>
        </span>

        <span className="sb-div" />

        <span className="sb-seg" title="AI Model">
          <span className="sb-key">AI Model:</span>
          <span className="sb-val sb-val--gold">Fine-tuned-Cyber-LM</span>
          <span className="sb-badge sb-badge--idle">Idle</span>
        </span>

        <span className="sb-div" />

        <span className="sb-seg" title="Current Project">
          <span className="sb-key">Project:</span>
          <span className="sb-val">Mobile_Analysis</span>
        </span>

        <span className="sb-div" />

        <span className="sb-seg" title="Region">
          <span className="sb-key">Region:</span>
          <span className="sb-val sb-val--cyan">Hyderabad</span>
        </span>

        {/* Re-open terminal button when hidden */}
        {!termVisible && (
          <>
            <span className="sb-div" />
            <button
              className="sb-seg sb-seg--btn"
              title="Open Terminal"
              onClick={onReopenTerminal}
            >
              <span className="sb-val sb-val--cyan">⌨ TERMINAL</span>
            </button>
          </>
        )}
      </div>

      {/* Centre */}
      <div className="sb-group sb-group--center">
        <span className="sb-seg" title="Scan Progress">
          <span className="sb-key">Scan Progress:</span>
          <span className="sb-val sb-val--gold">{SCAN_PCT}%</span>
          <span className="sb-bar">
            <span className="sb-bar__fill" style={{ width: `${SCAN_PCT}%` }} />
          </span>
        </span>
      </div>

      {/* Right */}
      <div className="sb-group sb-group--right">
        {activeFile && (
          <>
            <span className="sb-seg" title="Active file">
              <span className="sb-val sb-val--dim">{activeFile}</span>
            </span>
            <span className="sb-div" />
          </>
        )}
        <span className="sb-seg" title="Cursor position">
          <span className="sb-val sb-val--dim">Ln 22, Col 15</span>
        </span>
        <span className="sb-div" />
        <span className="sb-seg" title="Language">
          <span className="sb-val sb-val--cyan">{lang}</span>
        </span>
        <span className="sb-div" />
        <span className="sb-seg" title="Encoding">
          <span className="sb-val sb-val--dim">UTF-8</span>
        </span>
      </div>
    </footer>
  )
}

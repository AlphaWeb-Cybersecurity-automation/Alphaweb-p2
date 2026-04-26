import { useState, useRef } from 'react'
import './StatusBar.css'

const SCAN_PCT = 20

const TOOLS = [
  'nmap', 'masscan', 'nikto', 'sqlmap', 'ffuf', 'gobuster',
  'john', 'hydra', 'curl', 'tcpdump', 'nuclei', 'hashcat',
  'gitleaks', 'theharvester', 'sublist3r', 'testssl', 'wapiti',
  'wpscan', 'cewl', 'trivy', 'amass', 'commix', 'searchsploit',
  'subdominator', 'httpx',
]

function langFromFile(name) {
  if (!name) return '—'
  const ext = name.split('.').pop().toLowerCase()
  return { yaml: 'YAML', json: 'JSON', html: 'HTML', log: 'LOG', apk: 'APK', txt: 'TEXT', pdf: 'PDF' }[ext] ?? ext.toUpperCase()
}

function ToolsDropup() {
  const [open, setOpen] = useState(false)
  const btnRef = useRef(null)
  const [pos, setPos] = useState({ bottom: 0, left: 0 })

  function handleClick() {
    if (!open && btnRef.current) {
      const r = btnRef.current.getBoundingClientRect()
      setPos({ bottom: window.innerHeight - r.top, left: r.left + r.width / 2 })
    }
    setOpen(o => !o)
  }

  return (
    <span className="sb-dropup-wrap">
      {open && (
        <div
          className="sb-dropup"
          style={{ bottom: pos.bottom, left: pos.left, transform: 'translateX(-50%)' }}
        >
          <div className="sb-dropup__header">{TOOLS.length} Tools Available</div>
          <div className="sb-dropup__list">
            {TOOLS.map(t => (
              <div key={t} className="sb-dropup__item">{t}</div>
            ))}
          </div>
        </div>
      )}
      <button
        ref={btnRef}
        className="sb-seg sb-seg--btn sb-dropup-trigger"
        title="Available tools"
        onClick={handleClick}
      >
        <span className="sb-val sb-val--cyan">⚙ {TOOLS.length} TOOLS</span>
        <span className="sb-val sb-val--dim">{open ? ' ▼' : ' ▲'}</span>
      </button>
    </span>
  )
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
          <span className="sb-val sb-val--gold">AlphaLLM</span>
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

        <span className="sb-div" />

        <ToolsDropup />
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

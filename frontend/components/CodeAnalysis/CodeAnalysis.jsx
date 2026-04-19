import { useState, useRef, useCallback } from 'react'
import './CodeAnalysis.css'

// ── Constants ─────────────────────────────────────────────────────────────────

const SEV_COLOR = {
  critical: '#e06c75',
  high:     '#d19a66',
  medium:   '#e5c07b',
  low:      '#98c379',
}

const SEV_BG = {
  critical: 'rgba(224,108,117,0.13)',
  high:     'rgba(209,154,102,0.13)',
  medium:   'rgba(229,192,123,0.13)',
  low:      'rgba(152,195,121,0.13)',
}

const LANGUAGES = [
  { value: '',           label: 'Auto-detect' },
  { value: 'python',     label: 'Python'      },
  { value: 'javascript', label: 'JavaScript'  },
  { value: 'java',       label: 'Java'        },
  { value: 'php',        label: 'PHP'         },
  { value: 'go',         label: 'Go'          },
]

const ACCEPT_EXTS = '.apk,.zip,.py,.js,.ts,.jsx,.tsx,.java,.php,.go'

function extIcon(name) {
  const ext = name?.split('.').pop()?.toLowerCase()
  return { apk: '📱', zip: '📦', py: '🐍', js: '⚡', ts: '⚡', java: '☕', php: '🐘', go: '🐹' }[ext] ?? '·'
}

function formatBytes(n) {
  if (n < 1024)      return `${n} B`
  if (n < 1048576)   return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1048576).toFixed(1)} MB`
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SeverityBar({ result }) {
  const total = result.total_vulnerabilities
  return (
    <div className="ca-sev-bar">
      {['critical', 'high', 'medium', 'low'].map(s => (
        <div
          key={s}
          className="ca-sev-cell"
          style={{ borderColor: SEV_COLOR[s], background: SEV_BG[s] }}
        >
          <span className="ca-sev-count" style={{ color: SEV_COLOR[s] }}>{result[s]}</span>
          <span className="ca-sev-label">{s}</span>
        </div>
      ))}
      <div className="ca-sev-cell ca-sev-cell--total">
        <span className="ca-sev-count">{total}</span>
        <span className="ca-sev-label">total</span>
      </div>
    </div>
  )
}

function VulnCard({ v, idx }) {
  const [expanded, setExpanded] = useState(false)
  const sev = v.severity || 'low'
  return (
    <div
      className="ca-vuln"
      style={{ borderLeftColor: SEV_COLOR[sev] }}
      onClick={() => setExpanded(e => !e)}
    >
      <div className="ca-vuln__head">
        <div className="ca-vuln__meta">
          <span className="ca-vuln__badge" style={{ background: SEV_BG[sev], color: SEV_COLOR[sev] }}>
            {sev}
          </span>
          <span className="ca-vuln__type">{v.type ?? 'unknown'}</span>
          {v.cwe && <span className="ca-vuln__cwe">{v.cwe}</span>}
        </div>
        <div className="ca-vuln__loc">
          {v.file && <span className="ca-vuln__file" title={v.file}>{v.file.split('/').pop()}</span>}
          {v.line && <span className="ca-vuln__line">:{v.line}</span>}
          <span className="ca-vuln__chevron">{expanded ? '▼' : '▶'}</span>
        </div>
      </div>

      <p className="ca-vuln__issue">{v.issue}</p>

      {expanded && (
        <div className="ca-vuln__detail">
          {v.code_snippet && (
            <code className="ca-vuln__snippet">{v.code_snippet}</code>
          )}
          {v.fix && (
            <div className="ca-vuln__fix">
              <span className="ca-vuln__fix-label">Fix</span>
              <span className="ca-vuln__fix-text">{v.fix}</span>
            </div>
          )}
          {v.rule_id && (
            <div className="ca-vuln__rule">Rule: {v.rule_id}</div>
          )}
        </div>
      )}
    </div>
  )
}

function FileInventory({ inv }) {
  if (!inv) return null
  return (
    <div className="ca-inventory">
      <div className="ca-inventory__title">APK CONTENTS</div>
      <div className="ca-inventory__stats">
        <span>{inv.total_files} files</span>
        {inv.has_dex     && <span className="ca-inv-tag">DEX</span>}
        {inv.has_smali   && <span className="ca-inv-tag">smali</span>}
        {inv.has_kotlin  && <span className="ca-inv-tag">Kotlin</span>}
        {inv.has_native_libs && <span className="ca-inv-tag ca-inv-tag--warn">native .so</span>}
      </div>
      {inv.by_extension && (
        <div className="ca-inventory__exts">
          {Object.entries(inv.by_extension).slice(0, 8).map(([ext, count]) => (
            <span key={ext} className="ca-inv-ext">.{ext} <em>{count}</em></span>
          ))}
        </div>
      )}
    </div>
  )
}

function ResultsPane({ result, status, error }) {
  const [filter, setFilter] = useState('all')

  if (status === 'idle') {
    return (
      <div className="ca-results ca-results--empty">
        <div className="ca-empty-icon">⍺</div>
        <p className="ca-empty-title">Static Code Analysis</p>
        <p className="ca-empty-sub">
          Paste code or upload a file, then click Analyze.<br />
          Supports Python · JS · Java · PHP · Go · APK · ZIP
        </p>
        <div className="ca-empty-tools">
          <span>Bandit</span><span>ESLint</span><span>Semgrep</span><span>Pattern rules</span><span>APK scanner</span>
        </div>
      </div>
    )
  }

  if (status === 'analyzing') {
    return (
      <div className="ca-results ca-results--empty">
        <div className="ca-spinner" />
        <p className="ca-empty-sub">Running analysis…</p>
      </div>
    )
  }

  if (status === 'error') {
    return (
      <div className="ca-results ca-results--empty">
        <p style={{ color: 'var(--red)', fontSize: 12 }}>{error}</p>
      </div>
    )
  }

  if (!result) return null

  const vulns = result.vulnerabilities || []
  const shown = filter === 'all'
    ? vulns
    : vulns.filter(v => v.severity === filter)

  const lang = result.language
    ? <span className="ca-lang-badge">{result.language.toUpperCase()}</span>
    : null

  const fileType = result.file_type
  const isClean  = result.total_vulnerabilities === 0

  return (
    <div className="ca-results">
      {/* header */}
      <div className="ca-results__hdr">
        <div className="ca-results__title-row">
          <span className="ca-results__label">
            {fileType === 'apk' ? '📱 APK Analysis' : fileType === 'zip' ? '📦 ZIP Analysis' : '⚡ Code Analysis'}
          </span>
          {lang}
          {result.semgrep_used && <span className="ca-semgrep-badge">+Semgrep</span>}
        </div>
        {result.filename && (
          <span className="ca-results__filename">{result.filename}</span>
        )}
        {result.files_analyzed?.length > 0 && (
          <span className="ca-results__filename">
            {result.files_analyzed.length} file{result.files_analyzed.length > 1 ? 's' : ''} analyzed
          </span>
        )}
      </div>

      {/* APK file inventory */}
      {fileType === 'apk' && result.file_inventory && (
        <FileInventory inv={result.file_inventory} />
      )}

      {/* severity bar */}
      <SeverityBar result={result} />

      {isClean && (
        <div className="ca-clean">
          <span style={{ color: 'var(--green)' }}>✓</span> No vulnerabilities detected
        </div>
      )}

      {/* filter tabs */}
      {!isClean && (
        <div className="ca-filter-row">
          {['all', 'critical', 'high', 'medium', 'low'].map(f => {
            const cnt = f === 'all' ? vulns.length : result[f]
            if (cnt === 0 && f !== 'all') return null
            return (
              <button
                key={f}
                className={`ca-filter-btn ${filter === f ? 'ca-filter-btn--active' : ''}`}
                style={filter === f ? { borderColor: SEV_COLOR[f] ?? 'var(--cyan)', color: SEV_COLOR[f] ?? 'var(--cyan)' } : {}}
                onClick={() => setFilter(f)}
              >
                {f} {cnt > 0 && <em>{cnt}</em>}
              </button>
            )
          })}
        </div>
      )}

      {/* vuln list */}
      <div className="ca-vuln-list">
        {shown.map((v, i) => <VulnCard key={i} v={v} idx={i} />)}
      </div>
    </div>
  )
}

// ── Code input panel ──────────────────────────────────────────────────────────

function CodeInputPanel({ onAnalyze, loading }) {
  const [code,     setCode]     = useState('')
  const [language, setLanguage] = useState('')

  function submit() {
    if (!code.trim()) return
    onAnalyze({ mode: 'code', code, language: language || null })
  }

  return (
    <div className="ca-input-panel">
      <div className="ca-input-panel__toolbar">
        <span className="ca-panel-label">PASTE CODE</span>
        <select
          className="ca-lang-select"
          value={language}
          onChange={e => setLanguage(e.target.value)}
        >
          {LANGUAGES.map(l => (
            <option key={l.value} value={l.value}>{l.label}</option>
          ))}
        </select>
      </div>

      <textarea
        className="ca-textarea"
        spellCheck={false}
        placeholder={`Paste your code here…\n\nSupports: Python, JavaScript, TypeScript, Java, PHP, Go`}
        value={code}
        onChange={e => setCode(e.target.value)}
      />

      <div className="ca-input-panel__footer">
        <span className="ca-char-count">{code.length.toLocaleString()} chars</span>
        <button
          className="ca-analyze-btn"
          disabled={!code.trim() || loading}
          onClick={submit}
        >
          {loading ? <><span className="ca-btn-spinner" /> Analyzing…</> : 'Analyze Code →'}
        </button>
      </div>
    </div>
  )
}

// ── File upload panel ─────────────────────────────────────────────────────────

function FileUploadPanel({ onAnalyze, loading }) {
  const [file,     setFile]     = useState(null)
  const [dragging, setDragging] = useState(false)
  const [language, setLanguage] = useState('')
  const inputRef = useRef(null)

  const handleFiles = useCallback((fileList) => {
    if (fileList.length > 0) setFile(fileList[0])
  }, [])

  function handleDrop(e) {
    e.preventDefault()
    setDragging(false)
    if (e.dataTransfer.files.length) handleFiles(e.dataTransfer.files)
  }

  function submit() {
    if (!file) return
    onAnalyze({ mode: 'file', file, language: language || null })
  }

  return (
    <div className="ca-input-panel">
      <div className="ca-input-panel__toolbar">
        <span className="ca-panel-label">UPLOAD FILE</span>
        <select
          className="ca-lang-select"
          value={language}
          onChange={e => setLanguage(e.target.value)}
          disabled={file && ['apk','zip'].includes(file.name.split('.').pop().toLowerCase())}
        >
          {LANGUAGES.map(l => (
            <option key={l.value} value={l.value}>{l.label}</option>
          ))}
        </select>
      </div>

      <div
        className={`ca-dropzone ${dragging ? 'ca-dropzone--active' : ''} ${file ? 'ca-dropzone--filled' : ''}`}
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => !file && inputRef.current?.click()}
        role="button"
        tabIndex={0}
        onKeyDown={e => e.key === 'Enter' && !file && inputRef.current?.click()}
      >
        {!file ? (
          <>
            <div className="ca-dropzone__icon">⬆</div>
            <p className="ca-dropzone__title">Drop file here or click to browse</p>
            <p className="ca-dropzone__sub">APK · ZIP · .py · .js · .java · .php · .go</p>
          </>
        ) : (
          <div className="ca-file-preview">
            <span className="ca-file-preview__icon">{extIcon(file.name)}</span>
            <div className="ca-file-preview__info">
              <span className="ca-file-preview__name">{file.name}</span>
              <span className="ca-file-preview__size">{formatBytes(file.size)}</span>
            </div>
            <button
              className="ca-file-preview__remove"
              title="Remove"
              onClick={e => { e.stopPropagation(); setFile(null) }}
            >
              ×
            </button>
          </div>
        )}
      </div>

      {file && (
        <div className="ca-input-panel__footer">
          <button
            className="ca-browse-btn"
            onClick={() => inputRef.current?.click()}
          >
            Change file
          </button>
          <button
            className="ca-analyze-btn"
            disabled={loading}
            onClick={submit}
          >
            {loading ? <><span className="ca-btn-spinner" /> Analyzing…</> : 'Analyze File →'}
          </button>
        </div>
      )}

      <input
        ref={inputRef}
        type="file"
        accept={ACCEPT_EXTS}
        style={{ display: 'none' }}
        onChange={e => { if (e.target.files?.length) { handleFiles(e.target.files); e.target.value = '' } }}
      />
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function CodeAnalysis() {
  const [mode,    setMode]    = useState('code')   // 'code' | 'file'
  const [status,  setStatus]  = useState('idle')   // 'idle' | 'analyzing' | 'done' | 'error'
  const [result,  setResult]  = useState(null)
  const [error,   setError]   = useState(null)

  async function runAnalysis({ mode: m, code, file, language }) {
    setStatus('analyzing')
    setResult(null)
    setError(null)

    try {
      let res, data

      if (m === 'code') {
        res = await fetch('/api/analyze-code', {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify({ code, language, filename: null }),
        })
      } else {
        const form = new FormData()
        form.append('file', file)
        if (language) form.append('language', language)
        res = await fetch('/api/static-analyze', {
          method: 'POST',
          body:   form,
        })
      }

      data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? `HTTP ${res.status}`)
      setResult(data)
      setStatus('done')
    } catch (e) {
      setError(e.message)
      setStatus('error')
    }
  }

  const loading = status === 'analyzing'

  return (
    <section className="code-analysis">
      {/* ── Header ── */}
      <div className="ca-header">
        <div className="ca-header__left">
          <span className="ca-header__title">STATIC ANALYSIS</span>
          <span className="ca-header__sub">Rule-based vulnerability scanner</span>
        </div>
        <div className="ca-mode-toggle">
          <button
            className={`ca-mode-btn ${mode === 'code' ? 'ca-mode-btn--active' : ''}`}
            onClick={() => setMode('code')}
          >
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <polyline points="4,6 1,8 4,10"/>
              <polyline points="12,6 15,8 12,10"/>
              <line x1="9" y1="3" x2="7" y2="13"/>
            </svg>
            Code
          </button>
          <button
            className={`ca-mode-btn ${mode === 'file' ? 'ca-mode-btn--active' : ''}`}
            onClick={() => setMode('file')}
          >
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
              <path d="M9 1H3a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h10a1 1 0 0 0 1-1V6L9 1z"/>
              <polyline points="9,1 9,6 14,6"/>
            </svg>
            File / APK
          </button>
        </div>
        {status === 'done' && (
          <button className="ca-clear-btn" onClick={() => { setStatus('idle'); setResult(null) }}>
            ⌫ Clear
          </button>
        )}
      </div>

      {/* ── Body ── */}
      <div className="ca-body">
        {/* Left: input */}
        <div className="ca-left">
          {mode === 'code'
            ? <CodeInputPanel  onAnalyze={runAnalysis} loading={loading} />
            : <FileUploadPanel onAnalyze={runAnalysis} loading={loading} />
          }
        </div>

        {/* Right: results */}
        <div className="ca-right">
          <ResultsPane result={result} status={status} error={error} />
        </div>
      </div>
    </section>
  )
}

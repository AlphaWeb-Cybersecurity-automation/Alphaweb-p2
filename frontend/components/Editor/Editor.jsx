import { useState, useEffect } from 'react'
import './Editor.css'

// ── YAML content ─────────────────────────────────────────────────────────────
const YAML = [
  [{ t: 'comment', v: '# AlphaWeb Dynamic Tool Execution Plan' }],
  [{ t: 'comment', v: '# Target: android_main_apk.apk' }],
  [{ t: 'comment', v: '# Analysis Profile: mobile_security_full' }],
  [],
  [{ t: 'key', v: 'task_id' },      { t: 'colon', v: ': ' }, { t: 'string', v: '"mobile_analysis_001"' }],
  [{ t: 'key', v: 'target' },       { t: 'colon', v: ':' }],
  [{ t: 'indent', v: '  ' }, { t: 'key', v: 'type' },        { t: 'colon', v: ': ' }, { t: 'string', v: '"android_apk"' }],
  [{ t: 'indent', v: '  ' }, { t: 'key', v: 'file' },        { t: 'colon', v: ': ' }, { t: 'string', v: '"android_main_apk.apk"' }],
  [{ t: 'indent', v: '  ' }, { t: 'key', v: 'hash_sha256' }, { t: 'colon', v: ': ' }, { t: 'string', v: '"a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5"' }],
  [],
  [{ t: 'key', v: 'orchestration' },{ t: 'colon', v: ':' }],
  [{ t: 'indent', v: '  ' }, { t: 'key', v: 'mode' },               { t: 'colon', v: ': ' }, { t: 'string', v: '"dynamic"' }],
  [{ t: 'indent', v: '  ' }, { t: 'key', v: 'container_registry' }, { t: 'colon', v: ': ' }, { t: 'string', v: '"alphaweb-local"' }],
  [],
  [{ t: 'key', v: 'tools' }, { t: 'colon', v: ':' }],
  [{ t: 'indent', v: '  ' }, { t: 'dash', v: '- ' }, { t: 'key', v: 'name' },   { t: 'colon', v: ': ' }, { t: 'string', v: '"apktool"' }],
  [{ t: 'indent', v: '    ' }, { t: 'key', v: 'type' },   { t: 'colon', v: ': ' }, { t: 'string', v: '"local-container"' }],
  [{ t: 'indent', v: '    ' }, { t: 'key', v: 'action' }, { t: 'colon', v: ': ' }, { t: 'string', v: '"decompile"' }],
  [{ t: 'indent', v: '    ' }, { t: 'key', v: 'params' }, { t: 'colon', v: ':' }],
  [{ t: 'indent', v: '      ' }, { t: 'key', v: 'output_dir' },       { t: 'colon', v: ': ' }, { t: 'string', v: '"./Tool_Data/decompiled"' }],
  [{ t: 'indent', v: '      ' }, { t: 'key', v: 'decode_resources' }, { t: 'colon', v: ': ' }, { t: 'bool', v: 'true' }],
  [],
  [{ t: 'indent', v: '  ' }, { t: 'dash', v: '- ' }, { t: 'key', v: 'name' },   { t: 'colon', v: ': ' }, { t: 'string', v: '"semgrep"' }],
  [{ t: 'indent', v: '    ' }, { t: 'key', v: 'type' },   { t: 'colon', v: ': ' }, { t: 'string', v: '"local-container"' }],
  [{ t: 'indent', v: '    ' }, { t: 'key', v: 'action' }, { t: 'colon', v: ': ' }, { t: 'string', v: '"static_analysis"' }],
  [{ t: 'indent', v: '    ' }, { t: 'key', v: 'params' }, { t: 'colon', v: ':' }],
  [{ t: 'indent', v: '      ' }, { t: 'key', v: 'ruleset' },    { t: 'colon', v: ': ' }, { t: 'string', v: '"mobile-security"' }],
  [{ t: 'indent', v: '      ' }, { t: 'key', v: 'target_dir' }, { t: 'colon', v: ': ' }, { t: 'string', v: '"./Tool_Data/decompiled"' }],
  [{ t: 'indent', v: '      ' }, { t: 'key', v: 'output' },     { t: 'colon', v: ': ' }, { t: 'string', v: '"./Reports/semgrep_results.json"' }],
  [],
  [{ t: 'key', v: 'reporting' }, { t: 'colon', v: ':' }],
  [{ t: 'indent', v: '  ' }, { t: 'key', v: 'format' },             { t: 'colon', v: ': ' }, { t: 'array', v: '["json", "html", "pdf"]' }],
  [{ t: 'indent', v: '  ' }, { t: 'key', v: 'output_dir' },         { t: 'colon', v: ': ' }, { t: 'string', v: '"./Reports"' }],
  [{ t: 'indent', v: '  ' }, { t: 'key', v: 'severity_threshold' }, { t: 'colon', v: ': ' }, { t: 'string', v: '"medium"' }],
]

const ACTIVE_LINE = 21

function tabIcon(ext) {
  return { yaml: '⚙', json: '{}', html: '<>', log: '≡', apk: '📱', txt: '¶', pdf: '📄' }[ext] ?? '·'
}

function EmptyState() {
  return (
    <div className="ed-empty">
      <div className="ed-empty__logo">⍺</div>
      <p className="ed-empty__title">AlphaWeb</p>
      <p className="ed-empty__sub">Open a file from the explorer to start editing</p>
      <div className="ed-empty__hints">
        <span className="ed-empty__hint">Click a file in the sidebar →</span>
      </div>
    </div>
  )
}

const CODE_EXTS = new Set(['py', 'js', 'ts', 'jsx', 'tsx', 'java', 'php', 'go'])

const SEV_COLOR = { critical: '#e06c75', high: '#d19a66', medium: '#e5c07b', low: '#98c379' }
const SEV_BG    = { critical: 'rgba(224,108,117,0.12)', high: 'rgba(209,154,102,0.12)', medium: 'rgba(229,192,123,0.12)', low: 'rgba(152,195,121,0.12)' }

// ── Code viewer with line highlighting ───────────────────────────────────────
function CodeViewer({ content, vulnLines }) {
  const lines = content.split('\n')
  return (
    <div style={{ display: 'flex', minWidth: 0 }}>
      {/* gutter */}
      <div style={{
        flexShrink: 0, width: 50,
        background: 'var(--bg-primary)',
        borderRight: '1px solid var(--border)',
        paddingTop: 2,
      }}>
        {lines.map((_, i) => {
          const lineNo = i + 1
          const sev = vulnLines[lineNo]
          return (
            <div
              key={i}
              className="ed-lnum"
              style={sev ? { color: SEV_COLOR[sev], fontWeight: 600, opacity: 1 } : undefined}
            >
              {sev && <span style={{ marginRight: 2, fontSize: 8 }}>●</span>}
              {lineNo}
            </div>
          )
        })}
      </div>
      {/* code */}
      <div style={{ flex: 1, padding: '2px 0 20px 0', minWidth: 0 }}>
        {lines.map((line, i) => {
          const lineNo = i + 1
          const sev = vulnLines[lineNo]
          return (
            <div
              key={i}
              className="ed-line"
              style={sev ? { background: SEV_BG[sev], borderLeft: `2px solid ${SEV_COLOR[sev]}` } : undefined}
            >
              <span style={{ whiteSpace: 'pre', color: 'var(--text-secondary)' }}>{line || ' '}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Vuln panel ────────────────────────────────────────────────────────────────
function VulnPanel({ result }) {
  const [open, setOpen] = useState(true)
  if (!result) return null

  return (
    <div style={{
      borderTop: '1px solid var(--border)',
      background: 'var(--bg-2)',
      flexShrink: 0,
      maxHeight: open ? 280 : 36,
      overflow: 'hidden',
      transition: 'max-height 0.2s ease',
    }}>
      {/* panel header */}
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '6px 14px', cursor: 'pointer',
          borderBottom: open ? '1px solid var(--border)' : 'none',
          userSelect: 'none',
        }}
      >
        <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>VULNERABILITIES</span>
        <div style={{ display: 'flex', gap: 6, flex: 1 }}>
          {['critical','high','medium','low'].map(s => result[s] > 0 && (
            <span key={s} style={{
              background: SEV_BG[s], border: `1px solid ${SEV_COLOR[s]}`,
              color: SEV_COLOR[s], borderRadius: 3, padding: '1px 7px', fontSize: 10,
            }}>
              {result[s]} {s}
            </span>
          ))}
          {result.total_vulnerabilities === 0 && (
            <span style={{ color: '#98c379', fontSize: 11 }}>No vulnerabilities found</span>
          )}
        </div>
        <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>{open ? '▼' : '▶'}</span>
      </div>

      {/* vuln list */}
      {open && (
        <div style={{ overflowY: 'auto', maxHeight: 236, padding: '8px 14px', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {result.vulnerabilities.length === 0 && (
            <p style={{ color: '#98c379', fontSize: 12, margin: 0 }}>Clean — no issues detected.</p>
          )}
          {result.vulnerabilities.map((v, i) => (
            <div key={i} style={{
              background: 'var(--bg-3)',
              borderLeft: `3px solid ${SEV_COLOR[v.severity] ?? '#666'}`,
              borderRadius: 4, padding: '7px 11px', fontSize: 12,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <span style={{ color: SEV_COLOR[v.severity], fontWeight: 600 }}>
                  {v.type ?? 'unknown'}
                  {v.cwe && <span style={{ color: 'var(--text-dim)', fontWeight: 400 }}> · {v.cwe}</span>}
                </span>
                {v.line && <span style={{ color: 'var(--text-dim)', fontSize: 11 }}>line {v.line}</span>}
              </div>
              <p style={{ color: 'var(--text-secondary)', margin: '0 0 3px', fontSize: 11 }}>{v.issue}</p>
              {v.code_snippet && (
                <code style={{
                  display: 'block', background: 'var(--bg-1)', padding: '2px 7px',
                  borderRadius: 3, color: 'var(--text-dim)', fontSize: 10,
                  marginBottom: 3, whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                }}>
                  {v.code_snippet}
                </code>
              )}
              {v.fix && <p style={{ color: '#98c379', margin: 0, fontSize: 10 }}>Fix: {v.fix}</p>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── File preview (non-code / binary) ─────────────────────────────────────────
function BinaryPreview({ name, ext }) {
  const colors = { json: 'var(--gold)', html: 'var(--orange)', log: 'var(--text-dim)',
                   apk: 'var(--green)', txt: 'var(--text-secondary)', pdf: '#e06c75' }
  return (
    <div className="ed-preview">
      <div className="ed-preview__icon" style={{ color: colors[ext] ?? 'var(--text-secondary)' }}>
        {tabIcon(ext)}
      </div>
      <p className="ed-preview__name">{name}</p>
      <p className="ed-preview__ext">.{ext} file</p>
      <div className="ed-preview__actions">
        <button className="ed-preview__btn">Open in External Viewer</button>
      </div>
    </div>
  )
}

// ── Code file view (load + analyze) ──────────────────────────────────────────
function CodeFileView({ name, ext, fileObj }) {
  const [content, setContent]   = useState(null)
  const [loadErr, setLoadErr]   = useState(null)
  const [status, setStatus]     = useState('idle')   // idle | analyzing | done | error
  const [result, setResult]     = useState(null)
  const [apiErr, setApiErr]     = useState(null)

  useEffect(() => {
    if (!fileObj) { setContent(null); return }
    fileObj.text()
      .then(text => setContent(text))
      .catch(e => setLoadErr('Could not read file: ' + e.message))
  }, [fileObj])

  async function handleAnalyze() {
    if (!content) return
    setStatus('analyzing')
    setApiErr(null)
    setResult(null)
    try {
      const res  = await fetch('/api/analyze-code', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ code: content, filename: name }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail ?? `HTTP ${res.status}`)
      setResult(data)
      setStatus('done')
    } catch (e) {
      setApiErr(e.message)
      setStatus('error')
    }
  }

  // Map line number → highest severity on that line
  const vulnLines = {}
  if (result?.vulnerabilities) {
    const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 }
    for (const v of result.vulnerabilities) {
      if (!v.line) continue
      const cur = vulnLines[v.line]
      if (!cur || SEV_RANK[v.severity] > SEV_RANK[cur]) vulnLines[v.line] = v.severity
    }
  }

  if (loadErr) {
    return (
      <div className="ed-preview">
        <p style={{ color: '#e06c75', fontSize: 13 }}>{loadErr}</p>
      </div>
    )
  }

  if (!content) {
    return (
      <div className="ed-preview">
        <p style={{ color: 'var(--text-dim)', fontSize: 13 }}>Loading…</p>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}>
      {/* toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '4px 12px', borderBottom: '1px solid var(--border)',
        background: 'var(--bg-2)', flexShrink: 0,
      }}>
        <span style={{ color: 'var(--text-dim)', fontSize: 11, flex: 1 }}>
          {ext?.toUpperCase()} · {content.split('\n').length} lines
        </span>
        {status === 'error' && (
          <span style={{ color: '#e06c75', fontSize: 11 }}>{apiErr}</span>
        )}
        <button
          onClick={handleAnalyze}
          disabled={status === 'analyzing'}
          style={{
            background: status === 'done' ? 'var(--bg-3)' : 'var(--cyan)',
            color: status === 'done' ? 'var(--text-secondary)' : '#0d0d0d',
            border: 'none', borderRadius: 4, padding: '4px 12px',
            fontSize: 11, fontWeight: 600, cursor: status === 'analyzing' ? 'wait' : 'pointer',
            opacity: status === 'analyzing' ? 0.7 : 1,
          }}
        >
          {status === 'analyzing' ? 'Analyzing…' : status === 'done' ? 'Re-analyze' : 'Analyze'}
        </button>
      </div>

      {/* code view — scrollable */}
      <div style={{ flex: 1, overflow: 'auto', minHeight: 0 }}>
        <CodeViewer content={content} vulnLines={vulnLines} />
      </div>

      {/* vuln panel */}
      {result && <VulnPanel result={result} />}
    </div>
  )
}

// ── YAML viewer ───────────────────────────────────────────────────────────────
function YamlViewer() {
  return (
    <div className="ed-body">
      <div className="ed-gutter">
        {YAML.map((_, i) => (
          <div key={i} className={`ed-lnum ${i === ACTIVE_LINE ? 'ed-lnum--active' : ''}`}>
            {i + 1}
          </div>
        ))}
      </div>
      <div className="ed-content">
        {YAML.map((tokens, i) => (
          <div key={i} className={`ed-line ${i === ACTIVE_LINE ? 'ed-line--active' : ''}`}>
            {tokens.map((tok, j) => (
              <span key={j} className={`yt-${tok.t}`}>{tok.v}</span>
            ))}
            {i === ACTIVE_LINE && <span className="ed-cursor" />}
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Editor ────────────────────────────────────────────────────────────────────
export default function Editor({ openFiles = [], activeFile, onTabClick, onCloseTab }) {
  const currentFile = openFiles.find(f => f.name === activeFile)
  const isYaml      = currentFile?.ext === 'yaml' || currentFile?.name?.endsWith('.yaml')
  const isCode      = CODE_EXTS.has(currentFile?.ext?.toLowerCase())

  if (openFiles.length === 0) {
    return (
      <section className="editor">
        <div className="ed-tabs"><div className="ed-tabs__spacer" /></div>
        <EmptyState />
      </section>
    )
  }

  return (
    <section className="editor" style={{ display: 'flex', flexDirection: 'column' }}>
      {/* ── Tab bar ── */}
      <div className="ed-tabs">
        {openFiles.map(file => {
          const isActive = file.name === activeFile
          return (
            <div
              key={file.id ?? file.name}
              className={`ed-tab ${isActive ? 'ed-tab--active' : ''}`}
              onClick={() => onTabClick?.(file.name)}
            >
              <span className="ed-tab__icon">{tabIcon(file.ext)}</span>
              <span className="ed-tab__name">{file.name}</span>
              <button
                className="ed-tab__close"
                title="Close tab"
                onClick={e => { e.stopPropagation(); onCloseTab?.(file.name) }}
              >
                ×
              </button>
            </div>
          )
        })}
        <div className="ed-tabs__spacer" />
      </div>

      {/* ── Breadcrumb (only for YAML) ── */}
      {isYaml && (
        <div className="ed-breadcrumb">
          <span className="ed-bc-seg">Mobile_Analysis</span>
          <span className="ed-bc-sep">›</span>
          <span className="ed-bc-seg ed-bc-seg--active">{activeFile}</span>
          <span className="ed-bc-sep">›</span>
          <span className="ed-bc-seg">tools[1]</span>
          <span className="ed-bc-sep">›</span>
          <span className="ed-bc-seg ed-bc-seg--key">name</span>
        </div>
      )}

      {/* ── Content ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0, overflow: 'hidden' }}>
        {isYaml
          ? <YamlViewer />
          : isCode
            ? <CodeFileView
                key={currentFile?.id ?? activeFile}
                name={activeFile}
                ext={currentFile?.ext ?? ''}
                fileObj={currentFile?.fileObj}
              />
            : <BinaryPreview name={activeFile} ext={currentFile?.ext ?? ''} />
        }
      </div>
    </section>
  )
}

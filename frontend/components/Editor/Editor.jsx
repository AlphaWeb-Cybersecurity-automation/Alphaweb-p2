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

// ── File type → icon character ────────────────────────────────────────────────
function tabIcon(ext) {
  return { yaml: '⚙', json: '{}', html: '<>', log: '≡', apk: '📱', txt: '¶', pdf: '📄' }[ext] ?? '·'
}

// ── Empty state ───────────────────────────────────────────────────────────────
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

// ── Preview for non-YAML files ────────────────────────────────────────────────
function FilePreview({ name, ext }) {
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
        <button className="ed-preview__btn ed-preview__btn--primary">Send to Agent for Analysis</button>
      </div>
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

  if (openFiles.length === 0) {
    return (
      <section className="editor">
        <div className="ed-tabs"><div className="ed-tabs__spacer" /></div>
        <EmptyState />
      </section>
    )
  }

  return (
    <section className="editor">
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
      {isYaml
        ? <YamlViewer />
        : <FilePreview name={activeFile} ext={currentFile?.ext ?? ''} />
      }
    </section>
  )
}

import { useState, useRef, useCallback, useEffect } from 'react'
import './SideBar.css'

const SECTION_LABELS = {
  scanner:       'EXPLORER',
  reporting:     'REPORTS',
  orchestration: 'CONTAINERS',
}

function extIcon(ext) {
  const map = { apk: '📱', zip: '📦', tar: '📦', gz: '📦', yaml: '⚙', yml: '⚙',
                json: '{}', txt: '¶', pdf: '📄', log: '≡', csv: '⋮' }
  return map[ext?.toLowerCase()] ?? '·'
}

function extColor(ext) {
  return ({
    apk: 'var(--green)', zip: 'var(--cyan)', tar: 'var(--cyan)', gz: 'var(--cyan)',
    yaml: 'var(--cyan)', yml: 'var(--cyan)', json: 'var(--gold)',
    pdf: '#e06c75', log: 'var(--text-dim)', txt: 'var(--text-secondary)',
  })[ext?.toLowerCase()] ?? 'var(--text-secondary)'
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(1)} MB`
}

export default function SideBar({ activeView, activeFile, onFileOpen, onToast, onFilesChange }) {
  const [files, setFiles]         = useState([])
  const [dragging, setDragging]   = useState(false)
  const [creating, setCreating]   = useState(false)
  const [createName, setCreateName] = useState('')
  const fileInputRef  = useRef(null)
  const createInputRef = useRef(null)

  useEffect(() => {
    if (creating) createInputRef.current?.focus()
  }, [creating])

  const addFiles = useCallback((fileList) => {
    const items = Array.from(fileList).map(f => ({
      id:   `up-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      name: f.name,
      size: f.size,
      ext:  f.name.includes('.') ? f.name.split('.').pop().toLowerCase() : '',
      file: f,
      ts:   new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }),
    }))

    setFiles(prev => {
      const next = [...prev, ...items]
      onFilesChange?.(next)
      return next
    })

    items.forEach(item => onFileOpen?.({ id: item.id, name: item.name, ext: item.ext }))
    onToast?.(`${items.length} file${items.length > 1 ? 's' : ''} uploaded`, 'success')
  }, [onFileOpen, onFilesChange, onToast])

  function removeFile(id) {
    setFiles(prev => {
      const next = prev.filter(f => f.id !== id)
      onFilesChange?.(next)
      return next
    })
  }

  function commitCreate() {
    const name = createName.trim()
    setCreating(false)
    setCreateName('')
    if (!name) return
    const ext  = name.includes('.') ? name.split('.').pop().toLowerCase() : ''
    const item = {
      id:   `new-${Date.now()}-${Math.random().toString(36).slice(2)}`,
      name,
      size: 0,
      ext,
      file: null,
      ts:   new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }),
    }
    setFiles(prev => {
      const next = [...prev, item]
      onFilesChange?.(next)
      return next
    })
    onFileOpen?.({ id: item.id, name: item.name, ext: item.ext })
    onToast?.(`Created ${name}`, 'success')
  }

  function handleDrop(e) {
    e.preventDefault()
    setDragging(false)
    if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files)
  }

  function handleInputChange(e) {
    if (e.target.files?.length) addFiles(e.target.files)
    e.target.value = ''
  }

  return (
    <aside className="sidebar">
      {/* ── Header ── */}
      <div className="sidebar__header">
        <span className="sidebar__title">ALPHAWEB_WORKSPACE</span>
        <div className="sidebar__hdr-actions">
          <button
            className="sidebar__hdr-btn"
            title="New File"
            onClick={() => setCreating(true)}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" width="13" height="13">
              <rect x="2" y="1" width="9" height="13" rx="1"/>
              <line x1="8" y1="6" x2="12" y2="6"/>
              <line x1="10" y1="4" x2="10" y2="8"/>
            </svg>
          </button>
          <button
            className="sidebar__hdr-btn"
            title="Upload File"
            onClick={() => fileInputRef.current?.click()}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" width="13" height="13">
              <path d="M2 11v2h12v-2"/>
              <path d="M8 2v8"/>
              <polyline points="5,5 8,2 11,5"/>
            </svg>
          </button>
        </div>
      </div>

      <div className="sidebar__section-label">
        {SECTION_LABELS[activeView] ?? 'EXPLORER'}
      </div>

      {/* ── Upload area + file list ── */}
      <div className="sidebar__tree">
        {/* Drop zone */}
        <div
          className={[
            'sb-dropzone',
            dragging          ? 'sb-dropzone--active'  : '',
            files.length > 0  ? 'sb-dropzone--compact' : '',
          ].join(' ')}
          onDragOver={e => { e.preventDefault(); setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          onClick={() => files.length === 0 && fileInputRef.current?.click()}
          role="button"
          tabIndex={0}
          onKeyDown={e => e.key === 'Enter' && fileInputRef.current?.click()}
        >
          {files.length === 0 ? (
            <>
              <div className="sb-dropzone__icon">⬆</div>
              <p className="sb-dropzone__title">Drop files here</p>
              <p className="sb-dropzone__sub">or click to browse</p>
              <p className="sb-dropzone__hint">APK · ZIP · YAML · any file</p>
            </>
          ) : (
            <button
              className="sb-add-more"
              onClick={e => { e.stopPropagation(); fileInputRef.current?.click() }}
            >
              + Add more files
            </button>
          )}
        </div>

        {/* Inline create row */}
        {creating && (
          <div className="si-row si-row--creating" style={{ paddingLeft: 12 }}>
            <span style={{ fontSize: 13, color: 'var(--cyan)', flexShrink: 0 }}>·</span>
            <input
              ref={createInputRef}
              className="si-create-input"
              placeholder="filename.ext"
              value={createName}
              onChange={e => setCreateName(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') commitCreate()
                if (e.key === 'Escape') { setCreating(false); setCreateName('') }
              }}
              onBlur={commitCreate}
            />
          </div>
        )}

        {/* Uploaded file list */}
        {files.map(f => (
          <div
            key={f.id}
            className={`sb-file ${f.name === activeFile ? 'sb-file--active' : ''}`}
            onClick={() => onFileOpen?.({ id: f.id, name: f.name, ext: f.ext })}
            role="button"
            tabIndex={0}
            onKeyDown={e => e.key === 'Enter' && onFileOpen?.({ id: f.id, name: f.name, ext: f.ext })}
          >
            <span className="sb-file__icon" style={{ color: extColor(f.ext) }}>
              {extIcon(f.ext)}
            </span>
            <div className="sb-file__info">
              <span className="sb-file__name">{f.name}</span>
              <span className="sb-file__meta">{formatSize(f.size)} · {f.ts}</span>
            </div>
            <button
              className="sb-file__remove"
              title="Remove"
              onClick={e => { e.stopPropagation(); removeFile(f.id) }}
            >
              ×
            </button>
          </div>
        ))}
      </div>

      {/* ── Quick Actions ── */}
      <div className="sidebar__qa">
        <div className="sidebar__qa-label">QUICK ACTIONS</div>

        <button
          className="qa-row qa-row--sec"
          onClick={() => setCreating(true)}
        >
          <span className="qa-row__icon">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.4"
                 strokeLinecap="round" strokeLinejoin="round">
              <rect x="4" y="2" width="12" height="16" rx="1.5"/>
              <line x1="10" y1="7" x2="10" y2="13"/>
              <line x1="7" y1="10" x2="13" y2="10"/>
            </svg>
          </span>
          <div className="qa-row__text">
            <span className="qa-row__label">New File</span>
            <span className="qa-row__sub">Create file in workspace</span>
          </div>
        </button>

        <button
          className="qa-row qa-row--primary"
          onClick={() => fileInputRef.current?.click()}
        >
          <span className="qa-row__icon qa-row__icon--primary">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.4"
                 strokeLinecap="round" strokeLinejoin="round">
              <rect x="5.5" y="1.5" width="9" height="17" rx="1.5"/>
              <line x1="10" y1="6" x2="10" y2="12"/>
              <polyline points="7.5,8.5 10,6 12.5,8.5"/>
              <line x1="8" y1="15" x2="12" y2="15"/>
            </svg>
          </span>
          <div className="qa-row__text">
            <span className="qa-row__label">Upload File</span>
            <span className="qa-row__sub">Select file to analyze</span>
          </div>
          <span className="qa-row__badge">NEW</span>
        </button>

        <button className="qa-row qa-ml-btn" disabled>
          <span className="qa-row__icon qa-row__icon--ml">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.4"
                 strokeLinecap="round" strokeLinejoin="round">
              <circle cx="10" cy="10" r="3"/>
              <path d="M10 2v2M10 16v2M2 10h2M16 10h2"/>
              <path d="M4.93 4.93l1.41 1.41M13.66 13.66l1.41 1.41M4.93 15.07l1.41-1.41M13.66 6.34l1.41-1.41"/>
            </svg>
          </span>
          <div className="qa-row__text">
            <span className="qa-row__label">ML Security Scan</span>
            <span className="qa-row__sub">Code vulnerability detection</span>
          </div>
          <span className="qa-row__badge qa-row__badge--soon">SOON</span>
        </button>
      </div>

      <input
        ref={fileInputRef}
        type="file"
        multiple
        style={{ display: 'none' }}
        onChange={handleInputChange}
      />
    </aside>
  )
}

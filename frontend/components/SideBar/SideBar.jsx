import { useState, useRef, useEffect } from 'react'
import './SideBar.css'

// ── Initial file tree ────────────────────────────────────────────────────────
const INITIAL_TREE = [
  {
    id: 'task-config', name: 'Task_Configurations', type: 'folder',
    children: [
      { id: 'tc1', name: 'web_api_scan.yaml',  type: 'file', ext: 'yaml' },
      { id: 'tc2', name: 'network_recon.yaml', type: 'file', ext: 'yaml' },
      { id: 'tc3', name: 'ssl_audit.yaml',     type: 'file', ext: 'yaml' },
    ],
  },
  {
    id: 'tool-data', name: 'Tool_Data', type: 'folder',
    children: [
      { id: 'td1', name: 'decompiled',   type: 'folder', children: [] },
      { id: 'td2', name: 'scan_cache',   type: 'folder', children: [] },
      { id: 'td3', name: 'tool_outputs', type: 'folder', children: [] },
    ],
  },
  {
    id: 'reports', name: 'Reports', type: 'folder',
    children: [
      { id: 'r1', name: 'semgrep_results.json', type: 'file', ext: 'json' },
      { id: 'r2', name: 'summary_report.html',  type: 'file', ext: 'html' },
      { id: 'r3', name: 'executive_brief.pdf',  type: 'file', ext: 'pdf'  },
    ],
  },
  {
    id: 'logs', name: 'Logs', type: 'folder',
    children: [
      { id: 'l1', name: 'orchestration_2026-03-27.log', type: 'file', ext: 'log' },
      { id: 'l2', name: 'agent_session.log',            type: 'file', ext: 'log' },
    ],
  },
  {
    id: 'mobile', name: 'Mobile_Analysis', type: 'folder', icon: 'mobile', defaultOpen: true,
    children: [
      { id: 'm1', name: 'android_main_apk_analysis.yaml', type: 'file', ext: 'yaml' },
      { id: 'm2', name: 'android_main_apk.apk',           type: 'file', ext: 'apk'  },
      { id: 'm3', name: 'manifest_analysis.json',         type: 'file', ext: 'json' },
      { id: 'm4', name: 'strings_extract.txt',            type: 'file', ext: 'txt'  },
    ],
  },
]

const SECTION_LABELS = {
  scanner:       'EXPLORER',
  reporting:     'REPORTS',
  orchestration: 'CONTAINERS',
}

function extColor(ext) {
  return { yaml: 'var(--cyan)', json: 'var(--gold)', html: 'var(--orange)',
           pdf: '#e06c75', log: 'var(--text-dim)', apk: 'var(--green)',
           txt: 'var(--text-secondary)' }[ext] || 'var(--text-secondary)'
}

function addToFolder(nodes, parentId, item) {
  return nodes.map(n => {
    if (n.id === parentId) return { ...n, children: [...(n.children || []), item] }
    if (n.children)        return { ...n, children: addToFolder(n.children, parentId, item) }
    return n
  })
}

// ── Icons ────────────────────────────────────────────────────────────────────
function FolderIcon({ open }) {
  return (
    <svg className="si-icon" viewBox="0 0 16 16" fill="currentColor">
      {open
        ? <path d="M1.5 3A1.5 1.5 0 0 0 0 4.5v8A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5V6a1.5 1.5 0 0 0-1.5-1.5H7.207L5.5 3H1.5z" opacity="0.85"/>
        : <path d="M9.828 3H1.5A1.5 1.5 0 0 0 0 4.5v8A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5V6a1.5 1.5 0 0 0-1.5-1.5H7.207L5.5 3H1.5z" opacity="0.5"/>
      }
    </svg>
  )
}

function FileIcon() {
  return (
    <svg className="si-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1">
      <path d="M4 1.5h5.5l3 3V14a.5.5 0 0 1-.5.5H4a.5.5 0 0 1-.5-.5V2a.5.5 0 0 1 .5-.5z" opacity="0.6"/>
      <path d="M9 1.5V5h3.5" opacity="0.6"/>
    </svg>
  )
}

// ── TreeNode ─────────────────────────────────────────────────────────────────
function TreeNode({ item, depth = 0, activeFile, onFileOpen, creating, newName,
                    onNameChange, onNameConfirm, onNameCancel }) {
  const [open, setOpen]   = useState(item.defaultOpen ?? false)
  const inputRef          = useRef(null)
  const pad               = 8 + depth * 14
  const isCreatingHere    = creating?.parentId === item.id

  // Auto-open folder when creating inside it
  useEffect(() => { if (isCreatingHere) setOpen(true) }, [isCreatingHere])
  // Focus the inline input
  useEffect(() => {
    if (isCreatingHere) setTimeout(() => inputRef.current?.focus(), 30)
  }, [isCreatingHere])

  const childProps = { activeFile, onFileOpen, creating, newName, onNameChange, onNameConfirm, onNameCancel }

  if (item.type === 'folder') {
    return (
      <div>
        <button
          className="si-row si-row--folder"
          style={{ paddingLeft: pad }}
          onClick={() => setOpen(o => !o)}
        >
          <span className="si-arrow">{open ? '▾' : '▸'}</span>
          {item.icon === 'mobile'
            ? <span className="si-icon si-icon--mobile">📱</span>
            : <span style={{ color: 'var(--gold-dim)' }}><FolderIcon open={open} /></span>
          }
          <span className="si-name si-name--folder">{item.name}</span>
        </button>

        {open && (
          <div>
            {item.children.map(child => (
              <TreeNode key={child.id} item={child} depth={depth + 1} {...childProps} />
            ))}

            {/* Inline creation input */}
            {isCreatingHere && (
              <div className="si-row si-row--creating" style={{ paddingLeft: pad + 28 }}>
                {creating.type === 'folder'
                  ? <span style={{ color: 'var(--gold-dim)' }}><FolderIcon open={false} /></span>
                  : <FileIcon />
                }
                <input
                  ref={inputRef}
                  className="si-create-input"
                  value={newName}
                  placeholder={creating.type === 'file' ? 'filename.yaml' : 'folder_name'}
                  onChange={e => onNameChange(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter')  onNameConfirm()
                    if (e.key === 'Escape') onNameCancel()
                  }}
                  onBlur={onNameCancel}
                />
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  // File row
  const isActive = item.name === activeFile
  return (
    <button
      className={`si-row si-row--file ${isActive ? 'si-row--active' : ''}`}
      style={{ paddingLeft: pad + 14, color: extColor(item.ext) }}
      onClick={() => onFileOpen?.({ id: item.id, name: item.name, ext: item.ext })}
    >
      <FileIcon />
      <span className="si-name">{item.name}</span>
    </button>
  )
}

// ── SideBar ──────────────────────────────────────────────────────────────────
export default function SideBar({ activeView, activeFile, onFileOpen, onToast }) {
  const [fileTree, setFileTree] = useState(INITIAL_TREE)
  const [creating, setCreating] = useState(null)  // { type: 'file'|'folder', parentId }
  const [newName,  setNewName]  = useState('')
  const [refreshSpin, setRefreshSpin] = useState(false)
  const fileInputRef = useRef(null)

  function startCreate(type, parentId = 'mobile') {
    setCreating({ type, parentId })
    setNewName('')
  }

  function confirmCreate() {
    if (!newName.trim()) { setCreating(null); return }
    const trimmed = newName.trim()
    const ext     = trimmed.includes('.') ? trimmed.split('.').pop() : ''
    const id      = `new-${Date.now()}`
    const newItem = creating.type === 'folder'
      ? { id, name: trimmed, type: 'folder', children: [], defaultOpen: false }
      : { id, name: trimmed, type: 'file', ext }
    setFileTree(prev => addToFolder(prev, creating.parentId, newItem))
    if (creating.type === 'file') onFileOpen?.({ id, name: trimmed, ext })
    onToast?.(`${creating.type === 'folder' ? '📁' : '📄'} "${trimmed}" created`)
    setCreating(null)
    setNewName('')
  }

  function handleRefresh() {
    setRefreshSpin(true)
    setTimeout(() => setRefreshSpin(false), 700)
    onToast?.('Workspace refreshed', 'info')
  }

  function handleUpload(e) {
    const file = e.target.files?.[0]
    if (!file) return
    const ext = file.name.split('.').pop().toLowerCase()
    const id  = `upload-${Date.now()}`
    setFileTree(prev => addToFolder(prev, 'mobile', { id, name: file.name, type: 'file', ext }))
    onFileOpen?.({ id, name: file.name, ext })
    onToast?.(`"${file.name}" uploaded — ready for analysis`, 'info')
    e.target.value = ''
  }

  const treeProps = {
    activeFile, onFileOpen, creating, newName,
    onNameChange: setNewName, onNameConfirm: confirmCreate, onNameCancel: () => setCreating(null),
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
            onClick={() => startCreate('file')}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" width="13" height="13">
              <path d="M3 2.5h6.5l3 3V13a.5.5 0 0 1-.5.5H3a.5.5 0 0 1-.5-.5V3a.5.5 0 0 1 .5-.5z"/>
              <path d="M9 2.5V6h3.5"/><path d="M8 8.5v3M6.5 10h3"/>
            </svg>
          </button>
          <button
            className="sidebar__hdr-btn"
            title="New Folder"
            onClick={() => startCreate('folder')}
          >
            <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.3" width="13" height="13">
              <path d="M1 3.5A1.5 1.5 0 0 1 2.5 2h3l1.5 1.5H13A1.5 1.5 0 0 1 14.5 5v6a1.5 1.5 0 0 1-1.5 1.5H2.5A1.5 1.5 0 0 1 1 11V3.5z"/>
              <path d="M8 6.5v3M6.5 8h3"/>
            </svg>
          </button>
          <button
            className={`sidebar__hdr-btn ${refreshSpin ? 'sidebar__hdr-btn--spin' : ''}`}
            title="Refresh"
            onClick={handleRefresh}
          >↻</button>
        </div>
      </div>

      <div className="sidebar__section-label">
        {SECTION_LABELS[activeView] ?? 'EXPLORER'}
      </div>

      {/* ── File tree ── */}
      <div className="sidebar__tree">
        {fileTree.map(item => (
          <TreeNode key={item.id} item={item} {...treeProps} />
        ))}
      </div>

      {/* ── Quick Actions (bottom) ── */}
      <div className="sidebar__qa">
        <div className="sidebar__qa-label">QUICK ACTIONS</div>

        <button className="qa-row qa-row--sec" onClick={() => startCreate('folder')}>
          <span className="qa-row__icon">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M2 5.5A1.5 1.5 0 0 1 3.5 4h4l1.5 1.5H16A1.5 1.5 0 0 1 17.5 7v7a1.5 1.5 0 0 1-1.5 1.5H3.5A1.5 1.5 0 0 1 2 14V5.5z"/>
              <line x1="10" y1="9.5" x2="10" y2="13.5"/><line x1="8" y1="11.5" x2="12" y2="11.5"/>
            </svg>
          </span>
          <div className="qa-row__text">
            <span className="qa-row__label">Create New Folder</span>
            <span className="qa-row__sub">Inside Mobile_Analysis</span>
          </div>
        </button>

        <button className="qa-row qa-row--sec" onClick={() => startCreate('file')}>
          <span className="qa-row__icon">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 3.5h8l3.5 3.5V16a.5.5 0 0 1-.5.5H4a.5.5 0 0 1-.5-.5V4a.5.5 0 0 1 .5-.5z"/>
              <path d="M12 3.5V7h3.5"/>
              <path d="M6.5 11l2 2-2 2"/><line x1="11" y1="13" x2="13.5" y2="13"/>
            </svg>
          </span>
          <div className="qa-row__text">
            <span className="qa-row__label">Add Code Snippet</span>
            <span className="qa-row__sub">New analysis script</span>
          </div>
        </button>

        <button className="qa-row qa-row--primary" onClick={() => fileInputRef.current?.click()}>
          <span className="qa-row__icon qa-row__icon--primary">
            <svg viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round">
              <rect x="5.5" y="1.5" width="9" height="17" rx="1.5"/>
              <line x1="10" y1="6" x2="10" y2="12"/><polyline points="7.5,8.5 10,6 12.5,8.5"/>
              <line x1="8" y1="15" x2="12" y2="15"/>
            </svg>
          </span>
          <div className="qa-row__text">
            <span className="qa-row__label">Upload APK File</span>
            <span className="qa-row__sub">Select .apk to analyze</span>
          </div>
          <span className="qa-row__badge">NEW</span>
        </button>
      </div>

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".apk"
        style={{ display: 'none' }}
        onChange={handleUpload}
      />
    </aside>
  )
}

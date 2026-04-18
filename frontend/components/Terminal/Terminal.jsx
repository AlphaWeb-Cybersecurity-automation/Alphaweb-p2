import { useEffect, useRef, useState } from 'react'
import './Terminal.css'

// ── Log data ─────────────────────────────────────────────────────────────────
const LOGS = [
  { type: 'info',    icon: '▶', msg: 'Connecting to local container registry...', detail: 'alphaweb-local',                          ts: '09:14:01' },
  { type: 'success', icon: '✓', msg: 'Container registry connection established',  detail: null,                                      ts: '09:14:01' },
  { type: 'info',    icon: '▶', msg: 'Resolving tool availability for task:',      detail: 'mobile_analysis_001',                     ts: '09:14:02' },
  { type: 'success', icon: '✓', msg: 'apktool',                                    detail: '(local-container)  ·  ready  ·  v2.9.3',  ts: '09:14:02' },
  { type: 'success', icon: '✓', msg: 'semgrep',                                    detail: '(local-container)  ·  ready  ·  v1.45.0', ts: '09:14:02' },
  { type: 'success', icon: '✓', msg: 'schemathesis',                               detail: '(local-container)  ·  ready  ·  v3.28.0', ts: '09:14:03' },
  { type: 'pending', icon: '⟳', msg: 'Loading task configuration:',                detail: 'android_main_apk_analysis.yaml',           ts: '09:14:03' },
  { type: 'success', icon: '✓', msg: 'Task configuration loaded successfully',     detail: null,                                      ts: '09:14:03' },
  { type: 'pending', icon: '⟳', msg: 'Initializing dynamic orchestration engine...', detail: null,                                    ts: '09:14:04' },
  { type: 'success', icon: '✓', msg: 'Orchestration engine initialized',           detail: 'Region: Hyderabad',                        ts: '09:14:04' },
  { type: 'pending', icon: '⟳', msg: 'Stage 1: APK Decompilation',                detail: '(apktool)',                                ts: '09:14:05' },
  { type: 'success', icon: '✓', msg: 'apktool container started',                  detail: 'Container ID: a3f9b2c1d4e5f6a7',           ts: '09:14:06' },
  { type: 'success', icon: '✓', msg: 'Decompilation complete',                     detail: '847 files extracted  ·  2.3 MB',           ts: '09:14:12' },
  { type: 'pending', icon: '⟳', msg: 'Stage 2: Static Analysis',                  detail: '(semgrep)',                                ts: '09:14:12' },
  { type: 'success', icon: '✓', msg: 'semgrep container started',                  detail: 'Container ID: d4e5f6a7b8c9d0e1',           ts: '09:14:13' },
  { type: 'pending', icon: '⟳', msg: 'Running mobile-security ruleset...',         detail: null,                                      ts: '09:14:13' },
  { type: 'warning', icon: '!', msg: 'Found 3 high-severity issues in',            detail: 'com/example/MainActivity.java',             ts: '09:14:18' },
  { type: 'warning', icon: '!', msg: 'Hardcoded API key detected:',                detail: 'API_KEY = "sk-proj-..."  [CRITICAL]',       ts: '09:14:18' },
  { type: 'success', icon: '✓', msg: 'Scan progress:',                             detail: '20% complete  ·  Stage 2 of 5',            ts: '09:14:19' },
]

const PROBLEMS = [
  { sev: 'critical', file: 'MainActivity.java',  line: 47,  msg: 'Hardcoded API key: API_KEY = "sk-proj-..."' },
  { sev: 'high',     file: 'NetworkHelper.java',  line: 23,  msg: 'Improper certificate validation — TrustAll detected' },
  { sev: 'high',     file: 'StorageUtil.java',    line: 89,  msg: 'Insecure SharedPreferences: sensitive data stored unencrypted' },
  { sev: 'medium',   file: 'AndroidManifest.xml', line: 12,  msg: 'Overly permissive: android.permission.READ_CONTACTS' },
  { sev: 'medium',   file: 'CryptoUtil.java',     line: 34,  msg: 'Weak algorithm: MD5 used for hashing sensitive data' },
]

const SEV_COLORS = {
  critical: 'var(--red)',
  high:     'var(--orange)',
  medium:   'var(--gold)',
  low:      'var(--text-dim)',
}

// ── Tab panels ────────────────────────────────────────────────────────────────
function ConsolePanel({ visible: count, bottomRef }) {
  return (
    <div className="term-body">
      <div className="term-prompt">
        <span className="term-prompt__user">alphaweb</span>
        <span className="term-prompt__at">@</span>
        <span className="term-prompt__host">hyderabad</span>
        <span className="term-prompt__sep">:</span>
        <span className="term-prompt__path">~/Mobile_Analysis</span>
        <span className="term-prompt__char">$&nbsp;</span>
        <span className="term-prompt__cmd">alphaweb run android_main_apk_analysis.yaml</span>
      </div>

      {LOGS.slice(0, count).map((log, i) => (
        <div key={i} className={`term-entry term-entry--${log.type}`}>
          <span className="term-ts">{log.ts}</span>
          <span className={`term-icon term-icon--${log.type}`}>{log.icon}</span>
          <span className="term-msg">{log.msg}</span>
          {log.detail && (
            <span className={`term-detail term-detail--${log.type}`}>&nbsp;{log.detail}</span>
          )}
        </div>
      ))}

      {count < LOGS.length && (
        <div className="term-entry term-entry--loading">
          <span className="term-spinner">⠋</span>
          <span className="term-msg term-msg--dim">Processing...</span>
        </div>
      )}

      <div ref={bottomRef} />
    </div>
  )
}

function ProblemsPanel() {
  return (
    <div className="term-body">
      <div className="term-problems-summary">
        <span style={{ color: 'var(--red)' }}>● 1 Critical</span>
        <span style={{ color: 'var(--orange)' }}>● 2 High</span>
        <span style={{ color: 'var(--gold)' }}>● 2 Medium</span>
      </div>
      {PROBLEMS.map((p, i) => (
        <div key={i} className="term-problem">
          <span className="term-problem__sev" style={{ color: SEV_COLORS[p.sev] }}>
            [{p.sev.toUpperCase()}]
          </span>
          <span className="term-problem__file">{p.file}</span>
          <span className="term-problem__line">:{p.line}</span>
          <span className="term-problem__msg">{p.msg}</span>
        </div>
      ))}
    </div>
  )
}

function OutputPanel() {
  return (
    <div className="term-body">
      <div className="term-prompt">
        <span className="term-prompt__char">&gt;&nbsp;</span>
        <span className="term-prompt__cmd">Raw tool output — alphaweb orchestrator v1.0</span>
      </div>
      {[
        'INFO  Orchestrator started (pid: 4821)',
        'INFO  Loaded config: android_main_apk_analysis.yaml',
        'INFO  Container pool: 3 available slots',
        'DEBUG Pulling image: alphaweb/apktool:2.9.3',
        'DEBUG Image already present, skipping pull',
        'INFO  apktool[a3f9b2c1]: STARTED',
        'INFO  apktool[a3f9b2c1]: decompile OK (exit 0)',
        'INFO  semgrep[d4e5f6a7]: STARTED',
        'WARN  semgrep: 3 rule matches on mobile-security',
        'INFO  Writing report: ./Reports/semgrep_results.json',
        'INFO  Pipeline stage 2/5 complete',
      ].map((line, i) => (
        <div key={i} className="term-entry">
          <span className="term-msg" style={{
            color: line.startsWith('WARN') ? 'var(--orange)'
                 : line.startsWith('DEBUG') ? 'var(--text-dim)'
                 : 'var(--text-primary)'
          }}>{line}</span>
        </div>
      ))}
    </div>
  )
}

function DebugPanel() {
  return (
    <div className="term-body">
      {[
        { k: 'Node version',        v: 'v22.17.1' },
        { k: 'Platform',            v: 'win32 / x64' },
        { k: 'Container runtime',   v: 'Docker Desktop 4.28.0' },
        { k: 'Orchestrator PID',    v: '4821' },
        { k: 'Active containers',   v: '2 / 3 slots used' },
        { k: 'Memory usage',        v: '312 MB / 4 GB' },
        { k: 'Task queue',          v: '1 running, 0 pending' },
        { k: 'AI model',            v: 'Fine-tuned-Cyber-LM (idle)' },
        { k: 'Region',              v: 'Hyderabad' },
        { k: 'Log level',           v: 'DEBUG' },
      ].map(({ k, v }) => (
        <div key={k} className="term-debug-row">
          <span className="term-debug-key">{k}</span>
          <span className="term-debug-val">{v}</span>
        </div>
      ))}
    </div>
  )
}

// ── Terminal ──────────────────────────────────────────────────────────────────
export default function Terminal({ clearKey = 0, maximized = false, onClear, onMaximize, onClose }) {
  const [visibleCount, setVisibleCount] = useState(0)
  const [activeTab,    setActiveTab]    = useState('console')
  const bottomRef = useRef(null)

  // Reset log stream on clear
  useEffect(() => { setVisibleCount(0) }, [clearKey])

  // Stream in logs
  useEffect(() => {
    if (activeTab !== 'console') return
    if (visibleCount >= LOGS.length) return
    const t = setTimeout(() => setVisibleCount(v => v + 1), 220)
    return () => clearTimeout(t)
  }, [visibleCount, activeTab])

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [visibleCount])

  const TABS = [
    { id: 'console',  label: 'TOOL ORCHESTRATION CONSOLE', dot: true },
    { id: 'problems', label: 'PROBLEMS', badge: PROBLEMS.length },
    { id: 'output',   label: 'OUTPUT' },
    { id: 'debug',    label: 'DEBUG' },
  ]

  return (
    <section className={`terminal ${maximized ? 'terminal--maximized' : ''}`}>
      {/* ── Header ── */}
      <div className="term-header">
        <div className="term-tabs">
          {TABS.map(tab => (
            <button
              key={tab.id}
              className={`term-tab ${activeTab === tab.id ? 'term-tab--active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.dot && <span className="term-tab__dot" />}
              {tab.label}
              {tab.badge != null && (
                <span className="term-tab__badge">{tab.badge}</span>
              )}
            </button>
          ))}
        </div>

        <div className="term-controls">
          <button className="term-ctrl" title="Clear console"  onClick={onClear}>⊘</button>
          <button className="term-ctrl" title={maximized ? 'Restore' : 'Maximise'} onClick={onMaximize}>
            {maximized ? '⤡' : '⤢'}
          </button>
          <button className="term-ctrl term-ctrl--close" title="Close terminal" onClick={onClose}>✕</button>
        </div>
      </div>

      {/* ── Panel ── */}
      {activeTab === 'console'  && <ConsolePanel  visible={visibleCount} bottomRef={bottomRef} />}
      {activeTab === 'problems' && <ProblemsPanel />}
      {activeTab === 'output'   && <OutputPanel />}
      {activeTab === 'debug'    && <DebugPanel />}
    </section>
  )
}

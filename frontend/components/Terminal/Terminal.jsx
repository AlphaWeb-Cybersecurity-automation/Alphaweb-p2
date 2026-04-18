import { useEffect, useRef, useState } from 'react'
import './Terminal.css'

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
function ConsolePanel({ logs, bottomRef }) {
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  return (
    <div className="term-body">
      <div className="term-prompt">
        <span className="term-prompt__user">alphaweb</span>
        <span className="term-prompt__at">@</span>
        <span className="term-prompt__host">hyderabad</span>
        <span className="term-prompt__sep">:</span>
        <span className="term-prompt__path">~</span>
        <span className="term-prompt__char">$&nbsp;</span>
        <span className="term-prompt__cmd blink">▋</span>
      </div>

      {logs.map((log, i) => {
        if (log.type === 'cmd') {
          return (
            <div key={i} className="term-prompt" style={{ marginTop: 6 }}>
              <span className="term-prompt__user">alphaweb</span>
              <span className="term-prompt__at">@</span>
              <span className="term-prompt__host">hyderabad</span>
              <span className="term-prompt__sep">:</span>
              <span className="term-prompt__path">~</span>
              <span className="term-prompt__char">$&nbsp;</span>
              <span className="term-prompt__cmd">{log.msg}</span>
            </div>
          )
        }
        return (
          <div key={i} className={`term-entry term-entry--${log.type}`}>
            <span className="term-ts">{log.ts}</span>
            <span className={`term-icon term-icon--${log.type}`}>{log.icon}</span>
            <span className="term-msg">{log.msg}</span>
            {log.detail && (
              <span className={`term-detail term-detail--${log.type}`}>&nbsp;{log.detail}</span>
            )}
          </div>
        )
      })}

      {logs.length === 0 && (
        <div className="term-entry term-entry--info" style={{ opacity: 0.4, paddingTop: 8 }}>
          <span className="term-msg">Waiting for scan output...</span>
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
export default function Terminal({ clearKey = 0, logs = [], maximized = false, onClear, onMaximize, onClose }) {
  const [activeTab, setActiveTab] = useState('console')
  const bottomRef = useRef(null)

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
      {activeTab === 'console'  && <ConsolePanel  logs={logs} bottomRef={bottomRef} />}
      {activeTab === 'problems' && <ProblemsPanel />}
      {activeTab === 'output'   && <OutputPanel />}
      {activeTab === 'debug'    && <DebugPanel />}
    </section>
  )
}

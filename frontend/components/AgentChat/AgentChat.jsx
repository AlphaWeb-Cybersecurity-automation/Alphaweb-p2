import { useEffect, useRef, useState } from 'react'
import './AgentChat.css'

function ts() {
  return new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function classifyLine(line) {
  const l = line.trim()
  if (/\bopen\b/i.test(l))                       return { type: 'success', icon: '✓', msg: l, ts: ts() }
  if (/warning|warn/i.test(l))                    return { type: 'warning', icon: '!', msg: l, ts: ts() }
  if (/error|failed|refused/i.test(l))            return { type: 'error',   icon: '✗', msg: l, ts: ts() }
  if (/done|complete|finished|scanned/i.test(l))  return { type: 'success', icon: '✓', msg: l, ts: ts() }
  if (/filtered|closed/i.test(l))                 return { type: 'dim',     icon: '·', msg: l, ts: ts() }
  return { type: 'info', icon: '▶', msg: l, ts: ts() }
}

export default function AgentChat({ onScanOutput }) {
  const [messages,    setMessages]    = useState([])
  const [input,       setInput]       = useState('')
  const [domain,      setDomain]      = useState('')
  const [domainError, setDomainError] = useState('')
  const [loading,     setLoading]     = useState(false)
  const [modelStatus, setModelStatus] = useState('Idle')
  const endRef   = useRef(null)
  const inputRef = useRef(null)
  const abortRef = useRef(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  function validateDomain(val) {
    const v = val.trim()
    if (!v) return 'Domain or IP required'
    if (v.includes(' ')) return 'No spaces allowed'
    return ''
  }

  async function send() {
    const text = input.trim()
    if (!text || loading) return

    const err = validateDomain(domain)
    if (err) { setDomainError(err); return }
    setDomainError('')

    setMessages(m => [...m, { id: Date.now(), role: 'user', content: text, ts: ts() }])
    setInput('')
    setLoading(true)
    setModelStatus('Running tools...')

    onScanOutput?.([{ type: 'pending', icon: '⟳', msg: `Dispatching: ${text}`, detail: `→ ${domain.trim()}`, ts: ts() }])

    const controller = new AbortController()
    abortRef.current = controller

    try {
      const res = await fetch('/api/chat/stream', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ prompt: text, domain: domain.trim() }),
        signal:  controller.signal,
      })

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`)
      }

      const reader  = res.body.getReader()
      const decoder = new TextDecoder()
      let   buffer  = ''
      let   toolsUsed = ''

      while (true) {
        const { value, done } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() // keep incomplete last chunk

        for (const raw of lines) {
          if (!raw.startsWith('data: ')) continue
          const payload = raw.slice(6).trim()
          if (!payload) continue

          let evt
          try { evt = JSON.parse(payload) } catch { continue }

          if (evt.type === 'heartbeat') continue

          if (evt.type === 'tool_start') {
            setModelStatus(`Running ${evt.tool}...`)
            onScanOutput?.([{ type: 'cmd', icon: '$', msg: `${evt.tool} ${domain.trim()}`, ts: ts() }])
          }

          if (evt.type === 'tool_line') {
            onScanOutput?.([classifyLine(evt.line)])
          }

          if (evt.type === 'tool_done') {
            const status = evt.exit_code === 0 ? 'success' : 'warning'
            onScanOutput?.([{
              type: status, icon: evt.exit_code === 0 ? '✓' : '!',
              msg: `${evt.tool} finished (exit ${evt.exit_code})`, ts: ts(),
            }])
          }

          if (evt.type === 'error') {
            onScanOutput?.([{ type: 'error', icon: '✗', msg: evt.message, ts: ts() }])
            setMessages(m => [...m, {
              id: Date.now() + 1, role: 'ai',
              content: `[ERROR] ${evt.message}`, ts: ts(),
            }])
          }

          if (evt.type === 'analysis') {
            toolsUsed = evt.tool_used || ''
            setModelStatus('Analyzing...')
            setMessages(m => [...m, {
              id:      Date.now() + 1,
              role:    'ai',
              content: evt.content,
              tool:    toolsUsed,
              ts:      ts(),
            }])
          }

          if (evt.type === 'done') break
        }
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        onScanOutput?.([{ type: 'error', icon: '✗', msg: `Connection error: ${e.message}`, ts: ts() }])
        setMessages(m => [...m, {
          id: Date.now() + 1, role: 'ai',
          content: `Connection error: ${e.message}`, ts: ts(),
        }])
      }
    } finally {
      setLoading(false)
      setModelStatus('Idle')
      abortRef.current = null
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }

  return (
    <section className="agent-chat">
      {/* ── Header ── */}
      <div className="ac-header">
        <div className="ac-header-row">
          <span className="ac-title-text">AlphaWeb Agent</span>
          <div className="ac-model-row">
            <span className="ac-model-dot" />
            <span className="ac-model-name">ALPHA-LLM</span>
            <span className="ac-model-status">{modelStatus}</span>
          </div>
        </div>
        <p className="ac-subtitle">AI-POWERED CYBERSECURITY AUTOMATION PLATFORM</p>
      </div>

      {/* ── Messages ── */}
      <div className="ac-messages">
        {messages.length === 0 && (
          <div className="ac-empty">
            <div className="ac-empty__icon">⍺</div>
            <p className="ac-empty__title">Ready</p>
            <p className="ac-empty__sub">Set a target domain above, then describe what to do.</p>
            <div className="ac-examples">
              <span className="ac-example">"scan for open ports" → nmap</span>
              <span className="ac-example">"check web vulnerabilities" → nikto</span>
              <span className="ac-example">"test for SQL injection" → sqlmap</span>
            </div>
          </div>
        )}

        {messages.map(msg => (
          <div key={msg.id} className={`ac-msg ac-msg--${msg.role}`}>
            <div className="ac-msg__head">
              <span className="ac-msg__author">
                {msg.role === 'user' ? '[User]' : '[BarronLLM]'}
              </span>
              <div className="ac-msg__head-right">
                {msg.tool && msg.tool.split(', ').map(t => (
                  <span key={t} className="ac-msg__tool">{t.toUpperCase()}</span>
                ))}
                <span className="ac-msg__ts">{msg.ts}</span>
              </div>
            </div>
            <div className="ac-msg__body">{msg.content}</div>
          </div>
        ))}

        {loading && (
          <div className="ac-msg ac-msg--ai">
            <div className="ac-msg__head">
              <span className="ac-msg__author">[BarronLLM]</span>
            </div>
            <div className="ac-msg__body ac-msg__body--typing">
              <span className="ac-dot" /><span className="ac-dot" /><span className="ac-dot" />
            </div>
          </div>
        )}

        <div ref={endRef} />
      </div>

      {/* ── Target Domain ── */}
      <div className="ac-domain-section">
        <label className="ac-domain-label">TARGET DOMAIN / IP</label>
        <div className="ac-domain-row">
          <input
            className={`ac-domain-input ${domainError ? 'ac-domain-input--error' : domain ? 'ac-domain-input--ok' : ''}`}
            placeholder="https://example.com  or  192.168.1.1"
            value={domain}
            onChange={e => { setDomain(e.target.value); setDomainError('') }}
            onBlur={() => domain && setDomainError(validateDomain(domain))}
          />
          {domain && !domainError && <span className="ac-domain-check">✓</span>}
        </div>
        {domainError && <p className="ac-domain-err">{domainError}</p>}
      </div>

      {/* ── Input ── */}
      <div className="ac-input-row">
        <input
          ref={inputRef}
          className="ac-input"
          placeholder="Describe what to scan… (e.g. scan open ports)"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && !e.shiftKey && send()}
          disabled={loading}
        />
        <button
          className={`ac-send ${loading ? 'ac-send--loading' : ''}`}
          onClick={send}
          disabled={loading}
          title="Send"
        >
          {loading ? '⟳' : '↑'}
        </button>
      </div>
    </section>
  )
}

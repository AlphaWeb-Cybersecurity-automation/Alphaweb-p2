import { useEffect, useRef, useState } from 'react'
import './AgentChat.css'

const TOOLS = ['nmap','masscan','nikto','sqlmap','ffuf','gobuster','john','hydra','curl','tcpdump']

function ts() {
  return new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function parseToTermLogs(rawOutput, toolsStr, target) {
  const entries = []
  const tools = toolsStr.split(', ')

  // Split combined output by === TOOL === headers
  const sections = rawOutput.split(/\n=== ([A-Z0-9_]+)(?: ERROR)? ===\n/)
  // sections: [pre, toolName, content, toolName, content, ...]
  // If no headers (single tool legacy), treat whole output as one block
  if (sections.length <= 1) {
    entries.push({ type: 'cmd', icon: '$', msg: `${tools[0] || 'tool'} ${target}`, ts: ts() })
    for (const line of rawOutput.split('\n').filter(l => l.trim())) {
      entries.push(...[classifyLine(line)])
    }
    return entries
  }

  for (let i = 1; i < sections.length; i += 2) {
    const toolHeader = sections[i].toLowerCase()
    const content    = sections[i + 1] || ''
    entries.push({ type: 'cmd', icon: '$', msg: `${toolHeader} ${target}`, ts: ts() })
    for (const line of content.split('\n').filter(l => l.trim())) {
      entries.push(classifyLine(line))
    }
  }
  return entries
}

function classifyLine(line) {
  const l = line.trim()
  if (/\bopen\b/i.test(l))                            return { type: 'success', icon: '✓', msg: l, ts: ts() }
  if (/warning|warn/i.test(l))                         return { type: 'warning', icon: '!', msg: l, ts: ts() }
  if (/error|failed|refused/i.test(l))                 return { type: 'error',   icon: '✗', msg: l, ts: ts() }
  if (/done|complete|finished|scanned/i.test(l))       return { type: 'success', icon: '✓', msg: l, ts: ts() }
  if (/filtered|closed/i.test(l))                      return { type: 'dim',     icon: '·', msg: l, ts: ts() }
  return { type: 'info', icon: '▶', msg: l, ts: ts() }
}

export default function AgentChat({ onScanOutput }) {
  const [messages,    setMessages]    = useState([])
  const [input,       setInput]       = useState('')
  const [domain,      setDomain]      = useState('')
  const [domainError, setDomainError] = useState('')
  const [loading,     setLoading]     = useState(false)
  const [modelStatus, setModelStatus] = useState('Idle')
  const endRef    = useRef(null)
  const inputRef  = useRef(null)

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
    setModelStatus('Processing...')

    // Push "starting" entry to terminal
    onScanOutput?.([{ type: 'pending', icon: '⟳', msg: `Dispatching: ${text}`, detail: `→ ${domain.trim()}`, ts: ts() }])

    try {
      const res = await fetch('/api/chat', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ prompt: text, domain: domain.trim() }),
      })

      const data = await res.json()

      // Push raw output lines to terminal console
      if (data.raw_output && data.tool_used) {
        onScanOutput?.(parseToTermLogs(data.raw_output, data.tool_used, domain.trim()))
      }

      let content
      if (data.error) {
        content = `[ERROR] ${data.error}`
        if (data.ai_message) content += `\n\n${data.ai_message}`
        onScanOutput?.([{ type: 'error', icon: '✗', msg: data.error, ts: ts() }])
      } else {
        content = data.ai_message || 'Scan complete.'
      }

      setMessages(m => [...m, {
        id:    Date.now() + 1,
        role:  'ai',
        content,
        tool:  data.tool_used,
        ts:    ts(),
      }])
    } catch (e) {
      onScanOutput?.([{ type: 'error', icon: '✗', msg: `Connection error: ${e.message}`, ts: ts() }])
      setMessages(m => [...m, {
        id:      Date.now() + 1,
        role:    'ai',
        content: `Connection error: ${e.message}`,
        ts:      ts(),
      }])
    } finally {
      setLoading(false)
      setModelStatus('Idle')
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }

  return (
    <section className="agent-chat">
      {/* ── Header ── */}
      <div className="ac-header">
        <pre className="ac-ascii">{
`╔═╗╦  ╔═╗╦ ╦╔═╗  ╦ ╦╔═╗╔╗
╠═╣║  ╠═╝╠═╣╠═╣  ║║║║╣ ╠╩╗
╩ ╩╩═╝╩  ╩ ╩╩ ╩  ╚╩╝╚═╝╚═╝
  ╔═╗╔═╗╔═╗╔╗╔╔╦╗
  ╠═╣║ ╦║╣ ║║║ ║
  ╩ ╩╚═╝╚═╝╝╚╝ ╩          `
        }</pre>
        <p className="ac-subtitle">AI-POWERED CYBERSECURITY AUTOMATION PLATFORM</p>
        <p className="ac-badge">🛡 DEFENSIVE SECURITY ONLY 🔐</p>
        <div className="ac-model-row">
          <span className="ac-model-dot" />
          <span className="ac-model-name">BarronLLM</span>
          <span className="ac-model-status">{modelStatus}</span>
        </div>
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
        <p className="ac-domain-hint">
          Tools: {TOOLS.join(' · ')}
        </p>
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

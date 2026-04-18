import { useEffect, useRef, useState } from 'react'
import './AgentChat.css'

const INIT_MESSAGES = [
  {
    id: 1,
    role: 'user',
    content: 'Decompile and analyze android_main_apk.apk for security vulnerabilities. Focus on hardcoded secrets and insecure API calls.',
    ts: '09:14:00',
  },
  {
    id: 2,
    role: 'ai',
    content: `Analyzing APK decompilation plan... Initializing apktool orchestration for android_main_apk.apk.

I'm finding patterns of hardcoded API keys in the decompiled source. Detected in MainActivity.java at line 47:

  API_KEY = "sk-proj-..."

This is a critical exposure risk. Recommend immediate key rotation and implementing secure secret management (Android Keystore API).

Continuing analysis with semgrep mobile-security ruleset...`,
    ts: '09:14:04',
  },
  {
    id: 3,
    role: 'user',
    content: 'What other vulnerabilities should I look for?',
    ts: '09:14:20',
  },
  {
    id: 4,
    role: 'ai',
    content: `Based on the decompilation output, I recommend scanning for:

• Insecure data storage (SharedPreferences unencrypted)
• Weak cryptographic implementations (MD5/SHA1 detected)
• Exposed broadcast receivers with no permission guards
• Improper certificate validation (TrustAll pattern found)
• Excessive permission requests in AndroidManifest.xml

Running extended semgrep ruleset now...`,
    ts: '09:14:22',
  },
]

const AI_REPLY = `Processing your query against the current scan context. Analyzing decompiled artifacts and cross-referencing with the mobile-security ruleset.

I'll update you with findings shortly.`

export default function AgentChat() {
  const [messages, setMessages] = useState(INIT_MESSAGES)
  const [input, setInput]       = useState('')
  const [typing, setTyping]     = useState(false)
  const endRef = useRef(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, typing])

  function now() {
    return new Date().toLocaleTimeString('en-GB', {
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  }

  function send() {
    const text = input.trim()
    if (!text) return
    setMessages(m => [...m, { id: Date.now(), role: 'user', content: text, ts: now() }])
    setInput('')
    setTyping(true)
    setTimeout(() => {
      setTyping(false)
      setMessages(m => [...m, { id: Date.now() + 1, role: 'ai', content: AI_REPLY, ts: now() }])
    }, 1800)
  }

  return (
    <section className="agent-chat">
      {/* ── Header ───────────────────────────────────── */}
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
          <span className="ac-model-name">Fine-tuned-Cyber-LM</span>
          <span className="ac-model-status">Idle</span>
        </div>
      </div>

      {/* ── Messages ─────────────────────────────────── */}
      <div className="ac-messages">
        {messages.map(msg => (
          <div key={msg.id} className={`ac-msg ac-msg--${msg.role}`}>
            <div className="ac-msg__head">
              <span className="ac-msg__author">
                {msg.role === 'user' ? '[User]' : '[AlphaWeb AI]'}
              </span>
              <span className="ac-msg__ts">{msg.ts}</span>
            </div>
            <div className="ac-msg__body">{msg.content}</div>
          </div>
        ))}

        {typing && (
          <div className="ac-msg ac-msg--ai">
            <div className="ac-msg__head">
              <span className="ac-msg__author">[AlphaWeb AI]</span>
            </div>
            <div className="ac-msg__body ac-msg__body--typing">
              <span className="ac-dot" /><span className="ac-dot" /><span className="ac-dot" />
            </div>
          </div>
        )}

        <div ref={endRef} />
      </div>

      {/* ── Input ────────────────────────────────────── */}
      <div className="ac-input-row">
        <input
          className="ac-input"
          placeholder="Ask AlphaWeb AI..."
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && send()}
        />
        <button className="ac-send" onClick={send} title="Send">↑</button>
      </div>
    </section>
  )
}

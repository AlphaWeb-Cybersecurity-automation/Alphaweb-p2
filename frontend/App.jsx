import { useState, useCallback, useRef } from 'react'
import ActivityBar from './components/ActivityBar/ActivityBar.jsx'
import SideBar     from './components/SideBar/SideBar.jsx'
import Editor      from './components/Editor/Editor.jsx'
import Terminal    from './components/Terminal/Terminal.jsx'
import AgentChat   from './components/AgentChat/AgentChat.jsx'
import StatusBar   from './components/StatusBar/StatusBar.jsx'
import './App.css'

export default function App() {
  const [activeView, setActiveView] = useState('scanner')

  // Editor open tabs
  const [openFiles, setOpenFiles]   = useState([])
  const [activeFile, setActiveFile] = useState(null)

  // Terminal controls
  const [termVisible,   setTermVisible]   = useState(true)
  const [termMaximized, setTermMaximized] = useState(false)
  const [termClearKey,  setTermClearKey]  = useState(0)

  // Terminal console logs (from scan output)
  const [termLogs, setTermLogs] = useState([])
  const addTermLogs = useCallback((lines) => setTermLogs(prev => [...prev, ...lines]), [])

  // Toast
  const [toast, setToast] = useState(null)

  function showToast(msg, type = 'success') {
    setToast({ msg, type })
    setTimeout(() => setToast(null), 3200)
  }

  const openFile = useCallback((file) => {
    setOpenFiles(prev =>
      prev.find(f => f.name === file.name) ? prev : [...prev, file]
    )
    setActiveFile(file.name)
  }, [])

  const closeTab = useCallback((name) => {
    setOpenFiles(prev => {
      const next = prev.filter(f => f.name !== name)
      if (activeFile === name) {
        setActiveFile(next.length > 0 ? next[next.length - 1].name : null)
      }
      return next
    })
  }, [activeFile])

  return (
    <div className={[
      'app',
      termMaximized  ? 'app--term-max'    : '',
      !termVisible   ? 'app--term-hidden' : '',
    ].join(' ')}>

      <ActivityBar activeView={activeView} setActiveView={setActiveView} />

      <SideBar
        activeView={activeView}
        activeFile={activeFile}
        onFileOpen={openFile}
        onToast={showToast}
      />

      <Editor
        openFiles={openFiles}
        activeFile={activeFile}
        onTabClick={setActiveFile}
        onCloseTab={closeTab}
      />

      <AgentChat onScanOutput={addTermLogs} />

      <Terminal
        clearKey={termClearKey}
        logs={termLogs}
        maximized={termMaximized}
        visible={termVisible}
        onClear={() => { setTermClearKey(k => k + 1); setTermLogs([]); showToast('Console cleared', 'info') }}
        onMaximize={() => setTermMaximized(m => !m)}
        onClose={() => setTermVisible(false)}
      />

      <StatusBar
        activeFile={activeFile}
        termVisible={termVisible}
        onReopenTerminal={() => setTermVisible(true)}
      />

      {toast && (
        <div className={`toast toast--${toast.type}`} key={`${toast.msg}-${Date.now()}`}>
          <span>{toast.type === 'success' ? '✓' : toast.type === 'error' ? '✗' : 'ℹ'}</span>
          {toast.msg}
        </div>
      )}
    </div>
  )
}

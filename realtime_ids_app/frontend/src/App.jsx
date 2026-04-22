import { useState, useEffect, useRef, useCallback } from 'react'
import Sidebar from './components/Sidebar'
import Dashboard from './views/Dashboard'
import JuiceShop from './views/JuiceShop'
import BlockedIPs from './views/BlockedIPs'
import AttackPanel from './views/AttackPanel'

const WS_URL = `ws://${window.location.host}/ws`

export default function App() {
  const [mode, setMode] = useState('ids')           // 'ids' | 'attack'
  const [view, setView] = useState('dashboard')
  const [wsData, setWsData] = useState(null)
  const [wsConnected, setWsConnected] = useState(false)
  const [interfaces, setInterfaces] = useState([])
  const [ifacesLoading, setIfacesLoading] = useState(true)
  const [selectedIface, setSelectedIface] = useState('')
  const [jsPort, setJsPort] = useState(3000)
  const [isRunning, setIsRunning] = useState(false)
  const [simMode, setSimMode] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const wsRef = useRef(null)
  const reconnRef = useRef(null)

  // WebSocket
  useEffect(() => {
    function connect() {
      const ws = new WebSocket(WS_URL)
      wsRef.current = ws
      ws.onopen = () => setWsConnected(true)
      ws.onmessage = (e) => {
        try { setWsData(JSON.parse(e.data)) } catch {}
      }
      ws.onclose = () => {
        setWsConnected(false)
        reconnRef.current = setTimeout(connect, 2000)
      }
    }
    connect()
    return () => {
      clearTimeout(reconnRef.current)
      wsRef.current?.close()
    }
  }, [])

  // Auto-collapse sidebar on narrow screens
  useEffect(() => {
    const check = () => setSidebarCollapsed(window.innerWidth < 768)
    check()
    window.addEventListener('resize', check)
    return () => window.removeEventListener('resize', check)
  }, [])

  // Load interfaces
  const loadInterfaces = useCallback(async () => {
    setIfacesLoading(true)
    try {
      const d = await fetch('/api/interfaces').then(r => r.json())
      const ifaces = d.interfaces || []
      setInterfaces(ifaces)
      if (ifaces.length && !selectedIface) {
        setSelectedIface(ifaces[0].value || ifaces[0])
      }
    } catch {}
    setIfacesLoading(false)
  }, [selectedIface])

  useEffect(() => { loadInterfaces() }, [])

  // Sync initial running state from REST (handles page refresh while backend is running)
  useEffect(() => {
    fetch('/api/status').then(r => r.json()).then(d => {
      setIsRunning(d.running === true)
      setSimMode(d.simulation_mode === true)
    }).catch(() => {})
  }, [])

  // Sync running state from WS (live updates)
  useEffect(() => {
    if (wsData != null) setIsRunning(wsData.running === true)
  }, [wsData?.running])

  const startCapture = async () => {
    if (!selectedIface) return
    const res = await fetch('/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ interface: selectedIface, juiceshop_port: jsPort, simulation_mode: simMode }),
    }).then(r => r.json())
    if (res.ok) setIsRunning(true)
    else alert(res.msg || 'Failed to start capture')
  }

  const stopCapture = async () => {
    await fetch('/api/stop', { method: 'POST' })
    setIsRunning(false)
  }

  const blockIP = async (ip) => {
    await fetch('/api/block', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    })
  }

  const unblockIP = async (ip) => {
    await fetch('/api/unblock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip }),
    })
  }

  const controls = {
    interfaces,
    ifacesLoading,
    loadInterfaces,
    selectedIface,
    setSelectedIface,
    jsPort,
    setJsPort,
    isRunning,
    startCapture,
    stopCapture,
    simMode,
    setSimMode,
  }

  const blockedIPs = wsData?.juiceshop?.blocked_ips || wsData?.blocked_ips || []

  return (
    <div className="flex h-screen bg-slate-50 font-sans overflow-hidden">
      <Sidebar
        view={view}
        setView={setView}
        mode={mode}
        isRunning={isRunning}
        wsConnected={wsConnected}
        collapsed={sidebarCollapsed}
        onToggle={() => setSidebarCollapsed(v => !v)}
      />

      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        {/* Mode toggle bar */}
        <div className="flex-shrink-0 bg-white border-b border-gray-100 px-6 py-3 flex items-center gap-4">
          <div className="flex items-center bg-slate-100 rounded-xl p-1 gap-1">
            <button
              onClick={() => setMode('ids')}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                mode === 'ids'
                  ? 'bg-indigo-600 text-white shadow-sm'
                  : 'text-slate-500 hover:text-slate-700'
              }`}
            >
              IDS Monitor
            </button>
            <button
              onClick={() => setMode('attack')}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                mode === 'attack'
                  ? 'bg-red-500 text-white shadow-sm'
                  : 'text-slate-500 hover:text-slate-700'
              }`}
            >
              Attack Simulator
            </button>
          </div>

          {isRunning && mode === 'ids' && (
            <div className="flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
              <span className="text-xs font-semibold text-green-600 uppercase tracking-wide">Live</span>
            </div>
          )}

          {mode === 'attack' && !isRunning && (
            <div className="flex items-center gap-2 text-xs text-amber-600 bg-amber-50 border border-amber-100 px-3 py-1.5 rounded-lg">
              <span className="font-semibold">Tip:</span>
              Start IDS capture first to detect attacks in real-time
            </div>
          )}
        </div>

        {/* Content */}
        <main className="flex-1 overflow-y-auto">
          {mode === 'attack' ? (
            <AttackPanel />
          ) : (
            <>
              {view === 'dashboard' && (
                <Dashboard data={wsData?.general} controls={controls} onBlock={blockIP} />
              )}
              {view === 'juiceshop' && (
                <JuiceShop data={wsData?.juiceshop} onBlock={blockIP} />
              )}
              {view === 'blocked' && (
                <BlockedIPs blockedIPs={blockedIPs} onUnblock={unblockIP} />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  )
}

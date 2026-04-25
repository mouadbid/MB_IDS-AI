import { useState, useEffect, useRef, useCallback } from 'react'
import AttackPanel from './views/AttackPanel'
import Defender from './views/Defender'
import { Sword, Shield, Wifi, WifiOff } from 'lucide-react'

const WS_URL = `ws://${window.location.host}/ws`

export default function App() {
  const [mode, setMode] = useState('defender')   // 'attacker' | 'defender'
  const [wsData, setWsData] = useState(null)
  const [wsConnected, setWsConnected] = useState(false)
  const [interfaces, setInterfaces] = useState([])
  const [ifacesLoading, setIfacesLoading] = useState(true)
  const [selectedIface, setSelectedIface] = useState('')
  const [jsPort, setJsPort] = useState(4000)
  const [isRunning, setIsRunning] = useState(false)
  const [simMode, setSimMode] = useState(false)
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
    return () => { clearTimeout(reconnRef.current); wsRef.current?.close() }
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

  // Sync state from REST on mount
  useEffect(() => {
    fetch('/api/status').then(r => r.json()).then(d => {
      setIsRunning(d.running === true)
      setSimMode(d.simulation_mode === true)
    }).catch(() => {})
  }, [])

  // Sync from WebSocket
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

  const controls = { interfaces, ifacesLoading, loadInterfaces, selectedIface, setSelectedIface, jsPort, setJsPort, isRunning, startCapture, stopCapture, simMode, setSimMode }

  return (
    <div className="flex h-screen bg-slate-950 font-sans overflow-hidden">
      {/* ── Sidebar ── */}
      <aside className="w-20 flex-shrink-0 flex flex-col items-center py-6 gap-4 bg-slate-900 border-r border-slate-800">
        {/* Logo */}
        <div className="w-10 h-10 rounded-xl bg-indigo-600 flex items-center justify-center mb-4">
          <span className="text-white text-xs font-black">IDS</span>
        </div>

        {/* Defender */}
        <button
          onClick={() => setMode('defender')}
          title="Defender"
          className={`w-14 h-14 rounded-2xl flex flex-col items-center justify-center gap-1 transition-all text-xs font-semibold ${
            mode === 'defender'
              ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-900'
              : 'text-slate-400 hover:text-white hover:bg-slate-800'
          }`}
        >
          <Shield size={20} />
          <span className="text-[10px]">Defender</span>
        </button>

        {/* Attacker */}
        <button
          onClick={() => setMode('attacker')}
          title="Attacker"
          className={`w-14 h-14 rounded-2xl flex flex-col items-center justify-center gap-1 transition-all text-xs font-semibold ${
            mode === 'attacker'
              ? 'bg-red-600 text-white shadow-lg shadow-red-900'
              : 'text-slate-400 hover:text-white hover:bg-slate-800'
          }`}
        >
          <Sword size={20} />
          <span className="text-[10px]">Attacker</span>
        </button>

        {/* Spacer + status */}
        <div className="flex-1" />
        <div className="flex flex-col items-center gap-1.5">
          {wsConnected
            ? <Wifi size={14} className="text-green-400" />
            : <WifiOff size={14} className="text-slate-600" />}
          {isRunning && <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />}
        </div>
      </aside>

      {/* ── Main content ── */}
      <main className="flex-1 overflow-y-auto">
        {mode === 'defender' ? (
          <Defender
            wsData={wsData}
            wsConnected={wsConnected}
            controls={controls}
            recentFlows={wsData?.recent_flows || []}
            recentPackets={wsData?.recent_packets || []}
          />
        ) : (
          <AttackPanel jsPort={jsPort} />
        )}
      </main>
    </div>
  )
}

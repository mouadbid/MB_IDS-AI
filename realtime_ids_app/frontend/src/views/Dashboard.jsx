import { useRef } from 'react'
import { Activity, AlertTriangle, TrendingUp, Play, Square, ChevronDown, RefreshCw, FlaskConical } from 'lucide-react'
import StatCard from '../components/StatCard'
import AlertsTable from '../components/AlertsTable'
import { TimelineChart, AttackDonut } from '../components/charts'

export default function Dashboard({ data, controls, onBlock }) {
  const alertsRef = useRef(null)
  const scrollToAlerts = () => alertsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  const stats = data?.stats || {}
  const {
    interfaces, ifacesLoading, loadInterfaces,
    selectedIface, setSelectedIface,
    jsPort, setJsPort,
    isRunning, startCapture, stopCapture,
    simMode, setSimMode,
  } = controls

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-sm text-gray-400 mt-0.5">All network interfaces</p>
        </div>

        {/* Capture controls */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Interface selector */}
          <div className="flex items-center gap-1.5">
            <div className="relative">
              <select
                value={selectedIface}
                onChange={e => setSelectedIface(e.target.value)}
                disabled={ifacesLoading || isRunning}
                className="appearance-none pl-3 pr-8 py-2 bg-white border border-gray-200 rounded-xl text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-200 cursor-pointer max-w-[180px] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {ifacesLoading && (
                  <option value="">Loading interfaces…</option>
                )}
                {!ifacesLoading && interfaces.length === 0 && (
                  <option value="">No interfaces found</option>
                )}
                {interfaces.map((iface, i) => {
                  const value = typeof iface === 'object' ? iface.value : iface
                  const label = typeof iface === 'object' ? iface.label : iface
                  return <option key={i} value={value}>{label}</option>
                })}
              </select>
              <ChevronDown size={13} className="absolute right-2.5 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none" />
            </div>
            <button
              onClick={loadInterfaces}
              disabled={ifacesLoading || isRunning}
              title="Reload interfaces"
              className="p-2 bg-white border border-gray-200 rounded-xl text-gray-400 hover:text-gray-600 hover:bg-gray-50 disabled:opacity-40 transition-colors"
            >
              <RefreshCw size={13} className={ifacesLoading ? 'animate-spin' : ''} />
            </button>
          </div>

          <input
            type="number"
            value={jsPort}
            onChange={e => setJsPort(parseInt(e.target.value) || 3000)}
            disabled={isRunning}
            className="w-20 px-3 py-2 bg-white border border-gray-200 rounded-xl text-sm text-center text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-200 disabled:opacity-50"
            placeholder="3000"
          />

          <button
            onClick={() => setSimMode(v => !v)}
            disabled={isRunning}
            title="Real-World Simulation: scales IAT ×16 and caps TCP window to 8192 to match CICIDS LAN training distribution. ML threshold lowered to 5%."
            className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-medium border transition-all disabled:opacity-40 disabled:cursor-not-allowed ${
              simMode
                ? 'bg-violet-600 text-white border-violet-600 shadow-sm'
                : 'bg-white text-gray-500 border-gray-200 hover:border-violet-300 hover:text-violet-600'
            }`}
          >
            <FlaskConical size={13} />
            {simMode ? 'Sim ON' : 'Sim'}
          </button>

          {!isRunning ? (
            <button
              onClick={startCapture}
              disabled={!selectedIface}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-xl text-sm font-medium hover:bg-indigo-700 active:scale-95 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play size={13} />
              Start
            </button>
          ) : (
            <button
              onClick={stopCapture}
              className="flex items-center gap-2 px-4 py-2 bg-red-500 text-white rounded-xl text-sm font-medium hover:bg-red-600 active:scale-95 transition-all"
            >
              <Square size={13} />
              Stop
            </button>
          )}
        </div>
      </div>

      {/* Sim mode banner */}
      {simMode && isRunning && (
        <div className="flex items-start gap-2.5 bg-violet-50 border border-violet-100 rounded-xl px-4 py-3 text-sm text-violet-700">
          <FlaskConical size={15} className="flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold">Real-World Simulation active</span>
            <span className="text-violet-500 ml-2 text-xs">
              IAT ×16 · TCP window capped to 8192 · ML threshold 5% · Rule detections labeled <span className="font-mono bg-violet-100 px-1 rounded">Rule</span>
            </span>
          </div>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-4">
        <StatCard
          title="Total Packets"
          value={(stats.packets ?? 0).toLocaleString()}
          subtitle="Captured on interface"
          icon={Activity}
          color="yellow"
        />
        <StatCard
          title="Attacks Detected"
          value={(stats.attacks ?? 0).toLocaleString()}
          subtitle={`${(stats.flows ?? 0).toLocaleString()} flows analyzed`}
          icon={AlertTriangle}
          color="pink"
          onDetails={scrollToAlerts}
        />
        <StatCard
          title="Attack Rate"
          value={`${stats.rate ?? 0}%`}
          subtitle="of completed flows"
          icon={TrendingUp}
          color="purple"
          onDetails={scrollToAlerts}
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-2 gap-4">
        <div className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-800">Attack Timeline</h3>
            <span className="text-xs text-gray-400 bg-gray-50 px-2 py-1 rounded-lg">attacks / sec</span>
          </div>
          <TimelineChart timeline={data?.timeline || []} />
        </div>

        <div className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-800">Attack Types</h3>
            <span className="text-xs text-gray-400 bg-gray-50 px-2 py-1 rounded-lg">breakdown</span>
          </div>
          <AttackDonut attackTypes={data?.attack_types || {}} />
        </div>
      </div>

      {/* Alerts table */}
      <div ref={alertsRef} className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-gray-800">Live Alerts</h3>
          <span className="text-xs text-gray-400">{(data?.alerts || []).length} recent</span>
        </div>
        <AlertsTable alerts={data?.alerts || []} onBlock={onBlock} />
      </div>
    </div>
  )
}

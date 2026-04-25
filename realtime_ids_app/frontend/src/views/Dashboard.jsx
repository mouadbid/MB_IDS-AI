import { useRef } from 'react'
import { Activity, AlertTriangle, TrendingUp, Play, Square, ChevronDown, RefreshCw, FlaskConical, Info } from 'lucide-react'
import StatCard from '../components/StatCard'
import AlertsTable from '../components/AlertsTable'
import { TimelineChart, AttackDonut } from '../components/charts'

export default function Dashboard({ data, controls, onBlock, recentFlows = [] }) {
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
          <h1 className="text-xl font-bold text-gray-900">IDS Monitor</h1>
          <p className="text-sm text-gray-400 mt-0.5">ML-powered intrusion detection — real-time flow classification</p>
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

      {/* Setup guide — shown when IDS is not running */}
      {!isRunning && (
        <div className="bg-blue-50 border border-blue-200 rounded-2xl p-4">
          <div className="flex items-start gap-3">
            <Info size={16} className="text-blue-500 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <div className="text-sm font-semibold text-blue-800 mb-2">⚡ Quick Setup — Capture local Juice Shop traffic</div>
              <ol className="text-xs text-blue-700 space-y-1 list-decimal list-inside">
                <li>Select the <strong>Loopback</strong> interface above (captures <span className="font-mono">127.0.0.1</span> traffic)</li>
                <li>Set the port to <strong className="font-mono">4000</strong> (your Docker container port)</li>
                <li>Click <strong>Start</strong> — the 🤖 XGBoost model begins classifying flows</li>
                <li>Switch to <strong>Attack Simulator</strong>, set target to <span className="font-mono bg-blue-100 px-1 rounded">http://127.0.0.1:4000</span> and launch attacks</li>
              </ol>
              <div className="mt-2 text-xs text-blue-500">
                ⚠ On Windows, run the terminal as <strong>Administrator</strong> so Scapy/Npcap can capture loopback packets.
              </div>
            </div>
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

      {/* Live Flow Classification Feed */}
      <div className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-sm font-semibold text-gray-800">🤖 ML Model — Live Flow Classification</h3>
            <p className="text-xs text-gray-400 mt-0.5">Every network flow classified by the XGBoost model in real-time</p>
          </div>
          <div className="flex items-center gap-2">
            <span className="flex items-center gap-1 text-xs text-gray-400"><span className="w-2 h-2 rounded-full bg-red-400 inline-block" /> Attack</span>
            <span className="flex items-center gap-1 text-xs text-gray-400"><span className="w-2 h-2 rounded-full bg-green-400 inline-block" /> Benign</span>
            <span className="text-xs text-gray-300 bg-gray-50 px-2 py-1 rounded-lg">{recentFlows.length} flows</span>
          </div>
        </div>
        {recentFlows.length === 0 ? (
          <div className="text-center py-10 text-gray-300 text-sm">No flows captured yet — start IDS capture to see live classification</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-gray-400 border-b border-gray-100">
                  <th className="pb-2 pr-4 font-medium">Time</th>
                  <th className="pb-2 pr-4 font-medium">Source</th>
                  <th className="pb-2 pr-4 font-medium">Destination</th>
                  <th className="pb-2 pr-4 font-medium">Proto</th>
                  <th className="pb-2 pr-4 font-medium text-right">Pkts</th>
                  <th className="pb-2 pr-4 font-medium text-right">Bytes</th>
                  <th className="pb-2 pr-4 font-medium">ML Label</th>
                  <th className="pb-2 font-medium text-right">Conf.</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {recentFlows.slice(0, 40).map((f, i) => (
                  <tr key={i} className={`transition-colors ${
                    f.is_attack ? 'bg-red-50/60 hover:bg-red-50' : 'hover:bg-gray-50'
                  }`}>
                    <td className="py-1.5 pr-4 font-mono text-gray-400">{f.time}</td>
                    <td className="py-1.5 pr-4 font-mono text-gray-600 truncate max-w-[130px]">{f.src}</td>
                    <td className="py-1.5 pr-4 font-mono text-gray-600 truncate max-w-[130px]">{f.dst}</td>
                    <td className="py-1.5 pr-4">
                      <span className="px-1.5 py-0.5 rounded bg-gray-100 text-gray-500 font-mono">{f.proto === 6 ? 'TCP' : f.proto === 17 ? 'UDP' : f.proto || '—'}</span>
                    </td>
                    <td className="py-1.5 pr-4 text-right text-gray-500">{f.pkts}</td>
                    <td className="py-1.5 pr-4 text-right text-gray-500">{f.bytes > 1024 ? `${(f.bytes/1024).toFixed(1)}K` : f.bytes}</td>
                    <td className="py-1.5 pr-4">
                      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold ${
                        f.is_attack
                          ? 'bg-red-100 text-red-700'
                          : 'bg-green-100 text-green-700'
                      }`}>
                        {f.is_attack && <span className="w-1 h-1 rounded-full bg-red-500" />}
                        {f.label}
                      </span>
                      {f.detector && f.detector !== 'None' && (
                        <span className="ml-1.5 text-gray-300 text-xs">[{f.detector}]</span>
                      )}
                    </td>
                    <td className={`py-1.5 text-right font-mono font-semibold ${
                      f.confidence >= 80 ? 'text-red-600' :
                      f.confidence >= 50 ? 'text-orange-500' : 'text-gray-400'
                    }`}>
                      {f.confidence}%
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
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

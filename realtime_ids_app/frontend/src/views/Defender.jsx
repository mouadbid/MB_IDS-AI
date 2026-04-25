import { useState } from 'react'
import {
  Shield, Play, Square, Brain, Activity, AlertTriangle,
  TrendingUp, Zap, BarChart2, Cpu, FlaskConical, CheckCircle2,
  Info, Wifi
} from 'lucide-react'

// ── Helpers ─────────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, color }) {
  const colors = {
    blue:   'bg-blue-500/10 text-blue-400 border-blue-500/20',
    red:    'bg-red-500/10 text-red-400 border-red-500/20',
    green:  'bg-green-500/10 text-green-400 border-green-500/20',
    purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  }
  return (
    <div className={`rounded-2xl border p-4 ${colors[color]}`}>
      <div className="flex items-start justify-between">
        <Icon size={18} className="opacity-70 mt-0.5" />
        <span className="text-2xl font-black">{value}</span>
      </div>
      <div className="mt-3">
        <div className="text-sm font-semibold">{label}</div>
        {sub && <div className="text-xs opacity-60 mt-0.5">{sub}</div>}
      </div>
    </div>
  )
}

function ProtoChip({ proto }) {
  const map = {
    TCP:  'bg-blue-900/60 text-blue-300',
    UDP:  'bg-yellow-900/60 text-yellow-300',
    ICMP: 'bg-cyan-900/60 text-cyan-300',
    6:    'bg-blue-900/60 text-blue-300',
    17:   'bg-yellow-900/60 text-yellow-300',
  }
  const label = typeof proto === 'number' ? ({ 6: 'TCP', 17: 'UDP', 1: 'ICMP' }[proto] || proto) : proto
  const cls = map[proto] || map[label] || 'bg-slate-700 text-slate-300'
  return <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${cls}`}>{label || '?'}</span>
}

function LabelBadge({ label, isAttack }) {
  if (!isAttack) {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold bg-green-500/15 text-green-400">
        <CheckCircle2 size={10} />NORMAL
      </span>
    )
  }
  const colors = {
    'Web Attack  Brute Force': 'bg-orange-500/20 text-orange-300',
    'Web Attack  Sql Injection': 'bg-red-500/20 text-red-300',
    'Web Attack  XSS': 'bg-yellow-500/20 text-yellow-300',
    'DoS Hulk': 'bg-purple-500/20 text-purple-300',
    'DoS GoldenEye': 'bg-purple-500/20 text-purple-300',
  }
  const cls = colors[label] || 'bg-red-500/20 text-red-300'
  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-bold ${cls}`}>
      <AlertTriangle size={10} />{label || 'ATTACK'}
    </span>
  )
}

// ── AI Result Modal ──────────────────────────────────────────────────────────

function AIResultModal({ result, onClose }) {
  if (!result) return null
  const s = result.summary
  const isAttack = s.attack_flows > 0
  const conf = s.avg_confidence

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-slate-900 border border-slate-700 rounded-3xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        <div className={`px-6 py-5 border-b border-slate-800 ${isAttack ? 'bg-red-950/40' : 'bg-green-950/30'}`}>
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-xl ${isAttack ? 'bg-red-500/20' : 'bg-green-500/20'}`}>
              <Brain size={20} className={isAttack ? 'text-red-400' : 'text-green-400'} />
            </div>
            <div>
              <div className="text-white font-bold text-lg">🤖 AI Model Analysis</div>
              <div className="text-slate-400 text-xs">XGBoost feature-engineered prediction</div>
            </div>
            <button onClick={onClose} className="ml-auto text-slate-500 hover:text-white transition-colors text-lg">✕</button>
          </div>
        </div>

        <div className="p-6 space-y-5 max-h-[70vh] overflow-y-auto">
          <div className={`rounded-2xl border p-5 text-center ${isAttack ? 'bg-red-950/40 border-red-800/50' : 'bg-green-950/30 border-green-800/30'}`}>
            <div className="text-xs font-semibold uppercase tracking-widest text-slate-400 mb-2">Model Verdict</div>
            <div className={`text-3xl font-black ${isAttack ? 'text-red-400' : 'text-green-400'}`}>
              {isAttack ? '⚠ ' : '✓ '}{s.dominant_attack}
            </div>
            <div className="text-slate-400 text-sm mt-2">
              Avg confidence: <span className={`font-bold ${conf >= 70 ? 'text-red-400' : conf >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>{conf}%</span>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div className="bg-slate-800/60 rounded-xl p-3 text-center">
              <div className="text-2xl font-black text-white">{s.total_flows}</div>
              <div className="text-xs text-slate-400 mt-1">Flows Analyzed</div>
            </div>
            <div className="bg-red-950/50 rounded-xl p-3 text-center border border-red-900/30">
              <div className="text-2xl font-black text-red-400">{s.attack_flows}</div>
              <div className="text-xs text-slate-400 mt-1">Attack Flows</div>
            </div>
            <div className="bg-green-950/30 rounded-xl p-3 text-center border border-green-900/30">
              <div className="text-2xl font-black text-green-400">{s.benign_flows}</div>
              <div className="text-xs text-slate-400 mt-1">Normal Flows</div>
            </div>
          </div>

          {Object.keys(s.attack_breakdown).length > 0 && (
            <div className="bg-slate-800/40 rounded-2xl p-4">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Attack Type Breakdown</div>
              {Object.entries(s.attack_breakdown).map(([type, count]) => (
                <div key={type} className="flex items-center gap-3 mb-2">
                  <div className="text-xs text-slate-300 flex-1 truncate">{type}</div>
                  <div className="flex-1 bg-slate-700 rounded-full h-1.5 overflow-hidden">
                    <div className="h-full bg-red-500 rounded-full" style={{ width: `${Math.min(100, (count / s.attack_flows) * 100)}%` }} />
                  </div>
                  <span className="text-xs font-bold text-red-400 w-6 text-right">{count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main Defender View ───────────────────────────────────────────────────────

export default function Defender({ wsData, wsConnected, controls, recentFlows, recentPackets }) {
  const [analyzing, setAnalyzing] = useState(false)
  const [aiResult, setAiResult] = useState(null)
  const [aiError, setAiError] = useState('')

  const {
    jsPort, setJsPort,
    isRunning, startCapture, stopCapture,
    simMode, setSimMode,
  } = controls

  const stats = wsData?.general?.stats || {}

  const runAI = async () => {
    setAnalyzing(true)
    setAiError('')
    setAiResult(null)
    try {
      const d = await fetch('/api/suggest').then(r => r.json())
      if (d.ok) setAiResult(d)
      else setAiError(d.msg || 'Analysis failed')
    } catch (e) {
      setAiError('Cannot reach backend: ' + e.message)
    }
    setAnalyzing(false)
  }

  return (
    <div className="min-h-full bg-slate-950 text-white">

      {/* ── Top bar ── */}
      <div className="sticky top-0 z-20 bg-slate-900/90 backdrop-blur border-b border-slate-800 px-6 py-4 flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2 mr-2">
          <Shield size={18} className="text-indigo-400" />
          <span className="font-bold text-white">Defender</span>
          {isRunning && (
            <span className="flex items-center gap-1 text-xs text-green-400 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />LIVE
            </span>
          )}
        </div>

        <div className="bg-slate-800/80 border border-slate-700 text-slate-300 text-sm px-4 py-2 rounded-xl flex items-center gap-2">
          <Activity size={14} className="text-indigo-400" />
          <span className="font-medium">Simulation Mode</span>
        </div>

        <input
          type="number"
          value={jsPort}
          onChange={e => setJsPort(parseInt(e.target.value) || 4000)}
          disabled={isRunning}
          className="w-20 px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-sm text-center text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50"
          placeholder="4000"
        />

        <button
          onClick={() => setSimMode(v => !v)}
          disabled={isRunning}
          className={`flex items-center gap-1.5 px-3 py-2 rounded-xl text-sm font-medium border transition-all disabled:opacity-40 ${
            simMode ? 'bg-violet-600 text-white border-violet-600' : 'bg-slate-800 text-slate-400 border-slate-700 hover:border-violet-500 hover:text-violet-400'
          }`}
        >
          <FlaskConical size={13} />
          {simMode ? 'Sim ON' : 'Sim'}
        </button>

        {!isRunning ? (
          <button
            onClick={startCapture}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-semibold active:scale-95 transition-all"
          >
            <Play size={13} />Start Capture
          </button>
        ) : (
          <button onClick={stopCapture} className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-xl text-sm font-semibold active:scale-95 transition-all">
            <Square size={13} />Stop
          </button>
        )}

        <button
          onClick={runAI}
          disabled={analyzing}
          className="ml-auto flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 text-white rounded-xl text-sm font-bold shadow-lg shadow-violet-900/40 active:scale-95 transition-all disabled:opacity-60"
        >
          {analyzing
            ? <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Analyzing…</>
            : <><Brain size={15} />🤖 AI Analysis</>}
        </button>
      </div>

      <div className="p-6 space-y-6">

        {/* Error banner */}
        {aiError && (
          <div className="bg-red-950/60 border border-red-800/50 rounded-xl px-4 py-3 text-red-300 text-sm flex items-center gap-2">
            <AlertTriangle size={15} />{aiError}
          </div>
        )}

        {/* Setup guide */}
        {!isRunning && (
          <div className="bg-indigo-950/60 border border-indigo-800/40 rounded-2xl p-4">
            <div className="flex items-start gap-3">
              <Info size={16} className="text-indigo-400 flex-shrink-0 mt-0.5" />
              <div>
                <div className="text-sm font-bold text-indigo-300 mb-2">⚡ Quick Setup</div>
                <ol className="text-xs text-indigo-400/80 space-y-1 list-decimal list-inside">
                  <li>Set Port = <strong className="font-mono text-indigo-300">4000</strong> (Docker Juice Shop)</li>
                  <li>Click <strong className="text-indigo-300">Start Capture</strong></li>
                  <li>Go to <strong className="text-indigo-300">Attacker</strong> panel and launch attacks</li>
                  <li>Watch packets appear in Table 1, and predictions in Table 2</li>
                </ol>
              </div>
            </div>
          </div>
        )}

        {/* Stat cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard icon={Activity} label="Total Packets" value={(stats.packets ?? 0).toLocaleString()} sub="Scanned" color="blue" />
          <StatCard icon={BarChart2} label="Flows Analyzed" value={(stats.flows ?? 0).toLocaleString()} sub="Completed flows" color="purple" />
          <StatCard icon={AlertTriangle} label="Attacks Detected" value={(stats.attacks ?? 0).toLocaleString()} sub="By ML + rules" color="red" />
          <StatCard icon={TrendingUp} label="Attack Rate" value={`${stats.rate ?? 0}%`} sub="of all flows" color="green" />
        </div>

        {/* ── Two-column tables ── */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

          {/* TABLE 1 – Packet Scanner */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-slate-800/30">
              <div>
                <div className="flex items-center gap-2">
                  <Wifi size={15} className="text-blue-400" />
                  <span className="font-bold text-white text-sm">📡 Packet Scanner</span>
                  {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />}
                </div>
                <p className="text-xs text-slate-500 mt-0.5">Every captured packet — raw network data</p>
              </div>
              <span className="text-xs bg-blue-900/40 text-blue-300 px-2 py-1 rounded-lg border border-blue-800/40">
                {recentPackets.length} pkts
              </span>
            </div>

            {recentPackets.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-14 text-slate-600">
                <Activity size={32} className="mb-3 opacity-30" />
                <div className="text-sm">No packets captured yet</div>
                <div className="text-xs mt-1 opacity-70">Start capture to see live traffic</div>
              </div>
            ) : (
              <div className="overflow-x-auto overflow-y-auto max-h-[420px]">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 z-10">
                    <tr className="text-left text-slate-500 bg-slate-800/80 border-b border-slate-700">
                      <th className="px-3 py-2.5 font-semibold">#</th>
                      <th className="px-3 py-2.5 font-semibold">Time</th>
                      <th className="px-3 py-2.5 font-semibold">Source</th>
                      <th className="px-3 py-2.5 font-semibold">Destination</th>
                      <th className="px-3 py-2.5 font-semibold">Proto</th>
                      <th className="px-3 py-2.5 font-semibold text-right">Length</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {recentPackets.slice(0, 100).map((p, i) => (
                      <tr key={p.no ?? i} className="hover:bg-slate-800/30 transition-colors group">
                        <td className="px-3 py-2 font-mono text-slate-600">{p.no}</td>
                        <td className="px-3 py-2 font-mono text-slate-500 whitespace-nowrap">{p.time}</td>
                        <td className="px-3 py-2 font-mono text-slate-300 max-w-[110px]">
                          <div className="truncate">{p.src}</div>
                          {p.src_port > 0 && <div className="text-slate-600 text-[10px]">:{p.src_port}</div>}
                        </td>
                        <td className="px-3 py-2 font-mono text-slate-300 max-w-[110px]">
                          <div className="truncate">{p.dst}</div>
                          {p.dst_port > 0 && <div className="text-slate-600 text-[10px]">:{p.dst_port}</div>}
                        </td>
                        <td className="px-3 py-2"><ProtoChip proto={p.proto} /></td>
                        <td className="px-3 py-2 text-right font-mono text-slate-400">
                          {p.length > 1024 ? `${(p.length / 1024).toFixed(1)}K` : p.length}
                          <span className="text-slate-600 ml-0.5">B</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* TABLE 2 – Model Predictions */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 bg-slate-800/30">
              <div>
                <div className="flex items-center gap-2">
                  <Cpu size={15} className="text-violet-400" />
                  <span className="font-bold text-white text-sm">🤖 Model Predictions</span>
                  {isRunning && <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />}
                </div>
                <p className="text-xs text-slate-500 mt-0.5">XGBoost classification — Normal or Attack type</p>
              </div>
              <div className="flex items-center gap-2">
                <span className="flex items-center gap-1 text-[10px] text-slate-500">
                  <span className="w-2 h-2 rounded-full bg-green-500 inline-block" />Normal
                </span>
                <span className="flex items-center gap-1 text-[10px] text-slate-500">
                  <span className="w-2 h-2 rounded-full bg-red-500 inline-block" />Attack
                </span>
                <span className="text-xs bg-violet-900/40 text-violet-300 px-2 py-1 rounded-lg border border-violet-800/40">
                  {recentFlows.length} flows
                </span>
              </div>
            </div>

            {recentFlows.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-14 text-slate-600">
                <Brain size={32} className="mb-3 opacity-30" />
                <div className="text-sm">No predictions yet</div>
                <div className="text-xs mt-1 opacity-70">Start capture and launch attacks</div>
              </div>
            ) : (
              <div className="overflow-x-auto overflow-y-auto max-h-[420px]">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 z-10">
                    <tr className="text-left text-slate-500 bg-slate-800/80 border-b border-slate-700">
                      <th className="px-3 py-2.5 font-semibold">Time</th>
                      <th className="px-3 py-2.5 font-semibold">Source → Dest</th>
                      <th className="px-3 py-2.5 font-semibold">Verdict</th>
                      <th className="px-3 py-2.5 font-semibold text-right">Conf.</th>
                      <th className="px-3 py-2.5 font-semibold">Detector</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/50">
                    {recentFlows.slice(0, 100).map((f, i) => (
                      <tr key={i} className={`transition-colors ${f.is_attack ? 'bg-red-950/20 hover:bg-red-950/40' : 'hover:bg-slate-800/30'}`}>
                        <td className="px-3 py-2.5 font-mono text-slate-500 whitespace-nowrap">{f.time}</td>
                        <td className="px-3 py-2.5 max-w-[150px]">
                          <div className="font-mono text-slate-300 truncate text-[10px]">{f.src}</div>
                          <div className="font-mono text-slate-500 truncate text-[10px]">→ {f.dst}</div>
                        </td>
                        <td className="px-3 py-2.5">
                          <LabelBadge label={f.label} isAttack={f.is_attack} />
                        </td>
                        <td className={`px-3 py-2.5 text-right font-mono font-bold ${
                          f.confidence >= 80 ? 'text-red-400' : f.confidence >= 50 ? 'text-orange-400' : 'text-slate-500'
                        }`}>
                          {f.confidence}%
                        </td>
                        <td className="px-3 py-2.5">
                          {f.detector && f.detector !== 'None' && (
                            <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${
                              f.detector === 'ML' ? 'bg-indigo-900/60 text-indigo-400' : 'bg-orange-900/50 text-orange-400'
                            }`}>{f.detector}</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Live Attack Alerts */}
        {(wsData?.general?.alerts || []).length > 0 && (
          <div className="bg-slate-900 border border-red-900/30 rounded-2xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Zap size={15} className="text-red-400" />
                <span className="font-bold text-white text-sm">⚡ Live Attack Alerts</span>
              </div>
              <span className="text-xs text-slate-500">{wsData.general.alerts.length} recent</span>
            </div>
            <div className="divide-y divide-slate-800/60 max-h-52 overflow-y-auto">
              {wsData.general.alerts.slice(0, 20).map((a, i) => (
                <div key={i} className="flex items-center gap-3 px-5 py-2.5 text-xs hover:bg-slate-800/30 transition-colors">
                  <span className="text-slate-500 font-mono flex-shrink-0">{a.time}</span>
                  <span className="font-mono text-slate-400 flex-shrink-0">{a.src_ip}:{a.src_port}</span>
                  <span className="text-slate-600">→</span>
                  <span className="font-mono text-slate-400">{a.dst_ip}:{a.dst_port}</span>
                  <span className="flex-1" />
                  <span className="bg-red-500/20 text-red-300 px-2 py-0.5 rounded-full font-bold">{a.attack}</span>
                  <span className={`font-mono font-bold ${a.confidence >= 80 ? 'text-red-400' : 'text-orange-400'}`}>{a.confidence}%</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] ${a.detector === 'ML' ? 'bg-indigo-900/50 text-indigo-400' : 'bg-orange-900/50 text-orange-400'}`}>{a.detector}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {aiResult && <AIResultModal result={aiResult} onClose={() => setAiResult(null)} />}
    </div>
  )
}

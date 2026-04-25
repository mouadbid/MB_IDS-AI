import { useState } from 'react'
import {
  Shield, Play, Square, RefreshCw, ChevronDown, FlaskConical,
  Brain, Activity, AlertTriangle, TrendingUp, Zap, CheckCircle2,
  Info, BarChart2, Cpu
} from 'lucide-react'

// ── Small components ───────────────────────────────────────────────────────

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
  const map = { 6: { l: 'TCP', c: 'bg-blue-900/50 text-blue-300' }, 17: { l: 'UDP', c: 'bg-yellow-900/50 text-yellow-300' } }
  const { l, c } = map[proto] || { l: proto || '?', c: 'bg-slate-700 text-slate-300' }
  return <span className={`px-1.5 py-0.5 rounded text-xs font-mono font-semibold ${c}`}>{l}</span>
}

// ── AI Analysis Modal ──────────────────────────────────────────────────────

function AIResultModal({ result, onClose }) {
  if (!result) return null
  const s = result.summary
  const isAttack = s.attack_flows > 0
  const conf = s.avg_confidence

  const ATTACK_COLOR = {
    'Web Attack  Brute Force': 'text-orange-400',
    'Web Attack  Sql Injection': 'text-red-400',
    'Web Attack  XSS': 'text-yellow-400',
    'DoS Hulk': 'text-purple-400',
    'DoS GoldenEye': 'text-purple-400',
    BENIGN: 'text-green-400',
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-slate-900 border border-slate-700 rounded-3xl shadow-2xl w-full max-w-2xl mx-4 overflow-hidden"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
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
          {/* Verdict */}
          <div className={`rounded-2xl border p-5 text-center ${isAttack ? 'bg-red-950/40 border-red-800/50' : 'bg-green-950/30 border-green-800/30'}`}>
            <div className="text-xs font-semibold uppercase tracking-widest text-slate-400 mb-2">Model Verdict</div>
            <div className={`text-3xl font-black ${ATTACK_COLOR[s.dominant_attack] || 'text-white'}`}>
              {isAttack ? '⚠ ' : '✓ '}{s.dominant_attack}
            </div>
            <div className="text-slate-400 text-sm mt-2">
              Average confidence: <span className={`font-bold ${conf >= 70 ? 'text-red-400' : conf >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>{conf}%</span>
            </div>
          </div>

          {/* Stats row */}
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
              <div className="text-xs text-slate-400 mt-1">Benign Flows</div>
            </div>
          </div>

          {/* Attack breakdown */}
          {Object.keys(s.attack_breakdown).length > 0 && (
            <div className="bg-slate-800/40 rounded-2xl p-4">
              <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Attack Type Breakdown</div>
              {Object.entries(s.attack_breakdown).map(([type, count]) => (
                <div key={type} className="flex items-center gap-3 mb-2">
                  <div className="text-xs text-slate-300 flex-1 truncate">{type}</div>
                  <div className="flex-1 bg-slate-700 rounded-full h-1.5 overflow-hidden">
                    <div
                      className="h-full bg-red-500 rounded-full transition-all"
                      style={{ width: `${Math.min(100, (count / s.attack_flows) * 100)}%` }}
                    />
                  </div>
                  <span className="text-xs font-bold text-red-400 w-6 text-right">{count}</span>
                </div>
              ))}
            </div>
          )}

          {/* Per-flow details */}
          <div>
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Flow-level Predictions</div>
            <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
              {result.flows.map((f, i) => (
                <div key={i} className={`rounded-xl p-3 border text-xs ${f.is_attack ? 'bg-red-950/40 border-red-800/30' : 'bg-slate-800/40 border-slate-700/30'}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`font-bold ${ATTACK_COLOR[f.label] || 'text-white'}`}>
                      {f.is_attack ? '⚠' : '✓'} {f.label}
                    </span>
                    <span className={`font-mono font-bold ${f.confidence >= 70 ? 'text-red-400' : f.confidence >= 40 ? 'text-yellow-400' : 'text-slate-400'}`}>
                      {f.confidence}%
                    </span>
                  </div>
                  <div className="flex gap-4 text-slate-400">
                    <span>Pkts: <span className="text-white">{f.total_packets}</span></span>
                    <span>Bytes: <span className="text-white">{f.total_bytes}</span></span>
                    <span>Rate: <span className="text-white">{f.pkt_rate}/s</span></span>
                    <span>Dur: <span className="text-white">{f.flow_duration_ms}ms</span></span>
                  </div>
                  {/* Top features */}
                  <div className="mt-2 flex flex-wrap gap-1">
                    {f.top_features.map((tf, j) => (
                      <span key={j} className="bg-slate-700 text-slate-300 px-1.5 py-0.5 rounded text-[10px] font-mono">
                        {tf.name.replace(/ /g, '_').substring(0, 20)}: <span className={tf.score > 0 ? 'text-red-300' : 'text-blue-300'}>{tf.score}</span>
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main Defender view ─────────────────────────────────────────────────────

export default function Defender({ wsData, wsConnected, controls, recentFlows }) {
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
      <div className="sticky top-0 z-20 bg-slate-900/90 backdrop-blur border-b border-slate-800 px-6 py-4 flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2 mr-2">
          <Shield size={18} className="text-indigo-400" />
          <span className="font-bold text-white">Defender</span>
          {isRunning && (
            <span className="flex items-center gap-1 text-xs text-green-400 font-semibold">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse" />LIVE
            </span>
          )}
        </div>

        {/* Interface - Hardcoded to URL Mode */}
        <div className="bg-slate-800/80 border border-slate-700 text-slate-300 text-sm px-4 py-2 rounded-xl flex items-center gap-2">
          <Activity size={14} className="text-indigo-400" />
          <span className="font-medium">URL Capture Mode</span>
        </div>

        {/* Port */}
        <input
          type="number"
          value={jsPort}
          onChange={e => setJsPort(parseInt(e.target.value) || 4000)}
          disabled={isRunning}
          className="w-20 px-3 py-2 bg-slate-800 border border-slate-700 rounded-xl text-sm text-center text-white focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50"
          placeholder="4000"
        />

        {/* Sim mode */}
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

        {/* Start / Stop */}
        {!isRunning ? (
          <button
            onClick={startCapture}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl text-sm font-semibold active:scale-95 transition-all disabled:opacity-50"
          >
            <Play size={13} />Start Capture
          </button>
        ) : (
          <button onClick={stopCapture} className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-xl text-sm font-semibold active:scale-95 transition-all">
            <Square size={13} />Stop
          </button>
        )}

        {/* AI Analyze button */}
        <button
          onClick={runAI}
          disabled={analyzing}
          className="ml-auto flex items-center gap-2 px-5 py-2 bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-700 hover:to-indigo-700 text-white rounded-xl text-sm font-bold shadow-lg shadow-violet-900/40 active:scale-95 transition-all disabled:opacity-60"
        >
          {analyzing ? (
            <><span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />Analyzing…</>
          ) : (
            <><Brain size={15} />🤖 AI Analysis</>
          )}
        </button>
      </div>

      <div className="p-6 space-y-5">
        {/* Error */}
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
                  <li>Port = <strong className="font-mono text-indigo-300">4000</strong> (Docker Juice Shop)</li>
                  <li>Click <strong className="text-indigo-300">Start Capture</strong></li>
                  <li>Go to <strong className="text-indigo-300">Attacker</strong> panel and launch attacks to send synthetic flows to the model</li>
                  <li>Come back and click <strong className="text-indigo-300">🤖 AI Analysis</strong> to see what the model detected</li>
                </ol>
                <div className="mt-2 text-xs text-indigo-500">⚠ Run terminal as <strong>Administrator</strong> for Scapy loopback capture on Windows.</div>
              </div>
            </div>
          </div>
        )}

        {/* Stat cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard icon={Activity} label="Total Packets" value={(stats.packets ?? 0).toLocaleString()} sub="Captured" color="blue" />
          <StatCard icon={BarChart2} label="Flows Analyzed" value={(stats.flows ?? 0).toLocaleString()} sub="Completed flows" color="purple" />
          <StatCard icon={AlertTriangle} label="Attacks Detected" value={(stats.attacks ?? 0).toLocaleString()} sub="By ML model + rules" color="red" />
          <StatCard icon={TrendingUp} label="Attack Rate" value={`${stats.rate ?? 0}%`} sub="of all flows" color="green" />
        </div>

        {/* Live flow table */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden">
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2">
                <Cpu size={15} className="text-indigo-400" />
                <span className="font-bold text-white">🤖 ML Model — Live Traffic Classification</span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">Every network flow classified by XGBoost in real-time</p>
            </div>
            <div className="flex items-center gap-3 text-xs">
              <span className="flex items-center gap-1 text-slate-500"><span className="w-2 h-2 rounded-full bg-red-500 inline-block" />Attack</span>
              <span className="flex items-center gap-1 text-slate-500"><span className="w-2 h-2 rounded-full bg-green-500 inline-block" />Benign</span>
              <span className="bg-slate-800 text-slate-400 px-2 py-1 rounded-lg">{recentFlows.length} flows</span>
            </div>
          </div>

          {recentFlows.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-slate-600">
              <Shield size={36} className="mb-3 opacity-30" />
              <div className="text-sm">No flows captured yet</div>
              <div className="text-xs mt-1">Start capture and launch attacks from the Attacker panel</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-slate-500 bg-slate-800/50 border-b border-slate-800">
                    <th className="px-4 py-2.5 font-medium">Time</th>
                    <th className="px-4 py-2.5 font-medium">Source</th>
                    <th className="px-4 py-2.5 font-medium">Destination</th>
                    <th className="px-4 py-2.5 font-medium">Proto</th>
                    <th className="px-4 py-2.5 font-medium text-right">Pkts</th>
                    <th className="px-4 py-2.5 font-medium text-right">Bytes</th>
                    <th className="px-4 py-2.5 font-medium">🤖 Model Label</th>
                    <th className="px-4 py-2.5 font-medium text-right">Conf.</th>
                    <th className="px-4 py-2.5 font-medium">Detector</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {recentFlows.slice(0, 50).map((f, i) => (
                    <tr key={i} className={`transition-colors ${f.is_attack ? 'bg-red-950/30 hover:bg-red-950/50' : 'hover:bg-slate-800/30'}`}>
                      <td className="px-4 py-2 font-mono text-slate-500">{f.time}</td>
                      <td className="px-4 py-2 font-mono text-slate-400 max-w-[130px] truncate">{f.src}</td>
                      <td className="px-4 py-2 font-mono text-slate-400 max-w-[130px] truncate">{f.dst}</td>
                      <td className="px-4 py-2"><ProtoChip proto={f.proto} /></td>
                      <td className="px-4 py-2 text-right text-slate-400">{f.pkts}</td>
                      <td className="px-4 py-2 text-right text-slate-400">{f.bytes > 1024 ? `${(f.bytes / 1024).toFixed(1)}K` : f.bytes}</td>
                      <td className="px-4 py-2">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold ${
                          f.is_attack ? 'bg-red-500/20 text-red-300' : 'bg-green-500/15 text-green-400'
                        }`}>
                          {f.is_attack && <span className="w-1 h-1 rounded-full bg-red-400" />}
                          {f.label}
                        </span>
                      </td>
                      <td className={`px-4 py-2 text-right font-mono font-bold ${
                        f.confidence >= 80 ? 'text-red-400' : f.confidence >= 50 ? 'text-orange-400' : 'text-slate-500'
                      }`}>{f.confidence}%</td>
                      <td className="px-4 py-2">
                        {f.detector && f.detector !== 'None' && (
                          <span className={`text-xs px-1.5 py-0.5 rounded font-medium ${
                            f.detector === 'ML' ? 'bg-indigo-900/50 text-indigo-400' : 'bg-orange-900/50 text-orange-400'
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

        {/* Recent alerts */}
        {(wsData?.general?.alerts || []).length > 0 && (
          <div className="bg-slate-900 border border-red-900/30 rounded-2xl overflow-hidden">
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Zap size={15} className="text-red-400" />
                <span className="font-bold text-white">Live Alerts</span>
              </div>
              <span className="text-xs text-slate-500">{wsData.general.alerts.length} recent</span>
            </div>
            <div className="divide-y divide-slate-800/60 max-h-64 overflow-y-auto">
              {wsData.general.alerts.slice(0, 20).map((a, i) => (
                <div key={i} className="flex items-center gap-3 px-5 py-2.5 text-xs hover:bg-slate-800/30 transition-colors">
                  <span className="text-slate-500 font-mono flex-shrink-0">{a.time}</span>
                  <span className="font-mono text-slate-400 flex-shrink-0">{a.src_ip}:{a.src_port}</span>
                  <span className="text-slate-600">→</span>
                  <span className="font-mono text-slate-400">{a.dst_ip}:{a.dst_port}</span>
                  <span className="flex-1" />
                  <span className="bg-red-500/20 text-red-300 px-2 py-0.5 rounded-full font-semibold">{a.attack}</span>
                  <span className={`font-mono font-bold ${a.confidence >= 80 ? 'text-red-400' : 'text-orange-400'}`}>{a.confidence}%</span>
                  <span className={`px-1.5 py-0.5 rounded text-xs ${a.detector === 'ML' ? 'bg-indigo-900/50 text-indigo-400' : 'bg-orange-900/50 text-orange-400'}`}>{a.detector}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* AI Result Modal */}
      {aiResult && <AIResultModal result={aiResult} onClose={() => setAiResult(null)} />}
    </div>
  )
}

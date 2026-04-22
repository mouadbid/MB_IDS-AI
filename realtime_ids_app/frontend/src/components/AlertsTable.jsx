import { ShieldBan, Shield } from 'lucide-react'

const BADGE_COLORS = {
  'Web Attack  Sql Injection': 'bg-red-100 text-red-700',
  'Web Attack  XSS':           'bg-orange-100 text-orange-700',
  'Web Attack  Brute Force':   'bg-yellow-100 text-yellow-700',
  'DoS Hulk':                  'bg-purple-100 text-purple-700',
  'DoS slowloris':             'bg-purple-100 text-purple-700',
  'DoS Slowhttptest':          'bg-purple-100 text-purple-700',
  'DoS GoldenEye':             'bg-purple-100 text-purple-700',
  'DDoS':                      'bg-fuchsia-100 text-fuchsia-700',
  'PortScan':                  'bg-blue-100 text-blue-700',
  'FTP-Patator':               'bg-cyan-100 text-cyan-700',
  'SSH-Patator':               'bg-teal-100 text-teal-700',
  'Bot':                       'bg-gray-100 text-gray-700',
  'Infiltration':              'bg-rose-100 text-rose-700',
  'Heartbleed':                'bg-red-100 text-red-800',
  'BENIGN':                    'bg-green-100 text-green-700',
}

// Normalize label for lookup: collapse dash+spaces to double space, then single space
function normLabel(s) {
  return s.replace(/\s*[–—-]\s*/g, '  ').replace(/\s{2,}/g, ' ').trim().toLowerCase()
}
const NORM_BADGE = Object.fromEntries(
  Object.entries(BADGE_COLORS).map(([k, v]) => [normLabel(k), v])
)

function getBadgeColor(label) {
  return BADGE_COLORS[label] || NORM_BADGE[normLabel(label)] || 'bg-gray-100 text-gray-700'
}

function AttackBadge({ label }) {
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium whitespace-nowrap ${getBadgeColor(label)}`}>
      {label}
    </span>
  )
}

function ConfidenceBar({ value, isAttack }) {
  const color = !isAttack
    ? 'bg-green-400'
    : value > 80 ? 'bg-red-400' : value > 50 ? 'bg-orange-400' : 'bg-yellow-400'
  return (
    <div className="flex items-center gap-2 min-w-0">
      <div className="w-14 h-1.5 bg-gray-100 rounded-full overflow-hidden flex-shrink-0">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-xs text-gray-500 flex-shrink-0">{value}%</span>
    </div>
  )
}

function DetectorBadge({ detector, simMode }) {
  if (!detector || detector === 'None') return null
  return (
    <div className="flex items-center gap-1">
      <span className={`px-1.5 py-0.5 rounded text-xs font-mono font-medium ${
        detector === 'ML'
          ? 'bg-indigo-50 text-indigo-600'
          : 'bg-gray-100 text-gray-500'
      }`}>{detector}</span>
      {simMode && (
        <span className="px-1.5 py-0.5 rounded text-xs font-mono font-medium bg-violet-50 text-violet-600">Sim</span>
      )}
    </div>
  )
}

export default function AlertsTable({ alerts = [], onBlock, showBlock = true }) {
  if (!alerts.length) {
    return (
      <div className="text-center py-10 text-gray-400">
        <Shield size={28} className="mx-auto mb-2 opacity-25" />
        <p className="text-sm">No alerts yet</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto -mx-1">
      <table className="w-full text-sm min-w-[600px]">
        <thead>
          <tr className="border-b border-gray-100">
            {['Time', 'Source IP', 'Destination', 'Attack Type', 'Confidence', 'Detector', showBlock ? 'Action' : null]
              .filter(Boolean)
              .map(h => (
                <th key={h} className="text-left pb-3 px-2 text-xs text-gray-400 font-semibold uppercase tracking-wider">
                  {h}
                </th>
              ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-50">
          {alerts.slice(0, 50).map((a, i) => (
            <tr key={i} className="hover:bg-slate-50/60 transition-colors">
              <td className="py-2.5 px-2 font-mono text-xs text-gray-400 whitespace-nowrap">{a.time}</td>
              <td className="py-2.5 px-2 font-mono text-xs text-gray-700 whitespace-nowrap">{a.src_ip}</td>
              <td className="py-2.5 px-2 font-mono text-xs text-gray-500 whitespace-nowrap">
                {a.dst_ip}:{a.dst_port}
              </td>
              <td className="py-2.5 px-2"><AttackBadge label={a.attack} /></td>
              <td className="py-2.5 px-2"><ConfidenceBar value={a.confidence} isAttack={a.is_attack} /></td>
              <td className="py-2.5 px-2"><DetectorBadge detector={a.detector} simMode={a.sim_mode} /></td>
              {showBlock && (
                <td className="py-2.5 px-2">
                  {a.is_attack && (
                    <button
                      onClick={() => onBlock?.(a.src_ip)}
                      className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-red-50 text-red-600 hover:bg-red-100 text-xs font-medium transition-colors whitespace-nowrap"
                    >
                      <ShieldBan size={11} />
                      Block
                    </button>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

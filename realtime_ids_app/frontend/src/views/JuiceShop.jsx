import { useRef } from 'react'
import { Globe, AlertTriangle, TrendingUp, ShieldBan } from 'lucide-react'
import StatCard from '../components/StatCard'
import AlertsTable from '../components/AlertsTable'
import { TimelineChart, AttackDonut } from '../components/charts'

export default function JuiceShop({ data, onBlock }) {
  const alertsRef = useRef(null)
  const scrollToAlerts = () => alertsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  const stats = data?.stats || {}

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-gray-900">Juice Shop Monitor</h1>
        <p className="text-sm text-gray-400 mt-0.5">Port 3000 — OWASP Juice Shop traffic only</p>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          title="HTTP Requests"
          value={(stats.requests ?? 0).toLocaleString()}
          subtitle="total requests"
          icon={Globe}
          color="yellow"
        />
        <StatCard
          title="Attacks Detected"
          value={(stats.attacks ?? 0).toLocaleString()}
          subtitle="malicious flows"
          icon={AlertTriangle}
          color="pink"
          onDetails={scrollToAlerts}
        />
        <StatCard
          title="Attack Rate"
          value={`${stats.rate ?? 0}%`}
          subtitle="of analyzed flows"
          icon={TrendingUp}
          color="purple"
          onDetails={scrollToAlerts}
        />
        <StatCard
          title="Blocked IPs"
          value={(data?.blocked_ips?.length ?? 0).toLocaleString()}
          subtitle="active firewall rules"
          icon={ShieldBan}
          color="red"
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
            <h3 className="text-sm font-semibold text-gray-800">Attack Breakdown</h3>
            <span className="text-xs text-gray-400 bg-gray-50 px-2 py-1 rounded-lg">by type</span>
          </div>
          <AttackDonut attackTypes={data?.attack_types || {}} />
        </div>
      </div>

      {/* Alerts */}
      <div ref={alertsRef} className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-gray-800">Juice Shop Alerts</h3>
          <span className="text-xs text-gray-400">{(data?.alerts || []).length} recent</span>
        </div>
        <AlertsTable alerts={data?.alerts || []} onBlock={onBlock} />
      </div>
    </div>
  )
}

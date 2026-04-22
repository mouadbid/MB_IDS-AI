import { useState, useEffect } from 'react'
import { Ban, ShieldCheck, RefreshCw, Clock } from 'lucide-react'

export default function BlockedIPs({ blockedIPs = [], onUnblock }) {
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(false)

  const loadHistory = async () => {
    setLoading(true)
    try {
      const d = await fetch('/api/history/blocked').then(r => r.json())
      setHistory(d.history || [])
    } catch {}
    setLoading(false)
  }

  useEffect(() => { loadHistory() }, [])

  const handleUnblock = async (ip) => {
    await onUnblock(ip)
    setTimeout(loadHistory, 600)
  }

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Blocked IPs</h1>
          <p className="text-sm text-gray-400 mt-0.5">Windows Firewall rules managed by IDS</p>
        </div>
        <button
          onClick={loadHistory}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 bg-white border border-gray-200 rounded-xl text-sm text-gray-600 hover:bg-gray-50 active:scale-95 transition-all disabled:opacity-50"
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          Refresh
        </button>
      </div>

      {/* Active blocks */}
      <div className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-4">
          <Ban size={15} className="text-red-500" />
          <h3 className="text-sm font-semibold text-gray-800">Active Blocks</h3>
          <span className="ml-auto text-xs text-gray-400">{blockedIPs.length} active</span>
        </div>

        {blockedIPs.length === 0 ? (
          <div className="text-center py-10">
            <ShieldCheck size={28} className="mx-auto mb-2 text-green-300" />
            <p className="text-sm text-gray-400">No IPs currently blocked</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100">
                <th className="text-left pb-3 text-xs text-gray-400 font-semibold uppercase tracking-wider">IP Address</th>
                <th className="text-left pb-3 text-xs text-gray-400 font-semibold uppercase tracking-wider">Status</th>
                <th className="text-left pb-3 text-xs text-gray-400 font-semibold uppercase tracking-wider">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {blockedIPs.map((ip, i) => (
                <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                  <td className="py-3 font-mono text-sm text-gray-700">{ip}</td>
                  <td className="py-3">
                    <span className="px-2 py-1 bg-red-50 text-red-600 rounded-full text-xs font-medium">
                      Blocked
                    </span>
                  </td>
                  <td className="py-3">
                    <button
                      onClick={() => handleUnblock(ip)}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-green-50 text-green-600 hover:bg-green-100 text-xs font-medium transition-colors"
                    >
                      <ShieldCheck size={12} />
                      Unblock
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* History */}
      <div className="bg-white rounded-2xl border border-gray-100 p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-4">
          <Clock size={15} className="text-gray-400" />
          <h3 className="text-sm font-semibold text-gray-800">Block History</h3>
          <span className="ml-auto text-xs text-gray-400">{history.length} records</span>
        </div>

        {history.length === 0 ? (
          <p className="text-center text-sm text-gray-400 py-8">No block history yet</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100">
                <th className="text-left pb-3 text-xs text-gray-400 font-semibold uppercase tracking-wider">IP Address</th>
                <th className="text-left pb-3 text-xs text-gray-400 font-semibold uppercase tracking-wider">Last Blocked</th>
                <th className="text-left pb-3 text-xs text-gray-400 font-semibold uppercase tracking-wider">Times Blocked</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-50">
              {history.map((record, i) => (
                <tr key={i} className="hover:bg-slate-50/60 transition-colors">
                  <td className="py-3 font-mono text-sm text-gray-700">{record.ip}</td>
                  <td className="py-3 text-xs text-gray-500">
                    {record.blocked_at ? record.blocked_at.slice(0, 19).replace('T', ' ') : '—'}
                  </td>
                  <td className="py-3">
                    <span className="px-2 py-1 bg-orange-50 text-orange-600 rounded-full text-xs font-medium">
                      {record.block_count}x
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

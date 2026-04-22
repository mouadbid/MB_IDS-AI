import { LayoutDashboard, ShieldAlert, Ban, Settings, Activity, ChevronLeft, ChevronRight } from 'lucide-react'

const nav = [
  { id: 'dashboard', label: 'Dashboard',   icon: LayoutDashboard },
  { id: 'juiceshop', label: 'Juice Shop',  icon: ShieldAlert },
  { id: 'blocked',   label: 'Blocked IPs', icon: Ban },
]

export default function Sidebar({ view, setView, mode, isRunning, wsConnected, collapsed, onToggle }) {
  return (
    <aside
      className={`bg-[#1a2744] flex flex-col h-full flex-shrink-0 select-none transition-all duration-200 overflow-hidden ${
        collapsed ? 'w-14' : 'w-56'
      }`}
    >
      {/* Brand */}
      <div className={`flex items-center gap-3 border-b border-white/5 flex-shrink-0 ${collapsed ? 'px-3 py-5 justify-center' : 'px-5 py-6'}`}>
        <div className="w-8 h-8 bg-indigo-500 rounded-lg flex items-center justify-center flex-shrink-0">
          <Activity size={15} className="text-white" />
        </div>
        {!collapsed && (
          <div className="min-w-0">
            <div className="text-white font-semibold text-sm leading-tight truncate">IDS Monitor</div>
            <div className="text-slate-400 text-xs truncate">Security Dashboard</div>
          </div>
        )}
      </div>

      {/* Status pill */}
      <div className={`mx-3 mt-4 mb-1 rounded-xl bg-white/5 flex-shrink-0 ${collapsed ? 'px-2 py-2.5 flex flex-col items-center gap-1.5' : 'px-3 py-2 flex items-center gap-2'}`}>
        <span
          className={`w-2 h-2 rounded-full flex-shrink-0 ${isRunning ? 'bg-green-400 animate-pulse' : 'bg-slate-500'}`}
          title={isRunning ? 'Capturing' : 'Stopped'}
        />
        {!collapsed && (
          <span className="text-xs text-slate-300 flex-1">{isRunning ? 'Capturing' : 'Stopped'}</span>
        )}
        <span
          className={`w-2 h-2 rounded-full flex-shrink-0 ${wsConnected ? 'bg-blue-400' : 'bg-red-400'}`}
          title={wsConnected ? 'WebSocket connected' : 'WebSocket disconnected'}
        />
        {!collapsed && (
          <span className="text-xs text-slate-400">{wsConnected ? 'WS' : 'WS!'}</span>
        )}
      </div>

      {/* Nav */}
      <nav className="px-2 pt-4 flex-1">
        {!collapsed && (
          <p className="text-xs text-slate-500 uppercase tracking-widest px-3 mb-3 font-medium">Main Menu</p>
        )}
        {nav.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setView(id)}
            title={collapsed ? label : undefined}
            className={`w-full flex items-center gap-3 rounded-xl mb-1 text-sm font-medium transition-all duration-150 ${
              collapsed ? 'px-0 py-2.5 justify-center' : 'px-3 py-2.5'
            } ${
              view === id && mode === 'ids'
                ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-900/30'
                : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
            }`}
          >
            <Icon size={16} className="flex-shrink-0" />
            {!collapsed && label}
          </button>
        ))}
      </nav>

      {/* Bottom */}
      <div className={`pb-4 border-t border-white/5 pt-3 flex flex-col gap-1 ${collapsed ? 'px-2' : 'px-2'}`}>
        <button
          title={collapsed ? 'Settings' : undefined}
          className={`w-full flex items-center gap-3 rounded-xl text-sm text-slate-400 hover:bg-white/5 hover:text-slate-200 transition-all ${
            collapsed ? 'px-0 py-2.5 justify-center' : 'px-3 py-2.5'
          }`}
        >
          <Settings size={16} className="flex-shrink-0" />
          {!collapsed && 'Settings'}
        </button>

        {/* Collapse toggle */}
        <button
          onClick={onToggle}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={`w-full flex items-center gap-3 rounded-xl text-sm text-slate-500 hover:bg-white/5 hover:text-slate-300 transition-all ${
            collapsed ? 'px-0 py-2.5 justify-center' : 'px-3 py-2.5'
          }`}
        >
          {collapsed ? <ChevronRight size={16} /> : (
            <>
              <ChevronLeft size={16} />
              <span>Collapse</span>
            </>
          )}
        </button>
      </div>
    </aside>
  )
}

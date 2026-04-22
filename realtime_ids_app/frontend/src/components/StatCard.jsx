import { TrendingUp, TrendingDown, ArrowRight } from 'lucide-react'

const palette = {
  yellow: {
    bg:   'bg-amber-50 border-amber-100',
    icon: 'bg-amber-100 text-amber-600',
    label:'text-amber-700',
  },
  pink: {
    bg:   'bg-pink-50 border-pink-100',
    icon: 'bg-pink-100 text-pink-600',
    label:'text-pink-700',
  },
  purple: {
    bg:   'bg-violet-50 border-violet-100',
    icon: 'bg-violet-100 text-violet-600',
    label:'text-violet-700',
  },
  blue: {
    bg:   'bg-sky-50 border-sky-100',
    icon: 'bg-sky-100 text-sky-600',
    label:'text-sky-700',
  },
  red: {
    bg:   'bg-red-50 border-red-100',
    icon: 'bg-red-100 text-red-600',
    label:'text-red-700',
  },
}

export default function StatCard({ title, value, subtitle, icon: Icon, color = 'yellow', trend, onDetails }) {
  const c = palette[color] || palette.yellow
  const isUp = trend >= 0

  return (
    <div className={`rounded-2xl border p-5 ${c.bg} flex flex-col gap-4 min-w-0`}>
      <div className="flex items-start justify-between gap-2">
        <div className={`p-2 rounded-xl flex-shrink-0 ${c.icon}`}>
          <Icon size={18} />
        </div>
        {trend !== undefined && (
          <div className={`flex items-center gap-1 text-xs font-medium px-2 py-1 rounded-full flex-shrink-0 ${
            isUp ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-600'
          }`}>
            {isUp ? <TrendingUp size={10} /> : <TrendingDown size={10} />}
            {Math.abs(trend)}%
          </div>
        )}
      </div>

      <div className="min-w-0">
        <div className="text-3xl font-bold text-gray-900 tracking-tight truncate">
          {value ?? '—'}
        </div>
        <div className={`text-sm font-medium mt-0.5 ${c.label}`}>{title}</div>
        {subtitle && (
          <div className="text-xs text-gray-400 mt-1 truncate">{subtitle}</div>
        )}
      </div>

      {onDetails && (
        <button
          onClick={onDetails}
          className="self-start flex items-center gap-1 text-xs text-gray-500 hover:text-gray-700 font-medium transition-colors"
        >
          See Details <ArrowRight size={11} />
        </button>
      )}
    </div>
  )
}

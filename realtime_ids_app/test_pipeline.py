"""
test_pipeline.py — IDS pipeline diagnostic
Run from any terminal (no admin needed): python test_pipeline.py
"""
import json
import time
import sys

try:
    import requests
except ImportError:
    print("Need requests: pip install requests")
    sys.exit(1)

API   = "http://localhost:8000"
JUICE = "http://localhost:3000"

def ok(label, cond, note=""):
    tag = "\033[32mPASS\033[0m" if cond else "\033[31mFAIL\033[0m"
    print(f"  [{tag}] {label}" + (f"  ({note})" if note else ""))
    return cond

print("=" * 50)
print("IDS Pipeline Diagnostic")
print("=" * 50)

# ── 1. API reachable ─────────────────────────────────
print("\n[1] IDS Backend")
try:
    status = requests.get(f"{API}/api/status", timeout=3).json()
    ok("API reachable", True)
    running = ok("IDS running", status["running"],
                 f"interface={status.get('interface','?')}")
    if not running:
        print("    → Select Loopback interface, click Start")
        sys.exit(1)
except Exception as e:
    ok("API reachable", False, str(e))
    print("    → Is main.py running?")
    sys.exit(1)

# ── 2. Juice Shop ─────────────────────────────────────
print("\n[2] Juice Shop")
try:
    r = requests.get(f"{JUICE}/", timeout=5)
    ok("Juice Shop reachable", r.status_code == 200)
except Exception as e:
    ok("Juice Shop reachable", False, str(e))
    print("    → docker run -d -p 3000:3000 bkimminich/juice-shop")
    sys.exit(1)

# ── 3. Baseline ───────────────────────────────────────
print("\n[3] Alert baseline")
before = requests.get(f"{API}/api/alerts?limit=1", timeout=3).json()["alerts"]
before_count = len(before)
print(f"    Alerts in SQLite before: {before_count}")

# Also check live packet count via WS-less snapshot (REST fallback)
try:
    gen = requests.get(f"{API}/api/status", timeout=3).json()
    print(f"    Backend status: {gen}")
except Exception:
    pass

# ── 4. Brute force ────────────────────────────────────
print("\n[4] Sending brute force (60 rapid POST /rest/user/login)")
t0 = time.time()
sent = 0
for i in range(60):
    try:
        requests.post(f"{JUICE}/rest/user/login",
                      json={"email": f"victim{i}@evil.com", "password": f"x{i}"},
                      timeout=5)
        sent += 1
    except Exception:
        pass
    if (i + 1) % 15 == 0:
        print(f"    {i+1}/60 sent …")
elapsed = time.time() - t0
print(f"    Done: {sent}/60 in {elapsed:.1f}s")

# ── 5. Wait for flow aggregator ───────────────────────
print("\n[5] Waiting 8s for flow aggregator timeout …")
for i in range(8, 0, -1):
    print(f"    {i}s", end="\r", flush=True)
    time.sleep(1)
print("    Done    ")

# ── 6. New alerts? ────────────────────────────────────
print("\n[6] New alerts in SQLite")
after = requests.get(f"{API}/api/alerts?limit=50", timeout=3).json()["alerts"]
after_count = len(after)
new = after_count - before_count
ok("New alerts generated", new > 0, f"{new} new alerts")

if new > 0:
    print("\n    Detected:")
    for a in after[:new]:
        ts = a.get("timestamp", "?")
        label = a.get("label", "?")
        conf = a.get("confidence", 0.0)
        src = a.get("src_ip", "?")
        print(f"    • {ts}  {label}  conf={conf:.1f}%  src={src}")
else:
    print("\n    Possible causes:")
    print("    (a) Traffic not going through captured interface")
    print("        → Run test_interfaces.py as Admin to find correct interface")
    print("    (b) Flow timeout not reached — try waiting longer")
    print("    (c) All traffic classified as BENIGN (tuning issue)")

# ── 7. WebSocket ──────────────────────────────────────
print("\n[7] WebSocket check")
try:
    import websockets, asyncio

    async def _ws():
        async with websockets.connect("ws://localhost:8000/ws",
                                      open_timeout=3) as ws:
            return json.loads(await asyncio.wait_for(ws.recv(), timeout=3))

    data = asyncio.run(_ws())
    ok("WebSocket connected", True)
    g = data.get("general", {}).get("stats", {})
    print(f"    packets={g.get('packets', 0)}  "
          f"flows={g.get('flows', 0)}  "
          f"attacks={g.get('attacks', 0)}")
except ImportError:
    ok("websockets installed", False)
    print("    → pip install websockets  then restart main.py")
except Exception as e:
    ok("WebSocket connected", False, str(e))
    print("    → pip install websockets  then restart main.py")

print("\n" + "=" * 50)

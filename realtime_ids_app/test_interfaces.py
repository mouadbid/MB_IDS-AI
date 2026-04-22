"""
test_interfaces.py — find which Scapy interface captures localhost:3000 traffic
Must run as Administrator: python test_interfaces.py
"""
import threading
import time
import sys

try:
    from scapy.all import sniff, IFACES, IP, TCP
    import requests
except ImportError as e:
    print(f"Missing: {e}")
    sys.exit(1)

JUICE = "http://localhost:3000"
CAPTURE_SECONDS = 7

captured = {}   # iface_label → packet count
lock = threading.Lock()


def sniff_iface(dev, label):
    count = [0]

    def cb(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            if pkt[TCP].dport == 3000 or pkt[TCP].sport == 3000:
                with lock:
                    count[0] += 1

    try:
        sniff(iface=dev, prn=cb, store=False, timeout=CAPTURE_SECONDS)
    except Exception:
        pass

    if count[0] > 0:
        with lock:
            captured[label] = count[0]


print("=" * 60)
print("Interface Diagnostic — looking for localhost:3000 traffic")
print("=" * 60)

ifaces = list(IFACES.items())
print(f"\nStarting sniffers on {len(ifaces)} interfaces …")

threads = []
for dev, iface in ifaces:
    label = (getattr(iface, "description", "") or
             getattr(iface, "name", "") or dev)
    t = threading.Thread(target=sniff_iface, args=(dev, label), daemon=True)
    t.start()
    threads.append(t)

time.sleep(1.5)  # let sniffers initialize

print("Sending test requests to Juice Shop …")
try:
    requests.get(f"{JUICE}/", timeout=3)
    for i in range(20):
        requests.post(f"{JUICE}/rest/user/login",
                      json={"email": f"t{i}@t.com", "password": "x"},
                      timeout=3)
    print("  Sent 20 requests")
except Exception as e:
    print(f"  Error: {e}")
    print("  → Is Juice Shop running?")

print(f"Waiting {CAPTURE_SECONDS - 2}s …")
time.sleep(CAPTURE_SECONDS - 1)

for t in threads:
    t.join(timeout=0.2)

print("\n" + "=" * 60)
print("RESULTS — interfaces that saw port-3000 TCP traffic:")
print("=" * 60)

if not captured:
    print("\n  NONE — no interface captured port-3000 traffic!")
    print("  Possible issues:")
    print("  (a) Juice Shop not running on localhost:3000")
    print("  (b) Npcap not installed or not in WinPcap mode")
    print("  (c) Npcap loopback driver not installed")
else:
    sorted_ifaces = sorted(captured.items(), key=lambda x: -x[1])
    for label, count in sorted_ifaces:
        marker = " ← USE THIS" if count == sorted_ifaces[0][1] else ""
        print(f"  {count:4d} packets  |  {label}{marker}")

print()

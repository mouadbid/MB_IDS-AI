import asyncio
import json
import os
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from flow_engine import IDSEngine
from firewall import block_ip, unblock_ip, list_blocked
from database import init_db, insert_alert, get_alerts, record_block, record_unblock, get_block_history


def check_admin():
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return os.getuid() == 0

if not check_admin():
    print("WARNING: Not running as Administrator. Packet capture or firewall blocking may fail.")
    # sys.exit(1)

init_db()

engine: IDSEngine | None = None
active_interface: str | None = None
is_running = False

BASE_DIR = Path(__file__).parent
app = FastAPI(title="IDS Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class StartRequest(BaseModel):
    interface: str
    juiceshop_port: int = 3000
    simulation_mode: bool = False


class IPRequest(BaseModel):
    ip: str


@app.get("/api/interfaces")
async def get_interfaces():
    result = []
    errors = []

    # ── Primary: Scapy IFACES (requires Npcap / admin on Windows) ──
    try:
        from scapy.all import IFACES, get_if_list
        for dev, iface in IFACES.items():
            name = (
                getattr(iface, "description", "")
                or getattr(iface, "name", "")
                or dev
            )
            result.append({"value": dev, "label": name})
        if not result:
            for dev in get_if_list():
                result.append({"value": dev, "label": dev})
    except Exception as e:
        errors.append(f"scapy: {e}")

    # ── Fallback: psutil (always available, no admin required) ──────
    if not result:
        try:
            import psutil
            for name, addrs in psutil.net_if_addrs().items():
                # Build a friendly label
                label = name
                if name in ("lo", "lo0", "Loopback Pseudo-Interface 1") or name.startswith("lo"):
                    label = f"{name} (Loopback)"
                result.append({"value": name, "label": label})
        except Exception as e:
            errors.append(f"psutil: {e}")

    # ── Last resort: known Windows loopback names ───────────────────
    if not result:
        result = [
            {"value": "lo",  "label": "lo (Loopback)"},
            {"value": "eth0","label": "eth0"},
        ]

    return {"interfaces": result, "errors": errors if errors else None}


@app.get("/api/status")
async def status():
    return {
        "running": is_running,
        "interface": active_interface,
        "simulation_mode": engine.simulation_mode if engine else False,
    }


@app.post("/api/start")
async def start_capture(req: StartRequest):
    global engine, active_interface, is_running
    if is_running:
        return {"ok": False, "msg": "Already running"}
    try:
        engine = IDSEngine(
            artifacts_dir=str(BASE_DIR.parent) + "/",
            juiceshop_port=req.juiceshop_port,
            simulation_mode=req.simulation_mode,
        )
        engine.on_alert = insert_alert
        engine.start(req.interface)
        active_interface = req.interface
        is_running = True
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "msg": str(e)}


@app.post("/api/stop")
async def stop_capture():
    global engine, active_interface, is_running
    if engine:
        engine.stop()
    is_running = False
    active_interface = None
    return {"ok": True}


@app.get("/api/suggest")
async def suggest():
    """Re-run stored raw flow features through the model and return a rich analysis."""
    if not engine:
        return {"ok": False, "msg": "Engine not started. Start capture first."}

    import numpy as np
    raw = list(engine.raw_flow_features)
    if not raw:
        return {"ok": False, "msg": "No flows captured yet. Launch an attack first."}

    results = []
    for fd in raw:
        row = []
        for feat in engine.features:
            val = fd.get(feat, 0.0)
            try:
                val = float(val)
            except (ValueError, TypeError):
                val = 0.0
            if not np.isfinite(val):
                val = 0.0
            row.append(val)

        X = np.array(row, dtype=np.float32).reshape(1, -1)
        X_scaled = engine.scaler.transform(X)
        X_scaled = np.clip(X_scaled, -3.0, 3.0)

        confidence = float(engine.xgb_binary.predict_proba(X_scaled)[0][1])
        is_attack = confidence > 0.10
        label = "BENIGN"
        if is_attack:
            idx = engine.xgb_multi.predict(X_scaled)[0]
            label = engine.le.inverse_transform([idx])[0]

        # Top 5 contributing features (absolute scaled values)
        feat_vals = list(zip(engine.features, X_scaled[0].tolist()))
        top_feats = sorted(feat_vals, key=lambda x: abs(x[1]), reverse=True)[:5]

        results.append({
            "label": label,
            "confidence": round(confidence * 100, 1),
            "is_attack": is_attack,
            "stored_label": fd.get("_label", "?"),
            "top_features": [{"name": k, "score": round(v, 3)} for k, v in top_feats],
            # key raw values for display
            "flow_duration_ms": round(fd.get("Flow Duration", 0) / 1000, 2),
            "total_packets": int(fd.get("Total Fwd Packets", 0)) + int(fd.get("Total Backward Packets", 0)),
            "total_bytes": int(fd.get("Total Length of Fwd Packets", 0)) + int(fd.get("Total Length of Bwd Packets", 0)),
            "pkt_rate": round(fd.get("Flow Packets/s", 0), 1),
            "byte_rate": round(fd.get("Flow Bytes/s", 0), 1),
        })

    # Aggregate: pick most common attack label
    from collections import Counter
    attack_results = [r for r in results if r["is_attack"]]
    label_counts = Counter(r["label"] for r in attack_results)
    top_label = label_counts.most_common(1)[0][0] if label_counts else "BENIGN"
    avg_conf = round(sum(r["confidence"] for r in results) / len(results), 1) if results else 0

    return {
        "ok": True,
        "summary": {
            "total_flows": len(results),
            "attack_flows": len(attack_results),
            "benign_flows": len(results) - len(attack_results),
            "dominant_attack": top_label,
            "avg_confidence": avg_conf,
            "attack_breakdown": dict(label_counts),
        },
        "flows": results[:20],
    }

@app.post("/api/inject_flow")
async def inject_flow(req: Request):
    data = await req.json()
    if engine and is_running:
        engine.inject_synthetic_flow(data)
    return {"ok": True}

@app.post("/api/block")
async def block(req: IPRequest):
    ok = block_ip(req.ip)
    if ok:
        record_block(req.ip)
    return {"ok": ok, "ip": req.ip}


@app.post("/api/unblock")
async def unblock(req: IPRequest):
    ok = unblock_ip(req.ip)
    if ok:
        record_unblock(req.ip)
    return {"ok": ok, "ip": req.ip}


@app.get("/api/blocked")
async def blocked():
    return {"blocked": list_blocked()}


@app.get("/api/alerts")
async def alerts_history(limit: int = 200):
    return {"alerts": get_alerts(limit=limit)}


@app.get("/api/alerts/juiceshop")
async def alerts_juiceshop(limit: int = 200):
    return {"alerts": get_alerts(limit=limit, juiceshop_only=True)}


@app.get("/api/history/blocked")
async def blocked_history():
    return {"history": get_block_history()}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            if engine and is_running:
                data = engine.snapshot()
                data["blocked_ips"] = list_blocked()
                data["running"] = True
            else:
                data = {"running": False}
            await ws.send_text(json.dumps(data))
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


if __name__ == "__main__":
    print("IDS API running at http://localhost:8000")
    print("Start frontend: cd frontend && npm run dev  ->  http://localhost:5173")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

import asyncio
import json
import os
import sys
from pathlib import Path

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
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
    print("ERROR: Run as Administrator (required for packet capture + firewall).")
    sys.exit(1)

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
    try:
        from scapy.all import IFACES, get_if_list
        result = []
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
        return {"interfaces": result}
    except Exception as e:
        return {"interfaces": [], "error": str(e)}


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
    print("Start frontend: cd frontend && npm run dev  →  http://localhost:5173")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")

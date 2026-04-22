import sqlite3
import threading
from pathlib import Path
from datetime import datetime

DB_PATH = Path(__file__).parent.parent / "ids.db"
_lock = threading.Lock()


def _conn():
    c = sqlite3.connect(str(DB_PATH))
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with _lock:
        c = _conn()
        c.executescript("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                proto TEXT,
                label TEXT,
                confidence REAL,
                is_juiceshop INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                blocked_at TEXT NOT NULL,
                block_count INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
            CREATE INDEX IF NOT EXISTS idx_alerts_js ON alerts(is_juiceshop);
        """)
        c.commit()
        c.close()


def insert_alert(alert: dict):
    with _lock:
        c = _conn()
        c.execute(
            "INSERT INTO alerts "
            "(timestamp, src_ip, dst_ip, src_port, dst_port, proto, label, confidence, is_juiceshop) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                alert.get("time", datetime.now().strftime("%H:%M:%S")),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert.get("src_port"),
                alert.get("dst_port"),
                str(alert.get("proto", "")),
                alert.get("attack", "UNKNOWN"),
                float(alert.get("confidence", 0.0)),
                1 if alert.get("is_juiceshop") else 0,
            ),
        )
        c.commit()
        c.close()


def get_alerts(limit: int = 200, juiceshop_only: bool = False):
    with _lock:
        c = _conn()
        if juiceshop_only:
            rows = c.execute(
                "SELECT * FROM alerts WHERE is_juiceshop=1 ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        c.close()
        return [dict(r) for r in rows]


def record_block(ip: str):
    with _lock:
        c = _conn()
        c.execute(
            "INSERT INTO blocked_ips (ip, blocked_at, block_count) VALUES (?, ?, 1) "
            "ON CONFLICT(ip) DO UPDATE SET blocked_at=excluded.blocked_at, block_count=block_count+1",
            (ip, datetime.now().isoformat()),
        )
        c.commit()
        c.close()


def record_unblock(ip: str):
    with _lock:
        c = _conn()
        c.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
        c.commit()
        c.close()


def get_block_history(limit: int = 100):
    with _lock:
        c = _conn()
        rows = c.execute(
            "SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT ?", (limit,)
        ).fetchall()
        c.close()
        return [dict(r) for r in rows]

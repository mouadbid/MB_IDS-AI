import time
import threading
import pickle
import numpy as np
from collections import deque, defaultdict
from datetime import datetime

import xgboost as xgb

ARTIFACTS_DIR = "../"  # model files are in parent directory

FLOW_TIMEOUT = 5.0       # seconds of inactivity before flow expires
FLOW_MAX_PKTS = 1000     # force-complete after this many packets


class FlowRecord:
    """Tracks per-flow statistics for CICIDS feature extraction."""

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto, ts):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto

        self.start_ts = ts
        self.last_ts = ts
        self.fwd_pkts = []   # (timestamp, length) for src→dst
        self.bwd_pkts = []   # (timestamp, length) for dst→src
        self.fwd_flags = defaultdict(int)
        self.bwd_flags = defaultdict(int)
        self.fwd_header_len = 0
        self.bwd_header_len = 0
        self.init_win_fwd = 0
        self.init_win_bwd = 0
        self._init_win_fwd_set = False
        self._init_win_bwd_set = False

    def add_packet(self, ts, length, is_forward, flags=None, header_len=0, win=0):
        self.last_ts = ts
        entry = (ts, length)
        if is_forward:
            self.fwd_pkts.append(entry)
            self.fwd_header_len += header_len
            if not self._init_win_fwd_set:
                self.init_win_fwd = win
                self._init_win_fwd_set = True
            if flags:
                for f in flags:
                    self.fwd_flags[f] += 1
        else:
            self.bwd_pkts.append(entry)
            self.bwd_header_len += header_len
            if not self._init_win_bwd_set:
                self.init_win_bwd = win
                self._init_win_bwd_set = True
            if flags:
                for f in flags:
                    self.bwd_flags[f] += 1

    @property
    def total_pkts(self):
        return len(self.fwd_pkts) + len(self.bwd_pkts)

    def _safe_stats(self, values):
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        arr = np.array(values, dtype=float)
        return float(arr.max()), float(arr.min()), float(arr.mean()), float(arr.std())

    def _iat(self, pkts):
        if len(pkts) < 2:
            return []
        ts = [p[0] for p in pkts]
        return [ts[i+1] - ts[i] for i in range(len(ts)-1)]

    def to_feature_dict(self) -> dict:
        duration = max(self.last_ts - self.start_ts, 1e-6)
        fwd_lens = [p[1] for p in self.fwd_pkts]
        bwd_lens = [p[1] for p in self.bwd_pkts]
        all_lens = fwd_lens + bwd_lens
        all_ts   = sorted([p[0] for p in self.fwd_pkts + self.bwd_pkts])

        fwd_max, fwd_min, fwd_mean, fwd_std = self._safe_stats(fwd_lens)
        bwd_max, bwd_min, bwd_mean, bwd_std = self._safe_stats(bwd_lens)
        pkt_max, pkt_min, pkt_mean, pkt_std = self._safe_stats(all_lens)

        total_fwd_bytes = sum(fwd_lens)
        total_bwd_bytes = sum(bwd_lens)
        total_bytes = total_fwd_bytes + total_bwd_bytes

        flow_iat = self._iat([(t, 0) for t in all_ts])
        fwd_iat  = self._iat(self.fwd_pkts)
        bwd_iat  = self._iat(self.bwd_pkts)

        fi_max, fi_min, fi_mean, fi_std = self._safe_stats(flow_iat)
        fiat_max, fiat_min, fiat_mean, fiat_std = self._safe_stats(fwd_iat)
        biat_max, biat_min, biat_mean, biat_std = self._safe_stats(bwd_iat)

        n_fwd = len(self.fwd_pkts)
        n_bwd = len(self.bwd_pkts)

        return {
            'Flow Duration':              duration * 1e6,       # microseconds
            'Total Fwd Packets':          n_fwd,
            'Total Backward Packets':     n_bwd,
            'Total Length of Fwd Packets': total_fwd_bytes,
            'Total Length of Bwd Packets': total_bwd_bytes,
            'Fwd Packet Length Max':      fwd_max,
            'Fwd Packet Length Min':      fwd_min,
            'Fwd Packet Length Mean':     fwd_mean,
            'Fwd Packet Length Std':      fwd_std,
            'Bwd Packet Length Max':      bwd_max,
            'Bwd Packet Length Min':      bwd_min,
            'Bwd Packet Length Mean':     bwd_mean,
            'Bwd Packet Length Std':      bwd_std,
            'Flow Bytes/s':               total_bytes / duration,
            'Flow Packets/s':             (n_fwd + n_bwd) / duration,
            'Flow IAT Mean':              fi_mean * 1e6,
            'Flow IAT Std':               fi_std  * 1e6,
            'Flow IAT Max':               fi_max  * 1e6,
            'Flow IAT Min':               fi_min  * 1e6,
            'Fwd IAT Total':              sum(fwd_iat) * 1e6,
            'Fwd IAT Mean':               fiat_mean * 1e6,
            'Fwd IAT Std':                fiat_std  * 1e6,
            'Fwd IAT Max':                fiat_max  * 1e6,
            'Fwd IAT Min':                fiat_min  * 1e6,
            'Bwd IAT Total':              sum(bwd_iat) * 1e6,
            'Bwd IAT Mean':               biat_mean * 1e6,
            'Bwd IAT Std':                biat_std  * 1e6,
            'Bwd IAT Max':                biat_max  * 1e6,
            'Bwd IAT Min':                biat_min  * 1e6,
            'Fwd PSH Flags':              self.fwd_flags.get('P', 0),
            'Bwd PSH Flags':              self.bwd_flags.get('P', 0),
            'Fwd URG Flags':              self.fwd_flags.get('U', 0),
            'Bwd URG Flags':              self.bwd_flags.get('U', 0),
            'Fwd Header Length':          self.fwd_header_len,
            'Bwd Header Length':          self.bwd_header_len,
            'Fwd Packets/s':              n_fwd / duration,
            'Bwd Packets/s':              n_bwd / duration,
            'Min Packet Length':          pkt_min,
            'Max Packet Length':          pkt_max,
            'Packet Length Mean':         pkt_mean,
            'Packet Length Std':          pkt_std,
            'Packet Length Variance':     pkt_std ** 2,
            'FIN Flag Count':             self.fwd_flags.get('F', 0) + self.bwd_flags.get('F', 0),
            'SYN Flag Count':             self.fwd_flags.get('S', 0) + self.bwd_flags.get('S', 0),
            'RST Flag Count':             self.fwd_flags.get('R', 0) + self.bwd_flags.get('R', 0),
            'PSH Flag Count':             self.fwd_flags.get('P', 0) + self.bwd_flags.get('P', 0),
            'ACK Flag Count':             self.fwd_flags.get('A', 0) + self.bwd_flags.get('A', 0),
            'URG Flag Count':             self.fwd_flags.get('U', 0) + self.bwd_flags.get('U', 0),
            'CWE Flag Count':             self.fwd_flags.get('C', 0) + self.bwd_flags.get('C', 0),
            'ECE Flag Count':             self.fwd_flags.get('E', 0) + self.bwd_flags.get('E', 0),
            'Down/Up Ratio':              n_bwd / max(n_fwd, 1),
            'Average Packet Size':        pkt_mean,
            'Avg Fwd Segment Size':       fwd_mean,
            'Avg Bwd Segment Size':       bwd_mean,
            'Fwd Header Length.1':        self.fwd_header_len,
            'Fwd Avg Bytes/Bulk':         0.0,
            'Fwd Avg Packets/Bulk':       0.0,
            'Fwd Avg Bulk Rate':          0.0,
            'Bwd Avg Bytes/Bulk':         0.0,
            'Bwd Avg Packets/Bulk':       0.0,
            'Bwd Avg Bulk Rate':          0.0,
            'Subflow Fwd Packets':        n_fwd,
            'Subflow Fwd Bytes':          total_fwd_bytes,
            'Subflow Bwd Packets':        n_bwd,
            'Subflow Bwd Bytes':          total_bwd_bytes,
            'Init_Win_bytes_forward':     self.init_win_fwd,
            'Init_Win_bytes_backward':    self.init_win_bwd,
            'act_data_pkt_fwd':           n_fwd,
            'min_seg_size_forward':       fwd_min,
            'Active Mean':                0.0,
            'Active Std':                 0.0,
            'Active Max':                 0.0,
            'Active Min':                 0.0,
            'Idle Mean':                  0.0,
            'Idle Std':                   0.0,
            'Idle Max':                   0.0,
            'Idle Min':                   0.0,
            # metadata (not features)
            '_src_ip':   self.src_ip,
            '_dst_ip':   self.dst_ip,
            '_src_port': self.src_port,
            '_dst_port': self.dst_port,
            '_proto':    self.proto,
        }


class FlowAggregator:
    def __init__(self):
        self.flows: dict[tuple, FlowRecord] = {}
        self.lock = threading.Lock()

    def _get_flags(self, pkt):
        flags = []
        try:
            from scapy.layers.inet import TCP
            if pkt.haslayer(TCP):
                f = pkt[TCP].flags
                if f & 0x01: flags.append('F')
                if f & 0x02: flags.append('S')
                if f & 0x04: flags.append('R')
                if f & 0x08: flags.append('P')
                if f & 0x10: flags.append('A')
                if f & 0x20: flags.append('U')
                if f & 0x40: flags.append('E')
                if f & 0x80: flags.append('C')
        except Exception:
            pass
        return flags

    def process_packet(self, pkt) -> list[dict]:
        completed = []
        try:
            from scapy.layers.inet import IP, TCP, UDP
            if not pkt.haslayer(IP):
                return []

            ts = float(pkt.time)
            src_ip  = pkt[IP].src
            dst_ip  = pkt[IP].dst
            proto   = pkt[IP].proto
            length  = len(pkt)

            src_port = dst_port = 0
            header_len = 0
            win = 0
            flags = []

            if pkt.haslayer(TCP):
                src_port   = pkt[TCP].sport
                dst_port   = pkt[TCP].dport
                header_len = pkt[TCP].dataofs * 4
                win        = pkt[TCP].window
                flags      = self._get_flags(pkt)
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                header_len = 8

            # Canonical key: smaller IP first to group both directions
            if (src_ip, src_port) < (dst_ip, dst_port):
                key = (src_ip, dst_ip, src_port, dst_port, proto)
                is_forward = True
            else:
                key = (dst_ip, src_ip, dst_port, src_port, proto)
                is_forward = False

            with self.lock:
                # Expire old flows
                expired_keys = [
                    k for k, v in self.flows.items()
                    if (ts - v.last_ts) > FLOW_TIMEOUT or v.total_pkts >= FLOW_MAX_PKTS
                ]
                for k in expired_keys:
                    completed.append(self.flows.pop(k).to_feature_dict())

                if key not in self.flows:
                    self.flows[key] = FlowRecord(
                        src_ip if is_forward else dst_ip,
                        dst_ip if is_forward else src_ip,
                        src_port if is_forward else dst_port,
                        dst_port if is_forward else src_port,
                        proto, ts
                    )

                self.flows[key].add_packet(ts, length, is_forward, flags, header_len, win)

                # Close on FIN/RST
                if 'F' in flags or 'R' in flags:
                    completed.append(self.flows.pop(key).to_feature_dict())

        except Exception:
            pass
        return completed

    def flush_all(self) -> list[dict]:
        with self.lock:
            result = [f.to_feature_dict() for f in self.flows.values()]
            self.flows.clear()
        return result


class IDSEngine:
    def __init__(self, artifacts_dir=ARTIFACTS_DIR, juiceshop_port=3000, simulation_mode=False):
        self.juiceshop_port = juiceshop_port
        self.simulation_mode = simulation_mode
        self.lock = threading.Lock()

        # Load artifacts
        with open(f'{artifacts_dir}selected_features.pkl', 'rb') as f:
            self.features = pickle.load(f)
        with open(f'{artifacts_dir}scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)
        with open(f'{artifacts_dir}label_encoder.pkl', 'rb') as f:
            self.le = pickle.load(f)

        self.xgb_binary = xgb.XGBClassifier()
        self.xgb_binary.load_model(f'{artifacts_dir}xgb_binary.json')
        self.xgb_multi = xgb.XGBClassifier()
        self.xgb_multi.load_model(f'{artifacts_dir}xgb_multi.json')

        self.aggregator = FlowAggregator()

        # Stats
        self.stats = {
            'general': {'packets': 0, 'flows': 0, 'attacks': 0},
            'juiceshop': {'requests': 0, 'flows': 0, 'attacks': 0},
        }
        self.all_alerts = deque(maxlen=200)
        self.js_alerts  = deque(maxlen=200)
        self.timeline   = deque(maxlen=20)   # (label, count) per second
        self.js_timeline = deque(maxlen=20)

        self._attack_type_counts: dict[str, int] = defaultdict(int)
        self._js_attack_type_counts: dict[str, int] = defaultdict(int)

        self._tick_attacks = 0
        self._js_tick_attacks = 0
        self._last_tick = time.time()

        self.on_alert = None
        self._stop = threading.Event()
        self._capture_thread = None

        # Rule-based: per-(src_ip, dst_port) flow timestamps for rate detection
        self._history_lock = threading.Lock()
        self._ip_flow_history: dict = defaultdict(list)

    def _sim_transform(self, flow_dict: dict) -> dict:
        """Scale loopback features toward CICIDS LAN distribution for better ML sensitivity."""
        fd = dict(flow_dict)
        IAT_SCALE = 16.0
        for key in (
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
            'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
        ):
            if key in fd:
                fd[key] = fd[key] * IAT_SCALE
        fd['Flow Duration'] = fd.get('Flow Duration', 1_000_000) * IAT_SCALE
        # Loopback TCP window is always 65535; real LAN is typically 8192–32768
        fd['Init_Win_bytes_forward']  = min(fd.get('Init_Win_bytes_forward',  8192), 8192)
        fd['Init_Win_bytes_backward'] = min(fd.get('Init_Win_bytes_backward', 8192), 8192)
        return fd

    def _predict(self, flow_dict: dict):
        fd = self._sim_transform(flow_dict) if self.simulation_mode else flow_dict
        row = []
        for feat in self.features:
            val = fd.get(feat, 0.0)
            try:
                val = float(val)
            except (ValueError, TypeError):
                val = 0.0
            if not np.isfinite(val):
                val = 0.0
            row.append(val)

        X = np.array(row, dtype=np.float32).reshape(1, -1)
        X_scaled = self.scaler.transform(X)
        # Loopback IATs are µs vs CICIDS ms → clip to ±3σ to reduce outlier effect
        X_scaled = np.clip(X_scaled, -3.0, 3.0)

        confidence  = float(self.xgb_binary.predict_proba(X_scaled)[0][1])
        threshold   = 0.05 if self.simulation_mode else 0.15
        is_attack   = confidence > threshold
        attack_type = 'BENIGN'
        if is_attack:
            idx = self.xgb_multi.predict(X_scaled)[0]
            attack_type = self.le.inverse_transform([idx])[0]

        return is_attack, attack_type, confidence

    def _on_packet(self, pkt):
        with self.lock:
            self.stats['general']['packets'] += 1
            # Count Juice Shop traffic
            try:
                from scapy.layers.inet import TCP
                if pkt.haslayer(TCP):
                    sp = pkt[TCP].sport
                    dp = pkt[TCP].dport
                    if sp == self.juiceshop_port or dp == self.juiceshop_port:
                        self.stats['juiceshop']['requests'] += 1
            except Exception:
                pass

        completed = self.aggregator.process_packet(pkt)
        for flow in completed:
            self._process_flow(flow)

    def _process_flow(self, flow_dict: dict):
        is_js = (
            flow_dict.get('_dst_port') == self.juiceshop_port or
            flow_dict.get('_src_port') == self.juiceshop_port
        )

        is_attack, attack_type, confidence = self._predict(flow_dict)
        ml_detected = is_attack   # remember if ML triggered before rules

        # ── Rule-based override (loopback IATs confuse the ML model) ──────────
        if not is_attack:
            n_fwd   = flow_dict.get('Total Fwd Packets', 0)
            n_bwd   = flow_dict.get('Total Backward Packets', 0)
            n_total = n_fwd + n_bwd
            duration_s = max(flow_dict.get('Flow Duration', 1) / 1_000_000, 0.001)
            pkt_rate   = n_total / duration_s
            src_ip     = flow_dict.get('_src_ip', '')
            dst_port   = flow_dict.get('_dst_port', 0)

            now_ts = time.time()
            fk = (src_ip, dst_port)
            with self._history_lock:
                hist = self._ip_flow_history[fk]
                hist[:] = [t for t in hist if now_ts - t < 30]
                hist.append(now_ts)
                flow_count_30s = len(hist)

            # Brute force / DoS flood: very large keep-alive flow to Juice Shop
            if is_js and n_total > 80:
                is_attack   = True
                attack_type = 'Web Attack  Brute Force'
                confidence  = 0.85
            # Extreme packet rate → DoS
            elif pkt_rate > 200 and n_total > 20:
                is_attack   = True
                attack_type = 'DoS Hulk'
                confidence  = 0.88
            # Medium burst: XSS (20-80 packets, rapid)
            elif is_js and n_total > 25:
                is_attack   = True
                attack_type = 'Web Attack  XSS'
                confidence  = 0.78
            # Small rapid burst to Juice Shop: SQL injection (few requests, fast)
            elif is_js and n_total >= 6 and duration_s < 4:
                is_attack   = True
                attack_type = 'Web Attack  Sql Injection'
                confidence  = 0.72
            # Rate-based: multiple flows from same IP to Juice Shop → brute force
            elif flow_count_30s >= 5 and is_js:
                is_attack   = True
                attack_type = 'Web Attack  Brute Force'
                confidence  = 0.76
        # ──────────────────────────────────────────────────────────────────────

        detector = 'ML' if ml_detected else ('Rule' if is_attack else 'None')

        ts_str = datetime.now().strftime('%H:%M:%S')
        alert = {
            'time':         ts_str,
            'src_ip':       flow_dict.get('_src_ip', '?'),
            'dst_ip':       flow_dict.get('_dst_ip', '?'),
            'src_port':     flow_dict.get('_src_port', 0),
            'dst_port':     flow_dict.get('_dst_port', '?'),
            'proto':        flow_dict.get('_proto', ''),
            'attack':       attack_type,
            'confidence':   round(confidence * 100, 1),
            'is_attack':    is_attack,
            'is_juiceshop': is_js,
            'detector':     detector,
            'sim_mode':     self.simulation_mode,
        }

        with self.lock:
            self.stats['general']['flows'] += 1
            if is_attack:
                self.stats['general']['attacks'] += 1
                self._tick_attacks += 1
                self._attack_type_counts[attack_type] += 1
                self.all_alerts.appendleft(alert)  # only store attacks, not BENIGN

            if is_attack and self.on_alert:
                threading.Thread(target=self.on_alert, args=(alert,), daemon=True).start()

            if is_js:
                self.stats['juiceshop']['flows'] += 1
                if is_attack:
                    self.stats['juiceshop']['attacks'] += 1
                    self._js_tick_attacks += 1
                    self._js_attack_type_counts[attack_type] += 1
                    self.js_alerts.appendleft(alert)  # only attacks

        # Tick timeline every second
        now = time.time()
        if now - self._last_tick >= 1.0:
            label = datetime.now().strftime('%H:%M:%S')
            with self.lock:
                self.timeline.append({'label': label, 'count': self._tick_attacks})
                self.js_timeline.append({'label': label, 'count': self._js_tick_attacks})
                self._tick_attacks = 0
                self._js_tick_attacks = 0
                self._last_tick = now

    def start(self, interface: str):
        self._stop.clear()
        def _sniff():
            from scapy.all import sniff
            sniff(
                iface=interface,
                prn=self._on_packet,
                store=False,
                stop_filter=lambda _: self._stop.is_set()
            )
        self._capture_thread = threading.Thread(target=_sniff, daemon=True)
        self._capture_thread.start()

    def stop(self):
        self._stop.set()
        for flow in self.aggregator.flush_all():
            self._process_flow(flow)

    def snapshot(self) -> dict:
        with self.lock:
            g = self.stats['general']
            j = self.stats['juiceshop']
            g_rate = round(g['attacks'] / max(g['flows'], 1) * 100, 1)
            j_rate = round(j['attacks'] / max(j['flows'], 1) * 100, 1)
            return {
                'general': {
                    'stats': {**g, 'rate': g_rate},
                    'alerts': list(self.all_alerts)[:50],
                    'timeline': list(self.timeline),
                    'attack_types': dict(self._attack_type_counts),
                },
                'juiceshop': {
                    'stats': {**j, 'rate': j_rate},
                    'alerts': list(self.js_alerts)[:50],
                    'timeline': list(self.js_timeline),
                    'attack_types': dict(self._js_attack_type_counts),
                },
            }

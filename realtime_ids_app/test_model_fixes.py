"""
test_model_fixes.py — tests three proposed fixes for BENIGN misclassification
Run with: conda run -n MachineLearning python test_model_fixes.py
"""
import pickle, numpy as np, json
import xgboost as xgb

BASE = r'C:\Users\Ayoub\Documents\ESTC\Ridouani'

with open(BASE + '/scaler.pkl', 'rb') as f:      scaler  = pickle.load(f)
with open(BASE + '/selected_features.pkl', 'rb') as f: features = pickle.load(f)
with open(BASE + '/label_encoder.pkl', 'rb') as f: le = pickle.load(f)

xgb_bin = xgb.XGBClassifier(); xgb_bin.load_model(BASE + '/xgb_binary.json')
xgb_mul = xgb.XGBClassifier(); xgb_mul.load_model(BASE + '/xgb_multi.json')

def predict(flow_dict, label=''):
    row = []
    for feat in features:
        val = flow_dict.get(feat, 0.0)
        try:    val = float(val)
        except: val = 0.0
        if not np.isfinite(val): val = 0.0
        row.append(val)
    X = np.array(row, dtype=np.float32).reshape(1, -1)
    X_sc = scaler.transform(X)
    conf_raw = float(xgb_bin.predict_proba(X_sc)[0][1])
    X_clip = np.clip(X_sc, -3, 3)
    conf_clip = float(xgb_bin.predict_proba(X_clip)[0][1])
    label_raw  = 'BENIGN' if conf_raw  < 0.15 else le.inverse_transform([xgb_mul.predict(X_sc)[0]])[0]
    label_clip = 'BENIGN' if conf_clip < 0.15 else le.inverse_transform([xgb_mul.predict(X_clip)[0]])[0]
    return conf_raw, label_raw, conf_clip, label_clip, X_sc[0], row

# ── IAT feature names (subset of the 30) ──────────────────────────────────────
IAT_FEATURES = {f for f in features if 'IAT' in f}

def sep(title):
    print(f'\n{"="*60}')
    print(f'  {title}')
    print('='*60)

# ──────────────────────────────────────────────────────────────────────────────
# BASELINE: realistic loopback brute-force flow (60 requests, keep-alive)
# Duration ~5s, 120 packets, per-packet IAT mixes µs (within-exchange) and
# 200ms (between bursts of 5). Mean IAT ~80,000µs.
# ──────────────────────────────────────────────────────────────────────────────
BRUTE_LOOPBACK = {
    'Flow Duration':              5_000_000,   # 5s in µs
    'Total Fwd Packets':          65,
    'Total Backward Packets':     55,
    'Total Length of Fwd Packets': 38000,
    'Total Length of Bwd Packets': 42000,
    'Fwd Packet Length Max':      800,
    'Fwd Packet Length Min':      40,
    'Fwd Packet Length Mean':     584,
    'Fwd Packet Length Std':      190,
    'Bwd Packet Length Max':      1400,
    'Bwd Packet Length Min':      40,
    'Bwd Packet Length Mean':     763,
    'Bwd Packet Length Std':      280,
    'Flow Bytes/s':               16000,
    'Flow Packets/s':             24,
    'Flow IAT Mean':              80_000,      # 80ms mean IAT (loopback)
    'Flow IAT Std':               120_000,
    'Flow IAT Max':               210_000,
    'Flow IAT Min':               80,          # within-exchange: 80µs
    'Fwd IAT Total':              4_200_000,
    'Fwd IAT Mean':               67_000,
    'Fwd IAT Std':                110_000,
    'Fwd IAT Max':                210_000,
    'Fwd IAT Min':                80,
    'Bwd IAT Total':              3_900_000,
    'Bwd IAT Mean':               73_000,
    'Bwd IAT Std':                115_000,
    'Bwd IAT Max':                210_000,
    'Bwd IAT Min':                90,
    'Fwd PSH Flags':              60,
    'Bwd PSH Flags':              55,
    'Fwd URG Flags':              0,
    'Bwd URG Flags':              0,
    'Fwd Header Length':          1300,
    'Bwd Header Length':          1100,
    'Fwd Packets/s':              13,
    'Bwd Packets/s':              11,
    'Min Packet Length':          40,
    'Max Packet Length':          1400,
    'Packet Length Mean':         670,
    'Packet Length Std':          270,
    'Packet Length Variance':     72900,
    'FIN Flag Count':             2,
    'SYN Flag Count':             1,
    'RST Flag Count':             0,
    'PSH Flag Count':             115,
    'ACK Flag Count':             120,
    'URG Flag Count':             0,
    'CWE Flag Count':             0,
    'ECE Flag Count':             0,
    'Down/Up Ratio':              0.85,
    'Average Packet Size':        670,
    'Avg Fwd Segment Size':       584,
    'Avg Bwd Segment Size':       763,
    'Fwd Header Length.1':        1300,
    'Fwd Avg Bytes/Bulk':         0,
    'Fwd Avg Packets/Bulk':       0,
    'Fwd Avg Bulk Rate':          0,
    'Bwd Avg Bytes/Bulk':         0,
    'Bwd Avg Packets/Bulk':       0,
    'Bwd Avg Bulk Rate':          0,
    'Subflow Fwd Packets':        65,
    'Subflow Fwd Bytes':          38000,
    'Subflow Bwd Packets':        55,
    'Subflow Bwd Bytes':          42000,
    'Init_Win_bytes_forward':     65535,
    'Init_Win_bytes_backward':    65535,
    'act_data_pkt_fwd':           60,
    'min_seg_size_forward':       40,
    'Active Mean':                0,
    'Active Std':                 0,
    'Active Max':                 0,
    'Active Min':                 0,
    'Idle Mean':                  0,
    'Idle Std':                   0,
    'Idle Max':                   0,
    'Idle Min':                   0,
    'Destination Port':           3000,
}

sep('BASELINE — Loopback brute force flow (no fixes)')
raw, lbl_r, clip, lbl_c, zscores, vals = predict(BRUTE_LOOPBACK)
print(f'  Confidence (no clip):   {raw*100:.2f}%  → {lbl_r}')
print(f'  Confidence (±3σ clip):  {clip*100:.2f}%  → {lbl_c}')
print()
print(f'  {"Feature":<40} {"Raw value":>12} {"z-score":>10}')
print(f'  {"-"*65}')
for i, feat in enumerate(features):
    print(f'  {feat:<40} {vals[i]:>12.0f} {zscores[i]:>10.2f}')


# ──────────────────────────────────────────────────────────────────────────────
# FIX 1 — "Magical IPs" (loopback → different src IPs per request)
#
# IPs are NOT model features (none of the 30 features include IP address).
# BUT: different src IPs = different 5-tuple = separate flows per request.
# Effect: 60 separate flows of 2 packets each instead of 1 flow of 120 packets.
# This is what CICIDS brute force ACTUALLY looks like.
# ──────────────────────────────────────────────────────────────────────────────
sep('FIX 1 — Different source IPs (simulates per-request flows)')
print('  Note: IPs are NOT model features. The real benefit is forcing')
print('  separate TCP connections → each request becomes its own flow.')
print()

# Simulate what a single-request flow looks like (2-4 pkts, fast)
SINGLE_REQUEST_FLOW = {**BRUTE_LOOPBACK,
    'Flow Duration':             50_000,    # 50ms — one request/response
    'Total Fwd Packets':         2,
    'Total Backward Packets':    2,
    'Total Length of Fwd Packets': 600,
    'Total Length of Bwd Packets': 800,
    'Flow Bytes/s':              28000,
    'Flow Packets/s':            80,
    'Flow IAT Mean':             25_000,
    'Flow IAT Std':              10_000,
    'Flow IAT Max':              30_000,
    'Flow IAT Min':              20_000,
    'Fwd IAT Total':             25_000,
    'Fwd IAT Mean':              25_000,
    'Fwd IAT Std':               0,
    'Fwd IAT Max':               25_000,
    'Fwd IAT Min':               25_000,
    'Bwd IAT Total':             25_000,
    'Bwd IAT Mean':              25_000,
    'Bwd IAT Std':               0,
    'Bwd IAT Max':               25_000,
    'Bwd IAT Min':               25_000,
    'Fwd Packets/s':             40,
    'Bwd Packets/s':             40,
    'Subflow Fwd Packets':       2,
    'Subflow Fwd Bytes':         600,
    'Subflow Bwd Packets':       2,
    'Subflow Bwd Bytes':         800,
    'act_data_pkt_fwd':          2,
    'PSH Flag Count':            2,
    'ACK Flag Count':            4,
    'FIN Flag Count':            0,
    'SYN Flag Count':            1,
}
raw1, l1r, clip1, l1c, _, _ = predict(SINGLE_REQUEST_FLOW)
print(f'  Single-request flow (2 pkts, 50ms duration):')
print(f'    Confidence (no clip): {raw1*100:.2f}%  → {l1r}')
print(f'    Confidence (±3σ clip): {clip1*100:.2f}%  → {l1c}')
print()
print(f'  VERDICT: {"WORKS" if clip1 > 0.15 else "Still BENIGN"} — per-request flows {"change" if abs(clip1-clip)>0.05 else "barely change"} detection')


# ──────────────────────────────────────────────────────────────────────────────
# FIX 2 — IAT rescaling (multiply loopback IATs to match CICIDS range)
#
# CICIDS Flow IAT Mean = 1,299,765µs. Loopback mean = ~80,000µs.
# Scale factor: 1,299,765 / 80,000 ≈ 16x
# We apply this BEFORE the StandardScaler.
# ──────────────────────────────────────────────────────────────────────────────
sep('FIX 2 — IAT rescaling (multiply IATs to match CICIDS distribution)')

cicids_iat_mean = scaler.mean_[list(features).index('Flow IAT Mean')]
loopback_iat_mean = BRUTE_LOOPBACK['Flow IAT Mean']
scale_factor = cicids_iat_mean / loopback_iat_mean
print(f'  CICIDS Flow IAT Mean:   {cicids_iat_mean:,.0f} µs ({cicids_iat_mean/1e6:.2f}s)')
print(f'  Loopback Flow IAT Mean: {loopback_iat_mean:,.0f} µs ({loopback_iat_mean/1e6:.3f}s)')
print(f'  Computed scale factor:  {scale_factor:.1f}x')
print()

for factor in [1, 4, 8, 16, 32]:
    scaled = {**BRUTE_LOOPBACK}
    for feat in IAT_FEATURES:
        if feat in scaled:
            scaled[feat] = scaled[feat] * factor
    raw_f, lr_f, clip_f, lc_f, _, _ = predict(scaled)
    print(f'  IAT × {factor:2d}:  raw={raw_f*100:.2f}%  clip={clip_f*100:.2f}%  → {lc_f}')

print()
print(f'  VERDICT: check if higher factors push confidence above 0.15')


# ──────────────────────────────────────────────────────────────────────────────
# FIX 3a — Short FLOW_TIMEOUT (forces flow completion every ~0.3s)
# Currently: 5s timeout → 60 requests merge into 1 giant flow
# With 0.3s: each burst of requests gets its own flow
# Simulates: brute force as seen in CICIDS (many small flows)
# ──────────────────────────────────────────────────────────────────────────────
sep('FIX 3a — Short FLOW_TIMEOUT (split keep-alive into smaller flows)')
print('  AttackPanel sends bursts of 5 requests then sleeps 200ms.')
print('  With FLOW_TIMEOUT=0.3s, each burst = one flow (10 packets).')
print()

BURST_FLOW = {**BRUTE_LOOPBACK,
    'Flow Duration':             180_000,   # 180ms — one burst of 5 requests
    'Total Fwd Packets':         10,
    'Total Backward Packets':    10,
    'Total Length of Fwd Packets': 6000,
    'Total Length of Bwd Packets': 7000,
    'Flow Bytes/s':              72000,
    'Flow Packets/s':            111,
    'Flow IAT Mean':             18_000,
    'Flow IAT Std':              8_000,
    'Flow IAT Max':              30_000,
    'Flow IAT Min':              500,
    'Fwd IAT Total':             162_000,
    'Fwd IAT Mean':              18_000,
    'Fwd IAT Std':               8_000,
    'Fwd IAT Max':               30_000,
    'Fwd IAT Min':               500,
    'Bwd IAT Total':             162_000,
    'Bwd IAT Mean':              18_000,
    'Bwd IAT Std':               8_000,
    'Bwd IAT Max':               30_000,
    'Bwd IAT Min':               500,
    'Fwd Packets/s':             55,
    'Bwd Packets/s':             55,
    'Subflow Fwd Packets':       10,
    'Subflow Fwd Bytes':         6000,
    'Subflow Bwd Packets':       10,
    'Subflow Bwd Bytes':         7000,
    'act_data_pkt_fwd':          10,
    'PSH Flag Count':            10,
    'ACK Flag Count':            20,
}
raw3, lr3, clip3, lc3, _, _ = predict(BURST_FLOW)
print(f'  Burst flow (5 reqs, 180ms, 20 pkts):')
print(f'    Confidence (no clip): {raw3*100:.2f}%  → {lr3}')
print(f'    Confidence (±3σ clip): {clip3*100:.2f}%  → {lc3}')
print()
print(f'  VERDICT: {"WORKS" if clip3 > 0.15 else "Still BENIGN"} — short timeout {"helps" if clip3 > clip else "does not help"}')


# ──────────────────────────────────────────────────────────────────────────────
# FIX 3b — Combined: short timeout + IAT rescaling
# ──────────────────────────────────────────────────────────────────────────────
sep('FIX COMBINED — Short timeout + IAT rescaling (×16)')
COMBINED = {**BURST_FLOW}
for feat in IAT_FEATURES:
    if feat in COMBINED:
        COMBINED[feat] = COMBINED[feat] * 16
raw_c, lr_c, clip_c, lc_c, zs_c, _ = predict(COMBINED)
print(f'  Confidence (no clip): {raw_c*100:.2f}%  → {lr_c}')
print(f'  Confidence (±3σ clip): {clip_c*100:.2f}%  → {lc_c}')
print()
print(f'  Key z-scores after combined fix:')
for i, feat in enumerate(features):
    if 'IAT' in feat or 'Packet' in feat or 'Flow' in feat:
        print(f'    {feat:<40} z={zs_c[i]:>7.2f}')


# ──────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ──────────────────────────────────────────────────────────────────────────────
sep('SUMMARY')
print(f'  Baseline (loopback, 120pkt, 5s flow, no fix):   {clip*100:.2f}%')
print(f'  Fix 1 (per-request flows, 2pkt each):           {clip1*100:.2f}%')
print(f'  Fix 2 (IAT × 16, same flow):                    ', end='')
scaled_x16 = {**BRUTE_LOOPBACK}
for feat in IAT_FEATURES:
    if feat in scaled_x16: scaled_x16[feat] *= 16
_, _, clip_x16, lbl_x16, _, _ = predict(scaled_x16)
print(f'{clip_x16*100:.2f}%  → {lbl_x16}')
print(f'  Fix 3a (burst flow 0.3s timeout):               {clip3*100:.2f}%')
print(f'  Fix combined (burst + IAT×16):                  {clip_c*100:.2f}%  → {lc_c}')
print()
print('  Detection threshold: 0.15 (15%). Above = flagged as attack.')

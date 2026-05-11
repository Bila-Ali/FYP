"""
PDF Shield — Professional Cybersecurity Dashboard
===================================================
FYP: An Integrated AI System for Detection, Remediation,
     and Forensic Analysis of PDF-Based Malware

Team: Bilawal Ali (22BSCYS002) & Sagar (22BSCYS049)
Dept: BS Cyber Security, MUET
Supervisor: Engr. Mehran Mamonai

Entry point: streamlit run app.py
"""

import os
import sys
import json
import time
import shutil
import hashlib
import tempfile
import re
import numpy as np
from datetime import datetime
from pathlib import Path
from collections import Counter

import streamlit as st
import plotly.graph_objects as go

# ── Make sure the project root is on the path so imports work ──────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Import YOUR original files directly ────────────────────────────────────
from feature_extractor import (
    extract_features, FEATURE_COLUMNS, extract_header as _extract_hdr
)
from remediate import (
    remediate, prescan, file_hash, build_report,
    THREAT_ACTIONS
)
from dataset_loader import load_and_preprocess, train_test_split as dl_split

# forensic_report is imported lazily (needs reportlab — optional)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

APP_DIR     = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR   = os.path.join(APP_DIR, "models")
METRICS_FILE= os.path.join(MODEL_DIR, "metrics.json")
CSV_PATH    = os.path.join(APP_DIR, "meragedatacsv.csv")

# Feature order that matches training (from compare_models.py / predict.py)
FEATURE_ORDER = [
    "pdfsize", "metadata size", "pages", "xref Length", "title characters",
    "isEncrypted", "embedded files", "images",
    "obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref",
    "pageno", "encrypt", "ObjStm", "JS", "Javascript", "AA", "OpenAction",
    "Acroform", "JBIG2Decode", "RichMedia", "launch", "EmbeddedFile",
    "XFA", "Colors", "text_encoded", "pdf_version",
]

# Threat indicator metadata (mirrors forensic_report.py's THREAT_KEYWORDS)
THREAT_META = {
    "JS":           ("Inline JavaScript",           "HIGH",     "Code Execution"),
    "Javascript":   ("JavaScript Action",           "HIGH",     "Code Execution"),
    "OpenAction":   ("Auto-Execute on Open",        "HIGH",     "Code Execution"),
    "AA":           ("Additional Actions",          "HIGH",     "Code Execution"),
    "launch":       ("Launch External Program",     "HIGH",     "Command Execution"),
    "JBIG2Decode":  ("JBIG2 Heap Overflow",         "HIGH",     "Memory Exploit"),
    "RichMedia":    ("Rich Media Exploit",          "MEDIUM",   "Media Exploit"),
    "XFA":          ("XML Forms Architecture",      "MEDIUM",   "Form Exploit"),
    "ObjStm":       ("Object Stream Obfuscation",   "MEDIUM",   "Obfuscation"),
    "EmbeddedFile": ("Embedded File Payload",       "MEDIUM",   "Payload Delivery"),
    "encrypt":      ("Encryption / Hidden Content", "LOW",      "Obfuscation"),
    "Acroform":     ("AcroForm (JS-enabled Form)",  "LOW",      "Code Execution"),
}

# ─────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="PDF Shield | Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# CSS
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
html,body,.stApp{background:#0a0f1a!important;font-family:'Inter',sans-serif;color:#e2e8f0}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:#0f1622;border-radius:4px}
::-webkit-scrollbar-thumb{background:#2d3a5e;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#4d9fff}
section[data-testid="stSidebar"]{background:linear-gradient(180deg,#0c1222,#080e1a)!important;border-right:1px solid #1a2538!important}
section[data-testid="stSidebar"] *{color:#cbd5e6!important}
section[data-testid="stSidebar"] .stButton>button{background:transparent!important;border:none!important;text-align:left!important;padding:12px 16px!important;margin:4px 0!important;border-radius:10px!important;transition:all .2s}
section[data-testid="stSidebar"] .stButton>button:hover{background:rgba(77,159,255,.1)!important;border-left:3px solid #4d9fff!important;transform:translateX(4px)}
.dash-topbar{background:rgba(12,18,34,.8);backdrop-filter:blur(12px);border-bottom:1px solid #1e2d45;border-radius:0 0 16px 16px;padding:16px 28px;margin-bottom:28px;display:flex;align-items:center;justify-content:space-between}
.brand{font-size:1.4rem;font-weight:700;background:linear-gradient(135deg,#4d9fff,#00d4aa);-webkit-background-clip:text;background-clip:text;color:transparent}
.kpi-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin-bottom:28px}
.kpi-card{background:rgba(14,22,40,.6);backdrop-filter:blur(8px);border:1px solid rgba(30,45,69,.6);border-radius:20px;padding:20px 24px;transition:all .25s;position:relative;overflow:hidden}
.kpi-card::before{content:'';position:absolute;top:0;left:0;width:4px;height:100%;background:var(--accent)}
.kpi-card:hover{transform:translateY(-4px);border-color:rgba(77,159,255,.4);box-shadow:0 12px 28px rgba(0,0,0,.3)}
.kpi-card.critical{--accent:#ff4d6d}.kpi-card.warning{--accent:#ffc300}.kpi-card.success{--accent:#00d4aa}.kpi-card.info{--accent:#4d9fff}
.kpi-label{font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:1.5px;color:#8ba0c0;margin-bottom:8px}
.kpi-value{font-size:2.4rem;font-weight:700;line-height:1.1}
.kpi-sub{font-size:.7rem;color:#5a7a9a;margin-top:8px}
.panel{background:rgba(12,18,34,.5);backdrop-filter:blur(4px);border:1px solid #1e2d45;border-radius:20px;padding:20px 24px;margin-bottom:24px;transition:all .2s}
.panel:hover{border-color:#2a3d60;box-shadow:0 8px 24px rgba(0,0,0,.2)}
.panel-header{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #1e2d45;padding-bottom:14px;margin-bottom:18px}
.panel-title{font-size:.75rem;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#4d9fff}
.alert-row{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-radius:14px;margin-bottom:10px;background:rgba(9,22,40,.6);border-left:3px solid;transition:all .2s}
.alert-row:hover{background:rgba(20,35,60,.8);transform:translateX(4px)}
.alert-row.crit{border-color:#ff4d6d}.alert-row.high{border-color:#ff8c42}.alert-row.med{border-color:#ffc300}.alert-row.low{border-color:#4d9fff}
.alert-badge{font-size:.65rem;font-weight:700;padding:4px 10px;border-radius:20px;text-transform:uppercase;letter-spacing:.5px}
.badge-crit{background:#ff4d6d22;color:#ff4d6d;border:1px solid #ff4d6d66}
.badge-high{background:#ff8c4222;color:#ff8c42;border:1px solid #ff8c4266}
.badge-med{background:#ffc30022;color:#ffc300;border:1px solid #ffc30066}
.badge-low{background:#4d9fff22;color:#4d9fff;border:1px solid #4d9fff66}
.badge-clean{background:#00d4aa22;color:#00d4aa;border:1px solid #00d4aa66}
.verdict-banner{border-radius:24px;padding:24px 32px;display:flex;align-items:center;gap:24px;margin:20px 0}
.verdict-mal{border:1px solid #ff4d6d;box-shadow:0 0 20px rgba(255,77,109,.2);background:linear-gradient(135deg,rgba(255,77,109,.08),rgba(0,0,0,.2))}
.verdict-sus{border:1px solid #ffc300;box-shadow:0 0 20px rgba(255,195,0,.2);background:linear-gradient(135deg,rgba(255,195,0,.08),rgba(0,0,0,.2))}
.verdict-ben{border:1px solid #00d4aa;box-shadow:0 0 20px rgba(0,212,170,.2);background:linear-gradient(135deg,rgba(0,212,170,.08),rgba(0,0,0,.2))}
.verdict-icon{font-size:3rem}.verdict-text h2{font-size:1.8rem;font-weight:700;margin:0}
.dash-table{width:100%;border-collapse:collapse;font-size:.85rem}
.dash-table th{background:#0a1020;color:#4d9fff;padding:12px 16px;text-align:left;font-size:.7rem;font-weight:600;text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid #1e2d45}
.dash-table td{padding:12px 16px;border-bottom:1px solid #121a2a;color:#b8c4dc}
.dash-table tr:hover td{background:#0e1830}
.conf-bar-wrap{background:#1e2d45;border-radius:10px;height:6px;margin-top:8px;overflow:hidden}
.conf-bar-fill{height:6px;border-radius:10px;transition:width .4s}
.stButton>button{background:linear-gradient(135deg,#1a3a6a,#0f2848);border:1px solid #2a5a9a;border-radius:40px;padding:10px 24px;font-weight:600;font-size:.85rem;transition:all .2s;color:#e2e8f0}
.stButton>button:hover{background:linear-gradient(135deg,#2a5a9a,#1a3a6a);border-color:#4d9fff;transform:scale(1.02);box-shadow:0 4px 12px rgba(77,159,255,.3)}
.stTabs [data-baseweb="tab-list"]{background:#0c1222;border-radius:40px;padding:6px;gap:4px;border:1px solid #1e2d45}
.stTabs [data-baseweb="tab"]{border-radius:32px;padding:8px 20px;font-size:.8rem;font-weight:500;color:#8ba0c0}
.stTabs [aria-selected="true"]{background:#1e3a5c!important;color:#4d9fff!important}
.model-row{display:flex;justify-content:space-between;padding:12px 0;border-bottom:1px solid #1e2d45}
.scroll-box{max-height:320px;overflow-y:auto;padding-right:6px}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# SESSION STATE
# ─────────────────────────────────────────────────────────────────────────────

for key, val in [
    ("page", "dashboard"),
    ("scan_history", []),
    ("vt_api_key", ""),
]:
    if key not in st.session_state:
        st.session_state[key] = val

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — ML  (uses YOUR compare_models.py / dataset_loader.py functions)
# ─────────────────────────────────────────────────────────────────────────────

def _safe_float(v, d=0.0):
    try: return float(v)
    except: return d

def _encode_header_val(h):
    m = re.search(r'PDF-([\d.]+)', str(h))
    try: return float(m.group(1)) if m else 0.0
    except: return 0.0


def _build_vector(feat: dict) -> np.ndarray:
    """Convert feature dict (from extract_features) to ML input vector."""
    vec = []
    for col in FEATURE_ORDER:
        if col == "text_encoded":
            val = {"Yes": 1, "No": 0, "unclear": 0}.get(
                str(feat.get("text", "No")).strip(), 0)
        elif col == "pdf_version":
            val = _encode_header_val(feat.get("header", ""))
        else:
            val = _safe_float(feat.get(col, 0))
        vec.append(float(val))
    return np.array(vec, dtype=np.float32).reshape(1, -1)


@st.cache_resource(show_spinner=False)
def load_models():
    """
    Load models saved by compare_models.py or train_from_csv().
    Falls back to heuristic synthetic models if none found.
    Returns (rf, iso, scaler, imputer).
    """
    try:
        import joblib
        paths = {
            "rf":      os.path.join(MODEL_DIR, "rf_model.pkl"),
            "iso":     os.path.join(MODEL_DIR, "isolation_forest.pkl"),
            "scaler":  os.path.join(MODEL_DIR, "scaler.pkl"),
            "imputer": os.path.join(MODEL_DIR, "imputer.pkl"),
        }
        if all(os.path.isfile(p) for p in [paths["rf"], paths["iso"], paths["scaler"]]):
            rf     = joblib.load(paths["rf"])
            iso    = joblib.load(paths["iso"])
            scaler = joblib.load(paths["scaler"])
            imputer= joblib.load(paths["imputer"]) if os.path.isfile(paths["imputer"]) else None
            return rf, iso, scaler, imputer
    except Exception as e:
        st.warning(f"Could not load models: {e}")
    return None, None, None, None


def run_prediction(feat: dict) -> dict:
    """
    Run ML prediction using loaded models (or heuristic if not trained).
    Returns result dict for the GUI.
    """
    rf, iso, scaler, imputer = load_models()
    X = _build_vector(feat)

    if rf is None:
        # ── Heuristic fallback (no models trained yet) ──────────────
        threat_keys = ["JS","Javascript","OpenAction","launch","JBIG2Decode",
                       "RichMedia","XFA","ObjStm","EmbeddedFile","AA"]
        hits = sum(1 for k in threat_keys if _safe_float(feat.get(k, 0)) > 0)
        prob = min(0.95, hits * 0.15)
        verdict = "MALICIOUS" if prob > 0.6 else ("SUSPICIOUS" if prob > 0.3 else "BENIGN")
        return {
            "verdict": verdict,
            "rf_prediction": "MALICIOUS" if prob > 0.5 else "BENIGN",
            "rf_confidence": round(prob * 100, 1),
            "rf_prob_mal": prob,
            "rf_prob_ben": 1 - prob,
            "iso_anomaly": hits >= 2,
            "iso_score": round(-prob, 4),
            "top_features": [(k, 0.1) for k in threat_keys[:8]],
            "model_type": "heuristic",
        }

    # ── Real model prediction ────────────────────────────────────────
    import numpy as np
    if imputer is not None:
        X = imputer.transform(X)
    X = scaler.transform(X)

    rf_pred  = int(rf.predict(X)[0])
    rf_proba = rf.predict_proba(X)[0]
    rf_conf  = round(float(rf_proba[1]) * 100, 1)

    iso_raw   = iso.predict(X)[0]
    iso_score = round(float(iso.decision_function(X)[0]), 4)
    iso_anom  = (iso_raw == -1)

    verdict = ("MALICIOUS" if rf_conf >= 60 or (rf_conf >= 40 and iso_anom)
               else "SUSPICIOUS" if rf_conf >= 35 or iso_anom
               else "BENIGN")

    top_features = []
    if hasattr(rf, "feature_importances_"):
        imp = rf.feature_importances_
        idx = np.argsort(imp)[::-1][:8]
        top_features = [(FEATURE_ORDER[i], float(imp[i])) for i in idx]

    return {
        "verdict": verdict,
        "rf_prediction": "MALICIOUS" if rf_pred == 1 else "BENIGN",
        "rf_confidence": rf_conf,
        "rf_prob_mal": float(rf_proba[1]),
        "rf_prob_ben": float(rf_proba[0]),
        "iso_anomaly": iso_anom,
        "iso_score": iso_score,
        "top_features": top_features,
        "model_type": "trained",
    }


def load_metrics():
    if os.path.isfile(METRICS_FILE):
        with open(METRICS_FILE) as f:
            return json.load(f)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — THREAT INDICATORS  (derived from THREAT_META + extract_features)
# ─────────────────────────────────────────────────────────────────────────────

def get_indicators(feat: dict) -> list:
    """Return list of detected threat indicators from feature dict."""
    indicators = []
    for key, (desc, risk, attack) in THREAT_META.items():
        count = int(_safe_float(feat.get(key, 0)))
        if count > 0:
            indicators.append({"type": key, "count": count,
                               "description": desc, "risk": risk, "attack": attack})
    return sorted(indicators, key=lambda x: {"HIGH":0,"MEDIUM":1,"LOW":2}.get(x["risk"],3))


def get_intents(indicators: list, confidence: float) -> list:
    intents = []
    seen = set()
    intent_map = {
        "JS":          "Execute arbitrary JavaScript on victim machine",
        "Javascript":  "Execute arbitrary JavaScript on victim machine",
        "OpenAction":  "Auto-trigger payload the moment the PDF is opened",
        "AA":          "Trigger actions on specific user interactions",
        "launch":      "Execute shell commands / drop malware",
        "JBIG2Decode": "Exploit heap overflow (CVE-2009-0658 class)",
        "RichMedia":   "Exploit media player vulnerability",
        "XFA":         "Abuse XML Forms to run scripts or exfiltrate data",
        "ObjStm":      "Hide malicious objects from static scanners",
        "EmbeddedFile":"Drop a secondary payload onto the filesystem",
        "encrypt":     "Obfuscate malicious content from AV engines",
        "Acroform":    "Run JavaScript via form field events",
    }
    for ind in indicators:
        intent = intent_map.get(ind["type"])
        if intent and intent not in seen:
            intents.append(f"[{ind['risk']}] {intent}")
            seen.add(intent)
    if confidence > 75:
        intents.insert(0, f"High-confidence threat — RF model is {confidence:.0f}% certain")
    return intents


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — REMEDIATION  (calls YOUR remediate.py → remediate())
# ─────────────────────────────────────────────────────────────────────────────

def run_remediation(pdf_path: str, out_dir: str) -> dict:
    """
    Call remediate() from remediate.py and adapt the report dict for the GUI.
    """
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    stem       = Path(pdf_path).stem
    out_path   = os.path.join(out_dir, f"{stem}_CLEAN.pdf")

    report = remediate(pdf_path, out_path, save_report_json=False)

    if report is None:
        return {"error": "Remediation failed", "output_path": None,
                "total_removed": 0, "is_clean": False,
                "original_size_kb": 0, "clean_size_kb": 0,
                "original_md5": "N/A", "clean_md5": "N/A",
                "actions_taken": [], "threats_before": {}, "threats_after": {}}

    # Adapt remediate.py's report dict into what the GUI expects
    orig = report.get("original_file", {})
    cln  = report.get("cleaned_file",  {})
    rem  = report.get("remediation",   {})
    thr  = report.get("threats",       {})

    actions = []
    for name, cnt_before in thr.get("before", {}).items():
        cnt_after = thr.get("after", {}).get(name, 0)
        actions.append({
            "action":  f"Remove /{name}",
            "count":   max(0, cnt_before - cnt_after),
            "status":  "✅" if cnt_after == 0 else "⚠️",
        })

    return {
        "output_path":      out_path if os.path.isfile(out_path) else None,
        "clean_file":       Path(out_path).name,
        "method":           rem.get("method", "N/A"),
        "is_clean":         rem.get("is_clean", False),
        "total_removed":    rem.get("items_removed", 0),
        "original_size_kb": orig.get("size_kb", 0),
        "clean_size_kb":    cln.get("size_kb", 0),
        "original_md5":     orig.get("md5", "N/A"),
        "original_sha256":  orig.get("sha256", "N/A"),
        "clean_md5":        cln.get("md5", "N/A"),
        "actions_taken":    actions,
        "threats_before":   thr.get("before", {}),
        "threats_after":    thr.get("after",  {}),
        "duration_s":       rem.get("duration_s", 0),
        "warnings":         report.get("warnings", []),
    }


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — THREAT INTEL
# ─────────────────────────────────────────────────────────────────────────────

def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def mb_check_hash(sha256: str) -> dict:
    try:
        import requests
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query": "get_info", "hash": sha256}, timeout=10)
        data = r.json()
        if data.get("query_status") == "hash_not_found":
            return {"found": False}
        if data.get("query_status") == "ok":
            s = data["data"][0]
            return {"found": True, "malware_family": s.get("signature","Unknown"),
                    "first_seen": s.get("first_seen",""), "tags": s.get("tags",[])}
        return {"found": False}
    except Exception as e:
        return {"error": str(e), "found": False}


@st.cache_data(ttl=300)
def mb_recent_feed() -> list:
    try:
        import requests
        r = requests.post("https://mb-api.abuse.ch/api/v1/",
                          data={"query": "get_file_type", "file_type": "pdf", "limit": 20},
                          timeout=12)
        data = r.json()
        if data.get("query_status") == "ok":
            return [{"family": s.get("signature","Unknown"),
                     "date":   s.get("first_seen","")[:10],
                     "reporter": s.get("reporter","?"),
                     "tags":   s.get("tags",[])} for s in data.get("data",[])]
    except Exception:
        pass
    return []


def vt_check(sha256: str, api_key: str) -> dict:
    if not api_key:
        return {"error": "No API key"}
    try:
        import requests
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                         headers={"x-apikey": api_key}, timeout=15)
        if r.status_code == 404: return {"found": False}
        if r.status_code == 401: return {"error": "Invalid API key"}
        if r.status_code == 429: return {"error": "Rate limit exceeded"}
        stats = r.json().get("data",{}).get("attributes",{}).get("last_analysis_stats",{})
        return {"found": True, "malicious": stats.get("malicious",0),
                "total_engines": sum(stats.values())}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — TRAINING  (uses YOUR dataset_loader.py + compare_models.py)
# ─────────────────────────────────────────────────────────────────────────────

def train_from_csv(csv_path: str, callback=None) -> dict:
    """
    Load CSV using dataset_loader.load_and_preprocess(),
    then train models using compare_models.run_supervised() logic.
    Saves models to models/ folder.
    """
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.svm import SVC
    from sklearn.preprocessing import StandardScaler
    from sklearn.impute import SimpleImputer
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
    import joblib

    def cb(msg, step):
        if callback: callback(msg, step)
        else: print(f"  [{step}] {msg}")

    cb("Loading dataset with dataset_loader.py ...", 1)
    features, labels, feat_names = load_and_preprocess(csv_path)
    counts = Counter(labels)
    cb(f"Loaded {len(labels)} samples — {counts[1]} malicious / {counts[0]} benign", 2)

    # Convert list-of-dicts to numpy array in FEATURE_ORDER
    cb("Converting features to arrays ...", 3)
    X = np.array([[_safe_float(f.get(col, 0)) for col in FEATURE_ORDER]
                  for f in features], dtype=np.float32)
    y = np.array(labels, dtype=np.int32)

    cb("Imputing + scaling ...", 4)
    imputer = SimpleImputer(strategy="median")
    X = imputer.fit_transform(X)
    scaler = StandardScaler()
    X = scaler.fit_transform(X)

    # Stratified split
    from compare_models import stratified_split
    X_tr, y_tr, X_te, y_te = stratified_split(X, y)
    cb(f"Train: {len(y_tr)}  Test: {len(y_te)}", 5)

    Path(MODEL_DIR).mkdir(parents=True, exist_ok=True)
    results = {}
    metrics = {}

    model_defs = {
        "RandomForest": RandomForestClassifier(n_estimators=200, max_features="sqrt",
                        class_weight="balanced", random_state=42, n_jobs=-1),
        "DecisionTree": DecisionTreeClassifier(max_depth=15, min_samples_split=5,
                        class_weight="balanced", random_state=42),
        "SVM":          SVC(kernel="rbf", C=10, gamma="scale",
                        class_weight="balanced", probability=True, random_state=42),
    }

    for i, (name, model) in enumerate(model_defs.items(), 6):
        cb(f"Training {name} ...", i)
        model.fit(X_tr, y_tr)
        preds = model.predict(X_te)
        metrics[name] = {
            "accuracy":  round(accuracy_score(y_te, preds) * 100, 2),
            "precision": round(precision_score(y_te, preds, zero_division=0) * 100, 2),
            "recall":    round(recall_score(y_te, preds, zero_division=0) * 100, 2),
            "f1":        round(f1_score(y_te, preds, zero_division=0) * 100, 2),
        }
        results[name] = model

    cb("Training Isolation Forest ...", 9)
    iso = IsolationForest(n_estimators=200, contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_tr)
    results["IsolationForest"] = iso

    cb("Saving models ...", 10)
    joblib.dump(results["RandomForest"], os.path.join(MODEL_DIR, "rf_model.pkl"))
    joblib.dump(results["DecisionTree"], os.path.join(MODEL_DIR, "dt_model.pkl"))
    joblib.dump(results["SVM"],          os.path.join(MODEL_DIR, "svm_model.pkl"))
    joblib.dump(iso,                     os.path.join(MODEL_DIR, "isolation_forest.pkl"))
    joblib.dump(scaler,                  os.path.join(MODEL_DIR, "scaler.pkl"))
    joblib.dump(imputer,                 os.path.join(MODEL_DIR, "imputer.pkl"))

    best = max(metrics, key=lambda k: metrics[k]["f1"])
    metrics["best_model"]    = best
    metrics["dataset_info"]  = {"total_samples": int(len(y)),
                                 "malicious": int(counts[1]), "benign": int(counts[0]),
                                 "feature_count": X.shape[1]}
    with open(METRICS_FILE, "w") as f:
        json.dump(metrics, f, indent=2)

    return metrics


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — HTML REPORT  (for download in scan page)
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(feat, prediction, indicators, rem_report, pdf_name) -> str:
    verdict  = prediction["verdict"]
    vc = {"MALICIOUS":"#e94560","SUSPICIOUS":"#ffc300","BENIGN":"#2ecc71"}.get(verdict,"#7f8c8d")
    conf     = prediction["rf_confidence"]
    ind_rows = ""
    for ind in indicators:
        sc = {"HIGH":"#e94560","MEDIUM":"#ffc300","LOW":"#2ecc71"}.get(ind["risk"],"#7f8c8d")
        ind_rows += f"<tr><td style='color:#79c0ff;font-family:monospace'>{ind['type']}</td><td>{ind['count']}</td><td style='color:{sc};font-weight:bold'>{ind['risk']}</td><td>{ind['description']}</td><td style='color:#a0aec0'>{ind['attack']}</td></tr>"
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>PDF Shield — {pdf_name}</title>
<style>body{{background:#0a0f1a;color:#e2e8f0;font-family:Segoe UI,sans-serif;padding:40px}}
h1{{background:linear-gradient(135deg,#4d9fff,#00d4aa);-webkit-background-clip:text;background-clip:text;color:transparent}}
.s{{background:rgba(14,22,40,.6);border:1px solid #1e2d45;border-radius:16px;padding:20px;margin:20px 0}}
h2{{color:#4d9fff;font-size:.75rem;text-transform:uppercase;letter-spacing:2px;border-bottom:1px solid #1e2d45;padding-bottom:8px;margin-bottom:12px}}
table{{width:100%;border-collapse:collapse;font-size:.85rem}}th{{background:#0a1020;color:#4d9fff;padding:10px;text-align:left;font-size:.7rem;text-transform:uppercase}}
td{{padding:10px;border-bottom:1px solid #121a2a;color:#b8c4dc}}tr:hover td{{background:#0e1830}}
.v{{font-size:2rem;font-weight:700;color:{vc}}}footer{{color:#2d3a5e;text-align:center;margin-top:40px;font-size:.75rem}}</style></head>
<body><h1>🛡️ PDF Shield — Forensic Report</h1>
<p style="color:#5a7a9a">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | FYP: PDF Malware Detection | MUET</p>
<div class="s"><h2>Verdict</h2><div class="v">{verdict}</div>
<p style="margin-top:8px">RF Confidence: <b style="color:#4d9fff">{conf}%</b> &nbsp;|&nbsp; Indicators: <b style="color:#e94560">{len(indicators)}</b> &nbsp;|&nbsp; Anomaly: <b>{"Yes" if prediction["iso_anomaly"] else "No"}</b></p></div>
<div class="s"><h2>File</h2><table>
<tr><td><b>Name</b></td><td>{pdf_name}</td></tr>
<tr><td><b>Size</b></td><td>{feat.get("pdfsize",0)} KB</td></tr>
<tr><td><b>Pages</b></td><td>{feat.get("pages",0)}</td></tr>
<tr><td><b>PDF Version</b></td><td>{feat.get("header","N/A")}</td></tr>
<tr><td><b>Encrypted</b></td><td>{"Yes" if feat.get("isEncrypted") else "No"}</td></tr>
</table></div>
<div class="s"><h2>Threat Indicators ({len(indicators)})</h2>
{"<p style='color:#2ecc71'>✅ No threat indicators found.</p>" if not indicators else
f"<table><tr><th>Indicator</th><th>Count</th><th>Severity</th><th>Description</th><th>Attack Type</th></tr>{ind_rows}</table>"}
</div>
<div class="s"><h2>Remediation</h2><table>
<tr><td><b>Method</b></td><td>{rem_report.get("method","N/A")}</td></tr>
<tr><td><b>Status</b></td><td style="color:{'#2ecc71' if rem_report.get('is_clean') else '#ffc300'}">{"Fully Clean" if rem_report.get("is_clean") else "Partially Cleaned"}</td></tr>
<tr><td><b>Items Removed</b></td><td>{rem_report.get("total_removed",0)}</td></tr>
<tr><td><b>Original → Clean</b></td><td>{rem_report.get("original_size_kb",0)} KB → {rem_report.get("clean_size_kb",0)} KB</td></tr>
</table></div>
<footer>PDF Shield v1.0 | Bilawal Ali (22BSCYS002) &amp; Sagar (22BSCYS049) | BS Cyber Security, MUET | Supervisor: Engr. Mehran Mamonai</footer>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS — CHARTS
# ─────────────────────────────────────────────────────────────────────────────

def gauge_chart(value, title, color):
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=value,
        title={"text": title, "font": {"color": "#a0aec0", "size": 13}},
        number={"suffix": "%", "font": {"color": color, "size": 28}},
        gauge={"axis": {"range": [0,100], "tickcolor":"#1e2d45","tickfont":{"color":"#5a7a9a","size":9}},
               "bar": {"color": color}, "bgcolor": "#091628", "bordercolor": "#1e2d45",
               "steps": [{"range":[0,40],"color":"#0a1520"},{"range":[40,70],"color":"#0d1a2a"},{"range":[70,100],"color":"#0f1f33"}],
               "threshold": {"line":{"color":color,"width":2},"thickness":0.75,"value":value}}
    ))
    fig.update_layout(height=180, margin=dict(l=10,r=10,t=40,b=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
    return fig


def donut_chart(labels, values, colors, title):
    fig = go.Figure(go.Pie(labels=labels, values=values, hole=.65,
                            marker_colors=colors, textfont={"color":"#a0aec0","size":11},
                            hovertemplate="%{label}: %{value}<extra></extra>"))
    fig.update_layout(title={"text":title,"font":{"color":"#a0aec0","size":13}},
                      height=220, margin=dict(l=10,r=10,t=40,b=10),
                      paper_bgcolor="rgba(0,0,0,0)",
                      legend={"font":{"color":"#a0aec0","size":11},"bgcolor":"rgba(0,0,0,0)"})
    return fig


def bar_chart(labels, values, colors, title):
    fig = go.Figure(go.Bar(x=labels, y=values, marker_color=colors,
                            marker_line_color="#1e2d45", marker_line_width=1))
    fig.update_layout(title={"text":title,"font":{"color":"#a0aec0","size":13}},
                      height=220, margin=dict(l=10,r=10,t=40,b=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      xaxis={"gridcolor":"#1e2d45","tickfont":{"color":"#5a7a9a"},"showgrid":False},
                      yaxis={"gridcolor":"#1e2d45","tickfont":{"color":"#5a7a9a"},"gridwidth":.5})
    return fig


def vc(v): return {"MALICIOUS":"#ff4d6d","SUSPICIOUS":"#ffc300","BENIGN":"#00d4aa"}.get(v,"#5a7a9a")
def vc_css(v): return {"MALICIOUS":"verdict-mal","SUSPICIOUS":"verdict-sus","BENIGN":"verdict-ben"}.get(v,"")


# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="padding:20px 0 24px;text-align:center;border-bottom:1px solid #1e2d45;margin-bottom:24px">
      <div style="font-size:1.8rem;font-weight:800;background:linear-gradient(135deg,#4d9fff,#00d4aa);-webkit-background-clip:text;background-clip:text;color:transparent">🛡️ PDF Shield</div>
      <div style="font-size:.7rem;color:#4d9fff;margin-top:6px;letter-spacing:1px">SECURITY ANALYSIS PLATFORM</div>
    </div>""", unsafe_allow_html=True)

    for page_id, icon, label in [
        ("dashboard",    "📊", "Overview"),
        ("scan",         "🔬", "Scan PDF"),
        ("training",     "🧠", "Model Training"),
        ("threat_intel", "🌐", "Threat Intel"),
        ("history",      "📋", "History"),
        ("settings",     "⚙️",  "Settings"),
    ]:
        if st.button(f"{icon}  {label}", key=f"nav_{page_id}"):
            st.session_state.page = page_id
            st.rerun()

    st.markdown("---")
    metrics = load_metrics()
    if metrics:
        best = metrics.get("best_model","RF")
        acc  = metrics.get(best,{}).get("accuracy","?")
        ds   = metrics.get("dataset_info",{})
        st.markdown(f"""
        <div style="background:rgba(9,22,40,.6);border-radius:16px;padding:16px;border:1px solid #1e2d45">
          <div style="color:#00d4aa;font-size:.7rem;text-transform:uppercase;letter-spacing:1px">✅ Real Model Active</div>
          <div style="font-size:.8rem;margin-top:8px"><span style="color:#8ba0c0">Best:</span> <strong style="color:#4d9fff">{best}</strong></div>
          <div style="font-size:.8rem"><span style="color:#8ba0c0">Accuracy:</span> <strong style="color:#00d4aa">{acc}%</strong></div>
          <div style="font-size:.7rem;color:#5a7a9a;margin-top:6px">{ds.get("total_samples","?")} samples trained</div>
        </div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="background:rgba(9,22,40,.6);border-radius:16px;padding:16px;border:1px solid #ffc30044">
          <div style="color:#ffc300;font-size:.7rem;text-transform:uppercase">⚠️ No trained models</div>
          <div style="font-size:.75rem;margin-top:6px">Go to Model Training →</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<div style='margin-top:20px;font-size:.7rem;color:#4d9fff;text-transform:uppercase;letter-spacing:1px'>VirusTotal API Key</div>", unsafe_allow_html=True)
    vt_key = st.text_input("", value=st.session_state.vt_api_key,
                            placeholder="Paste VT key...", type="password",
                            label_visibility="collapsed")
    if vt_key != st.session_state.vt_api_key:
        st.session_state.vt_api_key = vt_key

page = st.session_state.page

# ─────────────────────────────────────────────────────────────────────────────
# PAGE: DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

if page == "dashboard":
    st.markdown(f"""
    <div class="dash-topbar">
      <div class="brand">🛡️ PDF SHIELD — SECURITY OPERATIONS CENTER</div>
      <div style="color:#5a7a9a;font-size:.75rem">{datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
    </div>""", unsafe_allow_html=True)

    hist  = st.session_state.scan_history
    total = len(hist)
    mal   = sum(1 for h in hist if h.get("verdict") == "MALICIOUS")
    sus   = sum(1 for h in hist if h.get("verdict") == "SUSPICIOUS")
    ben   = sum(1 for h in hist if h.get("verdict") == "BENIGN")
    m     = load_metrics()
    acc   = m.get(m.get("best_model",""), {}).get("accuracy","N/A") if m else "N/A"

    st.markdown(f"""
    <div class="kpi-grid">
      <div class="kpi-card critical"><div class="kpi-label">Malicious Detected</div><div class="kpi-value">{mal}</div><div class="kpi-sub">Confirmed threats</div></div>
      <div class="kpi-card warning"> <div class="kpi-label">Suspicious Files</div><div class="kpi-value">{sus}</div><div class="kpi-sub">Require review</div></div>
      <div class="kpi-card success"> <div class="kpi-label">Clean Files</div><div class="kpi-value">{ben}</div><div class="kpi-sub">Benign PDFs</div></div>
      <div class="kpi-card info">    <div class="kpi-label">Model Accuracy</div><div class="kpi-value">{acc}{"%" if acc != "N/A" else ""}</div><div class="kpi-sub">{"meragedatacsv.csv trained" if m else "Not trained yet"}</div></div>
    </div>""", unsafe_allow_html=True)

    c1, c2, c3 = st.columns([2,2,1.5])
    with c1:
        st.markdown('<div class="panel"><div class="panel-header"><span class="panel-title">📊 Scan Distribution</span></div>', unsafe_allow_html=True)
        if total > 0:
            st.plotly_chart(donut_chart(["Malicious","Suspicious","Benign"],
                            [max(mal,.01),max(sus,.01),max(ben,.01)],
                            ["#ff4d6d","#ffc300","#00d4aa"],""), use_container_width=True, config={"displayModeBar":False})
        else:
            st.markdown('<div style="height:180px;display:flex;align-items:center;justify-content:center;color:#5a7a9a">No scans yet</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="panel"><div class="panel-header"><span class="panel-title">🔬 Top Threat Indicators</span></div>', unsafe_allow_html=True)
        if hist:
            cnt = {}
            for h in hist:
                for ind in h.get("indicators", []):
                    cnt[ind["type"]] = cnt.get(ind["type"], 0) + 1
            if cnt:
                top = sorted(cnt.items(), key=lambda x: x[1], reverse=True)[:6]
                st.plotly_chart(bar_chart([x[0] for x in top], [x[1] for x in top],
                                ["#ff4d6d"]*2+["#ffc300"]*2+["#4d9fff"]*2, ""), use_container_width=True, config={"displayModeBar":False})
            else:
                st.markdown('<div style="height:180px;display:flex;align-items:center;justify-content:center;color:#5a7a9a">No indicators yet</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="height:180px;display:flex;align-items:center;justify-content:center;color:#5a7a9a">Upload a PDF to begin</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with c3:
        st.markdown('<div class="panel"><div class="panel-header"><span class="panel-title">🌐 Live Malware Feed</span></div>', unsafe_allow_html=True)
        feed = mb_recent_feed()
        if feed:
            st.markdown('<div class="scroll-box">', unsafe_allow_html=True)
            for s in feed[:8]:
                tags = ", ".join(s.get("tags",[])[:2]) or "pdf"
                st.markdown(f'<div class="alert-row crit"><div><div style="font-weight:600">{s["family"]}</div><div style="font-size:.7rem;color:#5a7a9a">{s["date"]} · {tags}</div></div><span class="alert-badge badge-crit">LIVE</span></div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="color:#5a7a9a;font-size:.8rem">Feed unavailable (no internet or requests not installed)</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="panel"><div class="panel-header"><span class="panel-title">📋 Recent Scan History</span></div>', unsafe_allow_html=True)
    if hist:
        rows = ""
        for h in reversed(hist[-10:]):
            v = h.get("verdict","?")
            bc = {"MALICIOUS":"badge-crit","SUSPICIOUS":"badge-med","BENIGN":"badge-clean"}.get(v,"badge-low")
            rows += f"<tr><td>{h.get('filename','?')}</td><td><span class='alert-badge {bc}'>{v}</span></td><td style='color:#ffc300'>{h.get('confidence','?')}%</td><td style='color:#ff4d6d'>{len(h.get('indicators',[]))}</td><td style='color:#00d4aa'>{h.get('removed',0)}</td><td style='color:#5a7a9a'>{h.get('timestamp','')}</td></tr>"
        st.markdown(f'<table class="dash-table"><tr><th>File</th><th>Verdict</th><th>Confidence</th><th>Indicators</th><th>Removed</th><th>Time</th></tr>{rows}</table>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="text-align:center;padding:24px;color:#5a7a9a">No scans yet. Upload a PDF to begin.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: SCAN
# ─────────────────────────────────────────────────────────────────────────────

elif page == "scan":
    st.markdown("""
    <div style="margin-bottom:28px">
      <div style="font-size:1.6rem;font-weight:700;background:linear-gradient(135deg,#fff,#4d9fff);-webkit-background-clip:text;background-clip:text;color:transparent">🔬 PDF Analysis Scanner</div>
      <div style="color:#8ba0c0;margin-top:6px">Upload a PDF for ML detection, remediation &amp; threat intelligence — powered by your trained models</div>
    </div>""", unsafe_allow_html=True)

    up_col, opt_col = st.columns([2,1])
    with up_col:
        uploaded = st.file_uploader("", type=["pdf"], label_visibility="collapsed")
    with opt_col:
        st.markdown('<div class="panel" style="padding:16px"><div style="font-size:.7rem;color:#4d9fff;text-transform:uppercase">Scan Options</div>', unsafe_allow_html=True)
        run_ti  = st.checkbox("Threat Intel Lookup", value=True)
        run_rem = st.checkbox("Auto-Remediate", value=True)
        st.markdown('</div>', unsafe_allow_html=True)

    if uploaded:
        tmp_dir  = tempfile.mkdtemp()
        pdf_path = os.path.join(tmp_dir, uploaded.name)
        with open(pdf_path, "wb") as f:
            f.write(uploaded.read())

        if st.button("🚀 Launch Full Analysis", type="primary"):
            pb  = st.progress(0)
            ptx = st.empty()

            # ── Step 1: Feature extraction (YOUR feature_extractor.py) ───────
            ptx.markdown("**[1/5]** Extracting PDF features via `feature_extractor.py` ...")
            feat = extract_features(pdf_path)
            pb.progress(20)
            if not feat:
                st.error("Feature extraction failed. Is this a valid PDF?")
                st.stop()

            # ── Step 2: ML prediction ─────────────────────────────────────────
            ptx.markdown("**[2/5]** Running ML classification ...")
            prediction = run_prediction(feat)
            indicators = get_indicators(feat)
            intents    = get_intents(indicators, prediction["rf_confidence"])
            pb.progress(40)
            time.sleep(0.1)

            # ── Step 3: Remediation (YOUR remediate.py → remediate()) ─────────
            ptx.markdown("**[3/5]** Remediating via `remediate.py` ...")
            clean_dir  = os.path.join(tmp_dir, "clean")
            rem_report = run_remediation(pdf_path, clean_dir) if run_rem else {
                "total_removed":0,"is_clean":None,"original_size_kb":0,
                "clean_size_kb":0,"original_md5":"N/A","clean_md5":"N/A",
                "actions_taken":[],"method":"skipped","output_path":None}
            pb.progress(60)

            # ── Step 4: Threat intel ──────────────────────────────────────────
            ptx.markdown("**[4/5]** Querying threat intelligence ...")
            sha256_val = _sha256(pdf_path)
            ti_mb = mb_check_hash(sha256_val) if run_ti else {"found": False}
            ti_vt = vt_check(sha256_val, st.session_state.vt_api_key) if (run_ti and st.session_state.vt_api_key) else {"error": "No key"}
            pb.progress(80)

            # ── Step 5: Reports ──────────────────────────────────────────────
            ptx.markdown("**[5/5]** Generating reports ...")
            html_rep = generate_html_report(feat, prediction, indicators, rem_report, uploaded.name)
            json_rep = json.dumps({"file": uploaded.name, "verdict": prediction["verdict"],
                                   "features": feat, "prediction": prediction,
                                   "indicators": indicators, "remediation": rem_report,
                                   "sha256": sha256_val}, indent=2, default=str)
            pb.progress(100)
            pb.empty(); ptx.empty()

            # Save to history
            st.session_state.scan_history.append({
                "filename":   uploaded.name,
                "verdict":    prediction["verdict"],
                "confidence": prediction["rf_confidence"],
                "indicators": indicators,
                "removed":    rem_report.get("total_removed", 0),
                "timestamp":  datetime.now().strftime("%H:%M:%S"),
            })

            # ── Verdict banner ────────────────────────────────────────────────
            v    = prediction["verdict"]
            icon = {"MALICIOUS":"🔴","SUSPICIOUS":"🟡","BENIGN":"🟢"}.get(v,"⚪")
            model_type_note = "*(heuristic — train models for real predictions)*" if prediction.get("model_type") == "heuristic" else ""
            st.markdown(f"""
            <div class="verdict-banner {vc_css(v)}">
              <div class="verdict-icon">{icon}</div>
              <div class="verdict-text">
                <h2>{v}</h2>
                <p>{uploaded.name} &nbsp;·&nbsp; {prediction['rf_confidence']}% confidence &nbsp;·&nbsp; {len(indicators)} indicators &nbsp;·&nbsp; {rem_report.get('total_removed',0)} threats removed</p>
              </div>
            </div>""", unsafe_allow_html=True)
            if model_type_note:
                st.caption(model_type_note)

            # ── KPIs ──────────────────────────────────────────────────────────
            k1,k2,k3,k4 = st.columns(4)
            for col, lbl, val, clr in [
                (k1,"RF Confidence",   f"{prediction['rf_confidence']}%", vc(v)),
                (k2,"Threat Indicators",str(len(indicators)),              "#ff4d6d" if indicators else "#00d4aa"),
                (k3,"ISO Anomaly",     "YES" if prediction["iso_anomaly"] else "NO", "#ffc300" if prediction["iso_anomaly"] else "#00d4aa"),
                (k4,"Items Removed",   str(rem_report.get("total_removed",0)), "#00d4aa"),
            ]:
                with col:
                    st.markdown(f'<div class="kpi-card info" style="--accent:{clr}"><div class="kpi-label">{lbl}</div><div class="kpi-value" style="color:{clr}">{val}</div></div>', unsafe_allow_html=True)

            st.markdown("---")
            t1,t2,t3,t4,t5,t6 = st.tabs(["🤖 ML Results","⚠️ Indicators","🎯 Intent","🧹 Remediation","🌐 Threat Intel","📋 Reports"])

            # ── Tab 1: ML ─────────────────────────────────────────────────────
            with t1:
                c1, c2 = st.columns(2)
                with c1:
                    st.plotly_chart(gauge_chart(prediction["rf_confidence"], "Random Forest\nP(Malicious)", vc(v)), use_container_width=True, config={"displayModeBar":False})
                    st.markdown(f'<div class="panel"><div class="panel-title">Random Forest</div><div style="display:flex;justify-content:space-between;padding:8px 0"><span style="color:#8ba0c0">Verdict</span><span style="color:{vc(v)};font-weight:600">{prediction["rf_prediction"]}</span></div><div style="display:flex;justify-content:space-between"><span style="color:#8ba0c0">Confidence</span><span style="color:{vc(v)}">{prediction["rf_confidence"]}%</span></div></div>', unsafe_allow_html=True)
                with c2:
                    iso_pct = min(100, max(0, int((1 + prediction["iso_score"]) * 50)))
                    iso_col = "#ff4d6d" if prediction["iso_anomaly"] else "#00d4aa"
                    st.plotly_chart(gauge_chart(iso_pct, "Isolation Forest\nAnomaly Score", iso_col), use_container_width=True, config={"displayModeBar":False})
                    st.markdown(f'<div class="panel"><div class="panel-title">Isolation Forest</div><div style="display:flex;justify-content:space-between;padding:8px 0"><span style="color:#8ba0c0">Anomaly</span><span style="color:{iso_col};font-weight:600">{"⚠️ DETECTED" if prediction["iso_anomaly"] else "✅ NORMAL"}</span></div><div style="display:flex;justify-content:space-between"><span style="color:#8ba0c0">Score</span><span>{prediction["iso_score"]}</span></div></div>', unsafe_allow_html=True)

                if prediction.get("top_features"):
                    st.markdown('<div class="panel"><div class="panel-title">Top Feature Importances</div>', unsafe_allow_html=True)
                    for fname, imp in prediction["top_features"]:
                        pct = min(100, int(imp * 1000))
                        val = feat.get(fname, 0)
                        clr = "#ff4d6d" if fname in ["JS","Javascript","OpenAction","launch","JBIG2Decode"] else "#4d9fff"
                        st.markdown(f'<div style="display:flex;justify-content:space-between;margin-bottom:4px"><span style="font-family:monospace;font-size:.8rem;color:#79c0ff">{fname}</span><span style="font-size:.75rem;color:#8ba0c0">val={val} · imp={imp:.4f}</span></div><div class="conf-bar-wrap"><div class="conf-bar-fill" style="width:{pct}%;background:{clr}"></div></div>', unsafe_allow_html=True)
                    st.markdown('</div>', unsafe_allow_html=True)

            # ── Tab 2: Indicators ─────────────────────────────────────────────
            with t2:
                if not indicators:
                    st.markdown('<div class="panel" style="text-align:center;color:#00d4aa">✅ No suspicious indicators found</div>', unsafe_allow_html=True)
                else:
                    risk_map = {"HIGH":("crit","badge-crit"),"MEDIUM":("high","badge-med"),"LOW":("med","badge-low")}
                    for ind in indicators:
                        rc, bc = risk_map.get(ind["risk"],("low","badge-low"))
                        st.markdown(f'<div class="alert-row {rc}"><div><div style="font-weight:600">{ind["type"]} <span style="color:#5a7a9a">× {ind["count"]}</span></div><div style="font-size:.75rem">{ind["description"]}</div><div style="font-size:.7rem;color:#79c0ff">🎯 {ind["attack"]}</div></div><span class="alert-badge {bc}">{ind["risk"]}</span></div>', unsafe_allow_html=True)

            # ── Tab 3: Intent ─────────────────────────────────────────────────
            with t3:
                st.markdown('<div class="panel"><div class="panel-title">🎯 Attacker Intent</div>', unsafe_allow_html=True)
                if intents:
                    for intent in intents:
                        st.markdown(f'<div class="alert-row crit"><div>{intent}</div></div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div style="color:#00d4aa">✅ No malicious intent detected</div>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)
                st.markdown(f'<div class="panel"><div class="panel-title">📁 File Hashes</div>', unsafe_allow_html=True)
                st.code(f"SHA256: {sha256_val}\nMD5:    {rem_report.get('original_md5','N/A')}", language=None)
                st.markdown('</div>', unsafe_allow_html=True)

            # ── Tab 4: Remediation ────────────────────────────────────────────
            with t4:
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f'<div class="panel"><div class="panel-title">Original File</div><div style="font-size:1.8rem;font-weight:700;color:#ff4d6d">{rem_report.get("original_size_kb",0)} KB</div><div style="font-family:monospace;font-size:.7rem">{rem_report.get("original_md5","N/A")}</div></div>', unsafe_allow_html=True)
                with c2:
                    st.markdown(f'<div class="panel"><div class="panel-title">Clean File</div><div style="font-size:1.8rem;font-weight:700;color:#00d4aa">{rem_report.get("clean_size_kb",0)} KB</div><div style="font-family:monospace;font-size:.7rem">{rem_report.get("clean_md5","N/A")}</div></div>', unsafe_allow_html=True)

                st.markdown('<div class="panel"><div class="panel-title">🔧 Actions Taken (remediate.py)</div><div class="scroll-box">', unsafe_allow_html=True)
                for act in rem_report.get("actions_taken", []):
                    clr = "#00d4aa" if act["count"] > 0 else "#5a7a9a"
                    st.markdown(f'<div style="display:flex;justify-content:space-between;padding:8px 0"><span style="color:{clr}">{act["status"]} {act["action"]}</span><span>×{act["count"]}</span></div>', unsafe_allow_html=True)
                if not rem_report.get("actions_taken"):
                    st.markdown('<div style="color:#5a7a9a">No actions taken</div>', unsafe_allow_html=True)
                st.markdown('</div></div>', unsafe_allow_html=True)

                op = rem_report.get("output_path")
                if op and os.path.isfile(op):
                    with open(op, "rb") as f:
                        st.download_button("⬇️ Download Clean PDF", f.read(),
                                          rem_report.get("clean_file","clean.pdf"), "application/pdf")

            # ── Tab 5: Threat Intel ───────────────────────────────────────────
            with t5:
                st.markdown('<div class="panel"><div class="panel-title">🦠 MalwareBazaar</div>', unsafe_allow_html=True)
                if ti_mb.get("found"):
                    st.markdown(f'<span class="alert-badge badge-crit">⚠️ CONFIRMED MALWARE</span><br><br>Family: <b>{ti_mb.get("malware_family","Unknown")}</b><br>First seen: {ti_mb.get("first_seen","?")[:10]}', unsafe_allow_html=True)
                elif ti_mb.get("error"):
                    st.markdown(f'<span style="color:#ffc300">{ti_mb["error"]}</span>', unsafe_allow_html=True)
                else:
                    st.markdown('<span class="alert-badge badge-clean">✅ Not found in MalwareBazaar</span>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

                st.markdown('<div class="panel"><div class="panel-title">🔍 VirusTotal</div>', unsafe_allow_html=True)
                if not st.session_state.vt_api_key:
                    st.markdown('<div style="color:#ffc300">⚠️ No API key — add in sidebar</div>', unsafe_allow_html=True)
                elif ti_vt.get("found"):
                    st.markdown(f'<div style="font-size:1.2rem;font-weight:700;color:#ff4d6d">{ti_vt["malicious"]}/{ti_vt["total_engines"]} engines detected</div>', unsafe_allow_html=True)
                elif ti_vt.get("error"):
                    st.markdown(f'<span style="color:#ffc300">{ti_vt["error"]}</span>', unsafe_allow_html=True)
                else:
                    st.markdown('<span class="alert-badge badge-clean">✅ Not found in VirusTotal</span>', unsafe_allow_html=True)
                st.markdown('</div>', unsafe_allow_html=True)

            # ── Tab 6: Reports ────────────────────────────────────────────────
            with t6:
                c1, c2 = st.columns(2)
                with c1:
                    st.download_button("⬇️ HTML Report", html_rep,
                                      f"report_{uploaded.name}.html", "text/html")
                with c2:
                    st.download_button("⬇️ JSON Report", json_rep,
                                      f"report_{uploaded.name}.json", "application/json")

                # Optional: full PDF forensic report via forensic_report.py
                st.markdown("---")
                st.markdown("**Generate full PDF forensic report** *(requires reportlab + trained models)*")
                if st.button("📄 Generate PDF Forensic Report"):
                    try:
                        from forensic_report import generate_report
                        out_pdf = os.path.join(tmp_dir, f"{Path(uploaded.name).stem}_FORENSIC.pdf")
                        result  = generate_report(pdf_path, MODEL_DIR, None, out_pdf)
                        if result and os.path.isfile(result):
                            with open(result, "rb") as f:
                                st.download_button("⬇️ Download PDF Report", f.read(),
                                                  Path(result).name, "application/pdf")
                    except ImportError:
                        st.error("reportlab not installed. Run: pip install reportlab")
                    except Exception as e:
                        st.error(f"Report generation failed: {e}")

            try: shutil.rmtree(tmp_dir)
            except: pass


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: TRAINING  (uses YOUR dataset_loader.py + compare_models.py)
# ─────────────────────────────────────────────────────────────────────────────

elif page == "training":
    st.markdown("""
    <div style="margin-bottom:28px">
      <div style="font-size:1.6rem;font-weight:700;background:linear-gradient(135deg,#fff,#4d9fff);-webkit-background-clip:text;background-clip:text;color:transparent">🧠 Model Training</div>
      <div style="color:#8ba0c0;margin-top:6px">Trains using <b>dataset_loader.py</b> + <b>compare_models.py</b> on your <b>meragedatacsv.csv</b></div>
    </div>""", unsafe_allow_html=True)

    csv_exists = os.path.isfile(CSV_PATH)
    st.markdown(f"""
    <div class="kpi-grid">
      <div class="kpi-card {'success' if csv_exists else 'critical'}">
        <div class="kpi-label">Dataset CSV</div>
        <div class="kpi-value" style="font-size:1.2rem">{"✅ Found" if csv_exists else "❌ Missing"}</div>
        <div class="kpi-sub">meragedatacsv.csv</div>
      </div>
      <div class="kpi-card info"><div class="kpi-label">Expected Samples</div><div class="kpi-value">19,133</div><div class="kpi-sub">PDFMalware2022 dataset</div></div>
      <div class="kpi-card info"><div class="kpi-label">Features</div><div class="kpi-value">31</div><div class="kpi-sub">PDF structural features</div></div>
      <div class="kpi-card info"><div class="kpi-label">Models</div><div class="kpi-value">4</div><div class="kpi-sub">RF · DT · SVM · IsoForest</div></div>
    </div>""", unsafe_allow_html=True)

    if not csv_exists:
        st.error(f"meragedatacsv.csv not found at: {CSV_PATH}")
        st.stop()

    if st.button("🚀 Train Models on meragedatacsv.csv", disabled=not csv_exists):
        pb   = st.progress(0)
        stat = st.empty()
        logs = []
        log_box = st.empty()

        def cb(msg, step):
            pb.progress(min(100, int(step / 10 * 100)))
            stat.markdown(f"**{msg}**")
            logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            log_box.code("\n".join(logs[-8:]), language=None)

        try:
            metrics = train_from_csv(CSV_PATH, cb)
            pb.progress(100); stat.empty(); log_box.empty()
            load_models.clear()
            st.success("✅ Training complete! Models saved to models/")

            best = metrics.get("best_model","?")
            st.markdown('<div class="panel"><div class="panel-title">📊 Model Performance on Test Set</div>', unsafe_allow_html=True)
            rows = ""
            for name in ["RandomForest","DecisionTree","SVM"]:
                r = metrics.get(name,{})
                is_best = name == best
                clr = "#00d4aa" if is_best else "#a0aec0"
                rows += f"<tr><td style='color:{clr};font-weight:{'700' if is_best else '400'}'>{name} {'⭐' if is_best else ''}</td><td style='color:#00d4aa'>{r.get('accuracy','?')}%</td><td style='color:#4d9fff'>{r.get('precision','?')}%</td><td style='color:#ffc300'>{r.get('recall','?')}%</td><td>{r.get('f1','?')}%</td></tr>"
            ds = metrics.get("dataset_info",{})
            st.markdown(f'<table class="dash-table"><tr><th>Model</th><th>Accuracy</th><th>Precision</th><th>Recall</th><th>F1</th></tr>{rows}</table><div style="margin-top:12px;font-size:.75rem;color:#5a7a9a">Dataset: {ds.get("total_samples","?")} samples | {ds.get("malicious","?")} malicious | {ds.get("benign","?")} benign | {ds.get("feature_count","?")} features</div>', unsafe_allow_html=True)
            st.markdown('</div>', unsafe_allow_html=True)
        except Exception as e:
            st.error(f"Training failed: {e}")

    existing = load_metrics()
    if existing:
        best = existing.get("best_model","")
        st.markdown('<div class="panel" style="margin-top:16px"><div class="panel-title">📈 Current Saved Model Performance</div>', unsafe_allow_html=True)
        for name, r in existing.items():
            if name in ("best_model","dataset_info","IsolationForest") or not isinstance(r, dict) or "accuracy" not in r: continue
            is_best = name == best
            clr = "#00d4aa" if is_best else "#a0aec0"
            st.markdown(f'<div class="model-row"><span style="color:{clr};font-weight:{"700" if is_best else "400"}">{name} {"⭐" if is_best else ""}</span><span>Acc: {r["accuracy"]}%</span><span>Pre: {r["precision"]}%</span><span>Rec: {r["recall"]}%</span><span>F1: {r["f1"]}%</span></div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="panel"><div class="panel-title">ℹ️ What happens when you click Train</div>', unsafe_allow_html=True)
    st.markdown("""
    1. **`dataset_loader.load_and_preprocess()`** — loads `meragedatacsv.csv`, encodes text/header columns
    2. **`compare_models.stratified_split()`** — 80/20 stratified train/test split
    3. Trains **Random Forest**, **Decision Tree**, **SVM** (supervised) + **Isolation Forest** (unsupervised)
    4. Saves `.pkl` model files to `models/` folder
    5. Saves `models/metrics.json` with accuracy/precision/recall/F1
    """, unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: THREAT INTEL
# ─────────────────────────────────────────────────────────────────────────────

elif page == "threat_intel":
    st.markdown("""
    <div style="margin-bottom:28px">
      <div style="font-size:1.6rem;font-weight:700;background:linear-gradient(135deg,#fff,#4d9fff);-webkit-background-clip:text;background-clip:text;color:transparent">🌐 Threat Intelligence</div>
      <div style="color:#8ba0c0;margin-top:6px">MalwareBazaar (free) · VirusTotal (free API key)</div>
    </div>""", unsafe_allow_html=True)

    c1, c2 = st.columns([1.2,1])
    with c1:
        st.markdown('<div class="panel"><div class="panel-title">🔍 Manual Hash Lookup</div>', unsafe_allow_html=True)
        hash_input = st.text_input("SHA256 hash", placeholder="e.g. abc123def456...")
        col1, col2 = st.columns(2)
        if col1.button("Check MalwareBazaar"):
            if hash_input.strip():
                with st.spinner("Querying..."):
                    r = mb_check_hash(hash_input.strip())
                if r.get("found"):
                    st.error(f"⚠️ FOUND! Family: {r.get('malware_family','Unknown')}")
                else:
                    st.success("✅ Not found in MalwareBazaar")
            else:
                st.warning("Enter a hash first")
        if col2.button("Check VirusTotal"):
            if not st.session_state.vt_api_key:
                st.warning("Add VirusTotal API key in the sidebar")
            elif hash_input.strip():
                with st.spinner("Querying..."):
                    r = vt_check(hash_input.strip(), st.session_state.vt_api_key)
                if r.get("found"):
                    st.error(f"⚠️ {r['malicious']}/{r['total_engines']} engines detected")
                elif r.get("error"):
                    st.warning(r["error"])
                else:
                    st.success("✅ Not found in VirusTotal")
        st.markdown('</div>', unsafe_allow_html=True)

        st.markdown('<div class="panel"><div class="panel-title">🔑 API Keys</div>', unsafe_allow_html=True)
        st.markdown("""
        <table class="dash-table">
          <tr><th>Service</th><th>Free?</th><th>Key?</th></tr>
          <tr><td>MalwareBazaar</td><td style="color:#00d4aa">✅ Free</td><td>❌ Not needed</td></tr>
          <tr><td>VirusTotal</td><td style="color:#00d4aa">✅ Free tier</td><td style="color:#ffc300">⚠️ Required</td></tr>
        </table>
        <div style="margin-top:12px;font-size:.75rem">Get free VT key: <a href="https://www.virustotal.com/gui/join-us" target="_blank" style="color:#4d9fff">virustotal.com/gui/join-us</a></div>
        """, unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="panel"><div class="panel-title">🦠 Live PDF Malware Feed</div>', unsafe_allow_html=True)
        if st.button("🔄 Refresh Feed"):
            mb_recent_feed.clear()
            st.rerun()
        feed = mb_recent_feed()
        if feed:
            for s in feed:
                tags = ", ".join(s.get("tags",[])[:3]) or "pdf"
                st.markdown(f'<div class="alert-row crit"><div><div style="font-weight:600">{s["family"]}</div><div style="font-size:.7rem;color:#5a7a9a">{s["date"]} · {s.get("reporter","?")} · {tags}</div></div><span class="alert-badge badge-crit">PDF</span></div>', unsafe_allow_html=True)
        else:
            st.markdown('<div style="color:#5a7a9a">Feed unavailable</div>', unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: HISTORY
# ─────────────────────────────────────────────────────────────────────────────

elif page == "history":
    st.markdown('<div style="font-size:1.6rem;font-weight:700;background:linear-gradient(135deg,#fff,#4d9fff);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:28px">📋 Scan History</div>', unsafe_allow_html=True)
    hist = st.session_state.scan_history
    if not hist:
        st.markdown('<div style="text-align:center;padding:60px;color:#5a7a9a">No scans yet. Go to Scan PDF to begin.</div>', unsafe_allow_html=True)
    else:
        if st.button("🗑️ Clear History"):
            st.session_state.scan_history = []
            st.rerun()
        rows = ""
        for i, h in enumerate(reversed(hist), 1):
            v  = h.get("verdict","?")
            bc = {"MALICIOUS":"badge-crit","SUSPICIOUS":"badge-med","BENIGN":"badge-clean"}.get(v,"badge-low")
            rows += f"<tr><td>{i}</td><td>{h.get('filename','?')}</td><td><span class='alert-badge {bc}'>{v}</span></td><td style='color:#ffc300'>{h.get('confidence','?')}%</td><td style='color:#ff4d6d'>{len(h.get('indicators',[]))}</td><td style='color:#00d4aa'>{h.get('removed',0)}</td><td style='color:#5a7a9a'>{h.get('timestamp','')}</td></tr>"
        st.markdown(f'<div class="panel"><table class="dash-table"><tr><th>#</th><th>File</th><th>Verdict</th><th>Confidence</th><th>Indicators</th><th>Removed</th><th>Time</th></tr>{rows}</table></div>', unsafe_allow_html=True)


# ─────────────────────────────────────────────────────────────────────────────
# PAGE: SETTINGS
# ─────────────────────────────────────────────────────────────────────────────

elif page == "settings":
    st.markdown('<div style="font-size:1.6rem;font-weight:700;background:linear-gradient(135deg,#fff,#4d9fff);-webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:28px">⚙️ Settings</div>', unsafe_allow_html=True)

    st.markdown('<div class="panel"><div class="panel-title">🔑 API Keys</div>', unsafe_allow_html=True)
    new_vt = st.text_input("VirusTotal API Key", value=st.session_state.vt_api_key,
                            type="password", placeholder="Get free key at virustotal.com/gui/join-us")
    if st.button("💾 Save"):
        st.session_state.vt_api_key = new_vt
        st.success("Saved!")
    st.markdown('</div>', unsafe_allow_html=True)

    m = load_metrics()
    st.markdown('<div class="panel"><div class="panel-title">ℹ️ System Info</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <table class="dash-table">
      <tr><th>Component</th><th>Status</th><th>Details</th></tr>
      <tr><td>meragedatacsv.csv</td><td style="color:{'#00d4aa' if os.path.isfile(CSV_PATH) else '#ff4d6d'}">{"✅ Found" if os.path.isfile(CSV_PATH) else "❌ Missing"}</td><td>{CSV_PATH}</td></tr>
      <tr><td>Trained Models</td><td style="color:{'#00d4aa' if m else '#ffc300'}">{"✅ Ready" if m else "⚠️ Not trained"}</td><td>{"Best: " + m.get("best_model","?") if m else "Run Model Training first"}</td></tr>
      <tr><td>feature_extractor.py</td><td style="color:#00d4aa">✅ Loaded</td><td>extract_features(), FEATURE_COLUMNS</td></tr>
      <tr><td>remediate.py</td><td style="color:#00d4aa">✅ Loaded</td><td>remediate(), prescan(), build_report()</td></tr>
      <tr><td>dataset_loader.py</td><td style="color:#00d4aa">✅ Loaded</td><td>load_and_preprocess()</td></tr>
      <tr><td>compare_models.py</td><td style="color:#00d4aa">✅ Loaded</td><td>stratified_split()</td></tr>
      <tr><td>forensic_report.py</td><td style="color:#4d9fff">ℹ️ Lazy loaded</td><td>generate_report() — on demand in Scan tab</td></tr>
      <tr><td>VirusTotal</td><td style="color:{'#00d4aa' if st.session_state.vt_api_key else '#ffc300'}">{"✅ Key set" if st.session_state.vt_api_key else "⚠️ No key"}</td><td>Free tier: 4 req/min</td></tr>
    </table>""", unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

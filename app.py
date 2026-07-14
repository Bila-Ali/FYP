#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║   PDF MALWARE DETECTION SUITE — Integrated GUI (Streamlit)                  ║
║   An Integrated AI System for Detection, Remediation, and Forensic Analysis ║
║   of PDF-Based Malware  ·  MUET BS Cyber Security FYP                       ║
╚══════════════════════════════════════════════════════════════════════════════╝

Phase I  (COMPLETED):  Dataset prep · Feature extraction · ML training · SHAP
Phase II (THIS GUI):   Detection · CDR Remediation · Forensic Analysis · Reports

Run:  streamlit run app.py
"""

import os, sys, json, time, shutil, tempfile, hashlib, math
import re as _re
import traceback as _traceback
from pathlib import Path
from datetime import datetime, timezone

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots

# ── Ensure project root is importable ─────────────────────────────────────────
HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

# ── Page config (MUST be first Streamlit call) ─────────────────────────────────
st.set_page_config(
    page_title="PDF Malware Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM CSS — Dark cyber theme, readable, distinctive
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
/* ══════════════════════════════════════════════════════════════════════
   DESIGN TOKENS — Apple HIG–inspired palette, spacing, and typography
   ══════════════════════════════════════════════════════════════════════ */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

:root {
    --bg:            #F5F5F7;
    --card:          #FFFFFF;
    --text:          #1D1D1F;
    --text-secondary:#6E6E73;
    --border:        #D2D2D7;
    --accent:        #0071E3;
    --accent-hover:  #0062CC;
    --success:       #34C759;
    --warning:       #FF9F0A;
    --danger:        #FF3B30;
    --medium:        #FFCC00;

    --radius-lg: 20px;
    --radius-md: 14px;
    --radius-sm: 10px;
    --shadow-soft:  0 10px 40px rgba(0,0,0,0.08);
    --shadow-lift:  0 16px 48px rgba(0,0,0,0.12);
    --mono: 'SF Mono', 'SFMono-Regular', ui-monospace, Menlo, Consolas, monospace;
    --sans: 'Inter', -apple-system, BlinkMacSystemFont, 'SF Pro Display', 'SF Pro Text',
            'Segoe UI', 'Helvetica Neue', sans-serif;
}

/* ══════════════════════════════════════════════════════════════════════
   BASE
   ══════════════════════════════════════════════════════════════════════ */
html, body, [class*="css"] {
    font-family: var(--sans);
}

.stApp {
    background: var(--bg);
    color: var(--text);
}

/* Tighten Streamlit's default block spacing for a calmer, airier layout */
.block-container {
    padding-top: 1.25rem;
    padding-bottom: 3rem;
    max-width: 1200px;
}

/* ══════════════════════════════════════════════════════════════════════
   REMOVE ALL NATIVE STREAMLIT CHROME — this is a standalone application,
   not "a Streamlit app". No header bar, toolbar, deploy button, hamburger
   menu, or "Made with Streamlit" footer should ever be visible.
   ══════════════════════════════════════════════════════════════════════ */
[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
[data-testid="stAppDeployButton"],
#MainMenu,
header[data-testid="stHeader"],
footer,
footer[class],
.stAppDeployButton,
div[data-testid="stAppDeployButton"] {
    display: none !important;
    visibility: hidden !important;
    height: 0 !important;
    width: 0 !important;
    margin: 0 !important;
    padding: 0 !important;
}

.stApp > header {
    display: none !important;
}

.main .block-container {
    padding-top: 1.25rem !important;
}

/* Remove the top-level app padding Streamlit reserves for its header */
[data-testid="stAppViewContainer"] > .main {
    padding-top: 0 !important;
}

h1, h2, h3, h4, h5, h6 { color: var(--text); letter-spacing: -0.02em; }
p, span, div { color: var(--text); }

/* ══════════════════════════════════════════════════════════════════════
   SIDEBAR
   ══════════════════════════════════════════════════════════════════════ */
[data-testid="stSidebar"] {
    background: #FBFBFD;
    border-right: 1px solid var(--border);
}

[data-testid="stSidebar"] .stMarkdown h3 {
    color: var(--text-secondary);
    font-size: 0.72rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    font-weight: 600;
    margin-top: 1.4rem;
    margin-bottom: 0.5rem;
}

[data-testid="stSidebar"] [data-testid="stWidgetLabel"] p {
    color: var(--text-secondary);
    font-size: 0.82rem;
    font-weight: 500;
}

/* ══════════════════════════════════════════════════════════════════════
   MAIN HEADER
   ══════════════════════════════════════════════════════════════════════ */
.main-header {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 2rem 2.5rem;
    margin-bottom: 1.75rem;
    display: flex;
    align-items: center;
    gap: 1.25rem;
    box-shadow: var(--shadow-soft);
    animation: fadeSlideUp 0.35s ease;
}

.main-header h1 {
    color: var(--text);
    font-size: 1.9rem;
    font-weight: 700;
    margin: 0;
    letter-spacing: -0.02em;
}

.main-header p {
    color: var(--text-secondary);
    margin: 0.3rem 0 0 0;
    font-size: 0.95rem;
}

/* ══════════════════════════════════════════════════════════════════════
   CARDS
   ══════════════════════════════════════════════════════════════════════ */
.card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-lg);
    padding: 2rem;
    margin-bottom: 1.5rem;
    box-shadow: var(--shadow-soft);
    transition: box-shadow 0.25s ease, transform 0.25s ease;
    animation: fadeSlideUp 0.35s ease;
}

.card:hover {
    box-shadow: var(--shadow-lift);
}

.card-title {
    color: var(--text);
    font-size: 1.05rem;
    letter-spacing: -0.01em;
    text-transform: none;
    font-weight: 600;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

/* ══════════════════════════════════════════════════════════════════════
   VERDICT BADGES
   ══════════════════════════════════════════════════════════════════════ */
.verdict-malicious {
    background: #FFF4F3;
    border: 1px solid rgba(255,59,48,0.35);
    border-radius: var(--radius-lg);
    padding: 1.75rem;
    text-align: center;
    box-shadow: var(--shadow-soft);
}

.verdict-benign {
    background: #F0FBF3;
    border: 1px solid rgba(52,199,89,0.35);
    border-radius: var(--radius-lg);
    padding: 1.75rem;
    text-align: center;
    box-shadow: var(--shadow-soft);
}

.verdict-label {
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: 0.01em;
}

.verdict-sub {
    font-size: 0.88rem;
    margin-top: 0.5rem;
    color: var(--text-secondary);
    opacity: 1;
}

/* ══════════════════════════════════════════════════════════════════════
   METRIC BOXES
   ══════════════════════════════════════════════════════════════════════ */
.metric-box {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 1.25rem 1rem;
    text-align: center;
    transition: box-shadow 0.25s ease, transform 0.25s ease;
}

.metric-box:hover {
    box-shadow: var(--shadow-soft);
    transform: translateY(-2px);
}

.metric-value {
    font-size: 1.7rem;
    font-weight: 700;
    font-family: var(--mono);
    color: var(--accent);
}

.metric-label {
    font-size: 0.72rem;
    color: var(--text-secondary);
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 0.3rem;
}

/* ══════════════════════════════════════════════════════════════════════
   RISK BADGES
   ══════════════════════════════════════════════════════════════════════ */
.risk-critical { color: var(--danger);  font-weight: 700; }
.risk-high     { color: var(--warning); font-weight: 700; }
.risk-medium   { color: #B58900;        font-weight: 700; }
.risk-low      { color: var(--success); font-weight: 700; }

/* ══════════════════════════════════════════════════════════════════════
   MITRE ATT&CK TABLE
   ══════════════════════════════════════════════════════════════════════ */
.mitre-row {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.85rem 1.1rem;
    margin-bottom: 0.6rem;
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    box-shadow: var(--shadow-soft);
}

.mitre-id {
    background: rgba(0,113,227,0.08);
    color: var(--accent);
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 0.2rem 0.55rem;
    border-radius: 6px;
    white-space: nowrap;
    font-weight: 600;
    border: 1px solid rgba(0,113,227,0.22);
}

/* ══════════════════════════════════════════════════════════════════════
   FEATURE IMPORTANCE BARS
   ══════════════════════════════════════════════════════════════════════ */
.feat-bar-wrap {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    margin-bottom: 0.45rem;
}
.feat-label { font-size: 0.78rem; color: var(--text-secondary); width: 140px; flex-shrink: 0; font-family: var(--mono); }
.feat-bar-bg { flex: 1; background: #ECECEE; border-radius: 6px; height: 10px; overflow: hidden; }
.feat-bar-fill { height: 100%; border-radius: 6px; transition: width 0.4s ease; }
.feat-val { font-size: 0.75rem; color: var(--text-secondary); width: 35px; text-align: right; font-family: var(--mono); }

/* ══════════════════════════════════════════════════════════════════════
   IOC CHIPS
   ══════════════════════════════════════════════════════════════════════ */
.ioc-chip {
    display: inline-block;
    background: #FFF4F3;
    border: 1px solid rgba(255,59,48,0.25);
    color: #C81E1E;
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 0.25rem 0.6rem;
    border-radius: 8px;
    margin: 0.15rem;
    word-break: break-all;
}

/* ══════════════════════════════════════════════════════════════════════
   YARA MATCH
   ══════════════════════════════════════════════════════════════════════ */
.yara-match {
    background: #FFFBF3;
    border-left: 3px solid var(--warning);
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
    padding: 0.75rem 1.1rem;
    margin-bottom: 0.5rem;
}

.yara-rule {
    color: #B36B00;
    font-family: var(--mono);
    font-size: 0.8rem;
    font-weight: 600;
}

/* ══════════════════════════════════════════════════════════════════════
   CDR REPORT
   ══════════════════════════════════════════════════════════════════════ */
.cdr-removed {
    background: #FFF4F3;
    border: 1px solid rgba(255,59,48,0.2);
    border-radius: var(--radius-sm);
    padding: 0.6rem 0.85rem;
    margin-bottom: 0.35rem;
    font-size: 0.78rem;
    font-family: var(--mono);
    color: #C81E1E;
}

.cdr-kept {
    background: #F0FBF3;
    border: 1px solid rgba(52,199,89,0.2);
    border-radius: var(--radius-sm);
    padding: 0.6rem 0.85rem;
    margin-bottom: 0.35rem;
    font-size: 0.78rem;
    color: #1E7F3C;
}

/* ══════════════════════════════════════════════════════════════════════
   PHASE BADGES
   ══════════════════════════════════════════════════════════════════════ */
.phase-badge {
    display: inline-block;
    background: rgba(0,113,227,0.08);
    border: 1px solid rgba(0,113,227,0.25);
    color: var(--accent);
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    padding: 0.2rem 0.55rem;
    border-radius: 6px;
    margin-left: 0.5rem;
}

/* ══════════════════════════════════════════════════════════════════════
   FILE UPLOADER — premium drag & drop
   ══════════════════════════════════════════════════════════════════════ */
[data-testid="stFileUploader"] {
    background: var(--card) !important;
}

[data-testid="stFileUploaderDropzone"] {
    background: #FAFAFC !important;
    border: 2px dashed var(--border) !important;
    border-radius: var(--radius-lg) !important;
    padding: 1.75rem !important;
    transition: border-color 0.25s ease, background 0.25s ease;
}

[data-testid="stFileUploaderDropzone"]:hover {
    border-color: var(--accent) !important;
    background: #F2F8FF !important;
}

[data-testid="stFileUploaderDropzoneInstructions"] div,
[data-testid="stFileUploaderDropzoneInstructions"] span {
    color: var(--text-secondary) !important;
}

[data-testid="stFileUploader"] section button {
    background: var(--card);
    color: var(--accent);
    border: 1px solid var(--border);
    border-radius: 999px;
    font-weight: 500;
    transition: all 0.25s ease;
}

[data-testid="stFileUploader"] section button:hover {
    border-color: var(--accent);
    background: #F2F8FF;
}

/* ══════════════════════════════════════════════════════════════════════
   BUTTONS
   ══════════════════════════════════════════════════════════════════════ */
.stButton > button {
    background: var(--accent);
    color: #FFFFFF;
    border: none;
    border-radius: 980px;
    height: 48px;
    font-weight: 500;
    letter-spacing: 0;
    box-shadow: 0 2px 8px rgba(0,113,227,0.25);
    transition: all 0.25s ease;
}

.stButton > button:hover {
    background: var(--accent-hover);
    transform: translateY(-1px);
    box-shadow: 0 6px 18px rgba(0,113,227,0.3);
}

.stButton > button:active {
    transform: translateY(0);
}

.stButton > button p { color: #FFFFFF; font-weight: 500; }

/* Download buttons — secondary style (white, bordered) */
.stDownloadButton > button {
    background: var(--card);
    color: var(--accent);
    border: 1px solid var(--border);
    border-radius: 980px;
    height: 48px;
    font-weight: 500;
    transition: all 0.25s ease;
}

.stDownloadButton > button:hover {
    border-color: var(--accent);
    background: #F2F8FF;
    transform: translateY(-1px);
    box-shadow: var(--shadow-soft);
}

/* ══════════════════════════════════════════════════════════════════════
   TABS
   ══════════════════════════════════════════════════════════════════════ */
.stTabs [data-baseweb="tab-list"] {
    gap: 0.25rem;
    border-bottom: 1px solid var(--border);
}

.stTabs [data-baseweb="tab"] {
    color: var(--text-secondary);
    font-weight: 500;
    font-size: 0.9rem;
}

.stTabs [data-baseweb="tab"][aria-selected="true"] {
    color: var(--accent);
    border-bottom-color: var(--accent) !important;
}

/* ══════════════════════════════════════════════════════════════════════
   INPUTS — text, slider, checkbox, radio
   ══════════════════════════════════════════════════════════════════════ */
.stTextInput input, .stNumberInput input {
    background: var(--card);
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    height: 48px;
    color: var(--text);
    transition: border-color 0.2s ease, box-shadow 0.2s ease;
}

.stTextInput input:focus, .stNumberInput input:focus {
    border-color: var(--accent) !important;
    box-shadow: 0 0 0 3px rgba(0,113,227,0.15) !important;
}

.stSlider [data-baseweb="slider"] div[role="slider"] {
    background-color: var(--accent) !important;
}

[data-testid="stTickBarMin"], [data-testid="stTickBarMax"] {
    color: var(--text-secondary);
}

.stCheckbox label p, .stRadio label p { color: var(--text); font-size: 0.9rem; }

/* ══════════════════════════════════════════════════════════════════════
   SIDEBAR NAVIGATION — Apple-style rounded pills
   ══════════════════════════════════════════════════════════════════════ */
[data-testid="stSidebar"] .stRadio [role="radiogroup"] {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
}

[data-testid="stSidebar"] .stRadio [role="radiogroup"] label {
    border-radius: 12px;
    padding: 0.65rem 0.85rem;
    margin: 0;
    transition: background 0.2s ease, transform 0.15s ease;
    cursor: pointer;
}

[data-testid="stSidebar"] .stRadio [role="radiogroup"] label p {
    font-size: 0.9rem;
    font-weight: 500;
    color: var(--text);
}

[data-testid="stSidebar"] .stRadio [role="radiogroup"] label:hover {
    background: rgba(0,113,227,0.07);
    transform: translateX(2px);
}

[data-testid="stSidebar"] .stRadio [role="radiogroup"] label:has(input:checked) {
    background: var(--accent);
    box-shadow: 0 4px 14px rgba(0,113,227,0.3);
}

[data-testid="stSidebar"] .stRadio [role="radiogroup"] label:has(input:checked) p {
    color: #FFFFFF;
    font-weight: 600;
}

/* Hide the default radio circle for a cleaner pill look */
[data-testid="stSidebar"] .stRadio [role="radiogroup"] label > div:first-child {
    display: none;
}

.stRadio [role="radiogroup"] label {
    border-radius: var(--radius-sm);
    padding: 0.35rem 0.5rem;
    transition: background 0.2s ease;
}

.stRadio [role="radiogroup"] label:hover { background: rgba(0,113,227,0.06); }

/* ══════════════════════════════════════════════════════════════════════
   EXPANDER
   ══════════════════════════════════════════════════════════════════════ */
[data-testid="stExpander"] {
    background: var(--card);
    border: 1px solid var(--border) !important;
    border-radius: var(--radius-md) !important;
    box-shadow: var(--shadow-soft);
    overflow: hidden;
}

[data-testid="stExpander"] summary {
    font-weight: 500;
    color: var(--text);
}

/* ══════════════════════════════════════════════════════════════════════
   ALERTS (info / warning / error / success)
   ══════════════════════════════════════════════════════════════════════ */
[data-testid="stAlert"] {
    border-radius: var(--radius-md) !important;
    border: 1px solid var(--border);
    box-shadow: var(--shadow-soft);
}

/* ══════════════════════════════════════════════════════════════════════
   DATAFRAME / TABLES
   ══════════════════════════════════════════════════════════════════════ */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    overflow: hidden;
    box-shadow: var(--shadow-soft);
}

table {
    border-collapse: collapse;
    width: 100%;
}

table th {
    background: #FAFAFC;
    color: var(--text-secondary);
    font-size: 0.72rem;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    text-align: left;
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid var(--border);
}

table td {
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
}

table tr:nth-child(even) td { background: #FAFAFC; }
table tr:hover td { background: #F2F8FF; }

/* ══════════════════════════════════════════════════════════════════════
   PROGRESS BAR
   ══════════════════════════════════════════════════════════════════════ */
[data-testid="stProgress"] > div > div > div {
    background: linear-gradient(90deg, var(--accent), #34AAFF) !important;
    border-radius: 999px;
}
[data-testid="stProgress"] > div > div {
    background: #ECECEE !important;
    border-radius: 999px;
}

/* ══════════════════════════════════════════════════════════════════════
   DIVIDER
   ══════════════════════════════════════════════════════════════════════ */
hr { border-color: var(--border) !important; margin: 1.75rem 0 !important; }

/* ══════════════════════════════════════════════════════════════════════
   SCROLLBAR
   ══════════════════════════════════════════════════════════════════════ */
::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: #C7C7CC; border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: #AEAEB2; }

/* ══════════════════════════════════════════════════════════════════════
   ANIMATIONS — subtle, 200–350ms
   ══════════════════════════════════════════════════════════════════════ */
@keyframes fadeSlideUp {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
}
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════════════════
# LAZY IMPORTS — the real Phase-I pipeline modules, loaded once and cached.
# app.py is a GUI shell around the actual project files (not a duplicated
# reimplementation): extract_features.py / predict_pdf.py / pdf_forensic_v2.py
# / pdf_cdr_v4.py, exactly as described in README.md.
# ═══════════════════════════════════════════════════════════════════════════════

@st.cache_resource(show_spinner=False)
def _import_extractor():
    """extract_features.py — F1/F2/F3 + derived feature extraction."""
    try:
        import extract_features
        return extract_features
    except Exception:
        return None

@st.cache_resource(show_spinner=False)
def _import_predictor():
    """predict_pdf.py — reused for build_feature_vector(), which aligns a
    raw extracted-feature dict to the model's trained column order
    (including reconstructing one-hot dummies like f2_form_AcroForm)."""
    try:
        import predict_pdf
        return predict_pdf
    except Exception:
        return None

@st.cache_resource(show_spinner=False)
def _import_forensic():
    """pdf_forensic_v2.py — hashing, entropy, IOCs, YARA, MITRE ATT&CK
    mapping, risk scoring, and pikepdf-based forensic extraction."""
    try:
        import pdf_forensic_v2
        return pdf_forensic_v2
    except Exception:
        return None

@st.cache_resource(show_spinner=False)
def _import_cdr():
    """pdf_cdr_v4.py — pikepdf-based Content Disarm & Reconstruction."""
    try:
        import pdf_cdr_v4
        return pdf_cdr_v4
    except Exception:
        return None

@st.cache_resource(show_spinner=False)
def _import_ml():
    try:
        import joblib
        return joblib
    except ImportError:
        return None

@st.cache_resource(show_spinner=False)
def _load_model(model_path: str):
    """Loads the joblib bundle produced by train_final_model.py:
    {"model": <sklearn estimator>, "final_features": [...], "class_names": [...]}"""
    joblib = _import_ml()
    if joblib and Path(model_path).exists():
        return joblib.load(model_path)
    return None

@st.cache_resource(show_spinner=False)
def _load_features(feat_path: str):
    """Fallback reader for a plain-text/CSV feature list (e.g.
    artifacts/case3_final_features.txt), used only if a loaded model bundle
    doesn't already carry its own final_features list."""
    p = Path(feat_path)
    if not p.exists():
        return None
    if p.suffix == ".csv":
        df = pd.read_csv(p)
        col = df.columns[0] if len(df.columns) == 1 else "feature"
        return df[col].tolist()
    with open(p) as f:
        return [line.strip().lstrip("- ").strip() for line in f if line.strip()]


# ═══════════════════════════════════════════════════════════════════════════════
# ML DETECTION  — wraps extract_features.py + predict_pdf.py + the joblib
# model bundle produced by train_final_model.py, exactly as `predict_pdf.py`
# does on the command line.
# ═══════════════════════════════════════════════════════════════════════════════

def ml_detect(pdf_path: str, model_path: str, features_path: str,
              threshold: float = 0.5) -> dict:
    extract_mod = _import_extractor()
    predict_mod = _import_predictor()
    if extract_mod is None:
        return {"available": False, "error": "extract_features.py not found "
                                               "(and its tools/ subfolder — see README.md)"}
    if predict_mod is None:
        return {"available": False, "error": "predict_pdf.py not found"}

    bundle = _load_model(model_path)
    if not bundle:
        return {"available": False, "error": f"Model not found: {model_path}"}

    # The trained artifact is a bundle dict {"model", "final_features",
    # "class_names"} (see train_final_model.py / predict_pdf.py), not a bare
    # estimator — fall back to a separate features file only for older/plain
    # sklearn-model artifacts that don't carry their own feature list.
    if isinstance(bundle, dict) and "model" in bundle:
        model = bundle["model"]
        final_features = bundle.get("final_features") or _load_features(features_path)
        class_names = bundle.get("class_names", ["benign", "malicious"])
    else:
        model = bundle
        final_features = _load_features(features_path)
        class_names = ["benign", "malicious"]

    if not final_features:
        return {"available": False, "error": f"No feature list in model bundle or at {features_path}"}

    try:
        raw = extract_mod.process_file(pdf_path, label="unknown")
    except Exception as e:
        return {"available": False, "error": f"Feature extraction failed: {e}"}
    if raw is None:
        return {"available": False, "error": "Feature extraction failed"}

    x_dict = predict_mod.build_feature_vector(raw, final_features)
    X = np.array([[x_dict[f] for f in final_features]], dtype=float)
    proba = model.predict_proba(X)[0]

    mal_idx = class_names.index("malicious") if "malicious" in class_names else int(np.argmax(proba))
    ben_idx = class_names.index("benign") if "benign" in class_names else int(np.argmin(proba))
    p_mal = float(proba[mal_idx])
    p_ben = float(proba[ben_idx])
    label = "MALICIOUS" if p_mal >= threshold else "BENIGN"

    # Feature contributions (global RF importances weighted by this file's values)
    if hasattr(model, "feature_importances_"):
        imps = dict(zip(final_features, model.feature_importances_))
    else:
        imps = {}

    contributions = sorted([
        {"feature": f, "value": x_dict.get(f, 0), "importance": imps.get(f, 0)}
        for f in final_features
    ], key=lambda x: x["importance"] * abs(x["value"] if isinstance(x["value"], (int, float)) else 0),
       reverse=True)[:15]

    return {
        "available":              True,
        "label":                  label,
        "probability_malicious":  round(p_mal, 4),
        "probability_benign":     round(p_ben, 4),
        "confidence_pct":         round(max(p_mal, p_ben) * 100, 2),
        "model":                  type(model).__name__,
        "top_features":           contributions,
        "raw_features":           raw,
        "final_features":         final_features,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# FORENSIC ANALYSIS — delegates to pdf_forensic_v2.py's forensic_analyse_v2(),
# which owns hashing, entropy, IOC extraction, YARA matching, attack-type
# classification, and MITRE ATT&CK mapping. We hand it the ML verdict we
# already computed via ml_detect() (bundle-based) so it never has to fall
# back to its own older model-loading convention.
# ═══════════════════════════════════════════════════════════════════════════════

def forensic_analyse(pdf_bytes: bytes, pdf_path: str, ml_result: dict | None = None,
                      do_lookup: bool = False) -> dict:
    forensic_mod = _import_forensic()
    if forensic_mod is None:
        return {"error": "pdf_forensic_v2.py not found", "schema_version": "2.0"}

    precomputed = None
    if ml_result is not None:
        if ml_result.get("available"):
            precomputed = {
                "available":              True,
                "label":                   ml_result["label"],
                "probability_malicious":   ml_result["probability_malicious"],
                "probability_benign":      ml_result["probability_benign"],
                "confidence_pct":          ml_result["confidence_pct"],
                "threshold":               0.5,
                "model":                   ml_result.get("model", "RandomForestClassifier"),
            }
        else:
            precomputed = {"available": False, "reason": ml_result.get("error", "unavailable")}

    # Only pay for the expensive pikepdf script/object extraction step when
    # the ML model already flagged the file malicious (mirrors
    # detect_and_analyze()'s decision rule in pdf_forensic_v2.py).
    deep_extraction = bool(precomputed and precomputed.get("label") == "MALICIOUS")

    try:
        report = forensic_mod.forensic_analyse_v2(
            pdf_path,
            do_lookup=do_lookup,
            precomputed_ml_verdict=precomputed,
            deep_extraction=deep_extraction,
        )
    except Exception as e:
        return {"error": f"Forensic analysis failed: {e}", "schema_version": "2.0"}

    if "error" in report:
        return report

    # Back-compat aliases: the Plotly/UI helpers below (structural_radar,
    # metric tiles) were written against the older flat key names. Add them
    # alongside pdf_forensic_v2's own (richer) structural_counts rather than
    # renaming its output.
    sc = report["structural_counts"]
    sc.setdefault("/JavaScript", sc.get("/JS+/JavaScript", 0))
    sc.setdefault("/JS", 0)
    sc["%%EOF"] = sc.get("eof_markers", 0)
    sc["/URI"] = len(_re.findall(rb"/URI", pdf_bytes))
    sc["/Font"] = len(_re.findall(rb"/Font", pdf_bytes))
    sc["stream"] = sc.get("streams", 0)
    sc["obj"] = sc.get("obj", 0)

    # Back-compat aliases for YARA matches: pdf_forensic_v2.run_yara() returns
    # {"rule","tags","meta":{"severity","attack_type","mitre_technique",...},"strings"}
    # but the UI (YARA tab, forensic-detail expander, HTML report) expects
    # flat "severity"/"technique"/"attack_type" keys directly on each match.
    for m in report.get("yara_matches", []):
        meta = m.get("meta", {}) or {}
        m.setdefault("severity", meta.get("severity", "MEDIUM"))
        m.setdefault("technique", meta.get("mitre_technique", "—"))
        m.setdefault("attack_type", meta.get("attack_type", "unknown"))

    return report


# ═══════════════════════════════════════════════════════════════════════════════
# CDR — delegates to pdf_cdr_v4.py's pikepdf-based disarm_and_reconstruct()
# (Table 2 of the paper: metadata, links, JavaScript, embedded files,
# multimedia, XFA, AcroForm, annotations, triggers/actions, functions).
# ═══════════════════════════════════════════════════════════════════════════════

def cdr_disarm(pdf_bytes: bytes, pdf_path: str | None = None) -> dict:
    """Runs the real CDR engine and returns a report shaped to stay
    compatible with the existing metric tiles (objects_total/removed/kept,
    size_reduction_pct, original/cleaned size), plus per-category removed
    counts for the detail panel."""
    cdr_mod = _import_cdr()
    if cdr_mod is None:
        return {"error": "pdf_cdr_v4.py not found (or pikepdf not installed)"}

    try:
        # pikepdf can open raw bytes directly (via an in-memory buffer) --
        # no need to write our own scratch file to disk at all. This also
        # sidesteps a Windows-only "OSError: [Errno 22] Invalid argument"
        # that came from round-tripping the reconstructed PDF through a
        # second temp file while the source file was still held open.
        log, clean_bytes = cdr_mod.disarm_and_reconstruct(pdf_bytes, output_path=None)
        renderable, render_detail = cdr_mod.check_renderable(clean_bytes)
    except Exception as e:
        return {"error": f"{e}", "traceback": _traceback.format_exc()}

    found_categories   = {k: v for k, v in log["found"].items()   if v}
    removed_categories = {k: v for k, v in log["removed"].items() if v}
    objects_removed = sum(removed_categories.values())
    objects_total   = sum(found_categories.values()) or objects_removed

    report = {
        "original_size_bytes": len(pdf_bytes),
        "cleaned_size_bytes":  len(clean_bytes),
        "objects_total":       objects_total,
        "objects_removed":     objects_removed,
        "objects_kept":        max(objects_total - objects_removed, 0),
        "removed_by_category": removed_categories,
        "found_by_category":   found_categories,
        "warnings":            log["warnings"],
        "errors":              log["errors"],
        "renderable":          renderable,
        "render_detail":       render_detail,
        "size_reduction_pct":  round(
            100 * (1 - len(clean_bytes) / len(pdf_bytes)) if pdf_bytes else 0, 1
        ),
    }
    return {
        "clean_bytes":          clean_bytes,
        "removed_by_category":  removed_categories,
        "found_by_category":    found_categories,
        "report":               report,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PLOTLY CHARTS
# ═══════════════════════════════════════════════════════════════════════════════

CHART_BG   = "rgba(0,0,0,0)"
CHART_FONT = dict(family="Inter, sans-serif", color="#6E6E73", size=12)
GRID_COLOR = "rgba(210,210,215,0.5)"

def _base_layout(**kwargs):
    return dict(
        paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG,
        font=CHART_FONT, margin=dict(l=10,r=10,t=30,b=10),
        **kwargs
    )

def gauge_chart(value: float, label: str, color: str) -> go.Figure:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value*100,
        title=dict(text=label, font=dict(color="#6E6E73", size=13)),
        number=dict(suffix="%", font=dict(color=color, size=28, family="SF Mono, monospace")),
        gauge=dict(
            axis=dict(range=[0,100], tickwidth=1, tickcolor="#D2D2D7",
                      tickfont=dict(color="#6E6E73", size=10)),
            bar=dict(color=color, thickness=0.25),
            bgcolor="rgba(245,245,247,0.8)",
            borderwidth=1, bordercolor="#D2D2D7",
            steps=[
                dict(range=[0,50],  color="rgba(52,199,89,0.08)"),
                dict(range=[50,75], color="rgba(255,204,0,0.08)"),
                dict(range=[75,100],color="rgba(255,59,48,0.08)"),
            ],
            threshold=dict(line=dict(color=color, width=2), thickness=0.7, value=value*100),
        )
    ))
    fig.update_layout(**_base_layout(height=200))
    return fig

def feature_importance_chart(top_features: list) -> go.Figure:
    if not top_features: return go.Figure()
    feats = [f["feature"] for f in reversed(top_features[:12])]
    vals  = [f["importance"]*100 for f in reversed(top_features[:12])]
    colors = ["#FF3B30" if v > 5 else "#FF9F0A" if v > 2 else "#0071E3" for v in vals]
    fig = go.Figure(go.Bar(
        x=vals, y=feats, orientation="h",
        marker=dict(color=colors, line=dict(width=0)),
        text=[f"{v:.2f}%" for v in vals], textfont=dict(size=10, color="#6E6E73"),
        textposition="outside",
    ))
    fig.update_layout(**_base_layout(
        height=340,
        xaxis=dict(title="Importance (%)", gridcolor=GRID_COLOR, showgrid=True,
                   tickfont=dict(color="#6E6E73", size=10)),
        yaxis=dict(tickfont=dict(color="#6E6E73", size=10, family="SF Mono, monospace")),
    ))
    return fig

def entropy_bar_chart(value: float) -> go.Figure:
    fig = go.Figure(go.Bar(
        x=[value], y=["Entropy"],
        orientation="h",
        marker=dict(
            color="#FF3B30" if value > 7 else "#FF9F0A" if value > 6 else "#0071E3",
            line=dict(width=0),
        ),
        text=[f"{value:.3f} bits/byte"], textposition="outside",
        textfont=dict(color="#6E6E73"),
    ))
    fig.add_vline(x=7.0, line_dash="dash", line_color="#6E6E73", annotation_text="High")
    fig.update_layout(**_base_layout(
        height=110,
        xaxis=dict(range=[0,8.5], gridcolor=GRID_COLOR, tickfont=dict(color="#6E6E73")),
        yaxis=dict(tickfont=dict(color="#6E6E73")),
    ))
    return fig

def structural_radar(structural: dict) -> go.Figure:
    cats = ["JavaScript", "OpenAction", "Launch", "EmbeddedFile", "XFA", "URIs", "Objects", "EOF"]
    vals = [
        min(structural.get("/JavaScript",0) + structural.get("/JS",0), 10),
        min(structural.get("/OpenAction",0), 5),
        min(structural.get("/Launch",0), 5),
        min(structural.get("/EmbeddedFile",0), 5),
        min(structural.get("/XFA",0), 5),
        min(structural.get("/URI",0), 10),
        min(structural.get("obj",0)//10, 10),
        min(structural.get("%%EOF",0), 5),
    ]
    fig = go.Figure(go.Scatterpolar(
        r=vals, theta=cats, fill="toself",
        fillcolor="rgba(255,59,48,0.15)",
        line=dict(color="#FF3B30", width=2),
        marker=dict(color="#FF3B30"),
    ))
    fig.update_layout(**_base_layout(
        height=280,
        polar=dict(
            radialaxis=dict(visible=True, range=[0,10],
                           tickfont=dict(color="#6E6E73", size=9),
                           gridcolor=GRID_COLOR, linecolor=GRID_COLOR),
            angularaxis=dict(tickfont=dict(color="#6E6E73", size=11),
                             linecolor=GRID_COLOR, gridcolor=GRID_COLOR),
            bgcolor="rgba(245,245,247,0.5)",
        ),
    ))
    return fig

def risk_score_gauge(score: int, label: str) -> go.Figure:
    color = "#FF3B30" if label == "CRITICAL" else \
            "#FF9F0A" if label == "HIGH" else \
            "#FFCC00" if label == "MEDIUM" else "#34C759"
    return gauge_chart(score/100, f"Risk Score · {label}", color)


# ═══════════════════════════════════════════════════════════════════════════════
# UI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def html(content: str):
    st.markdown(content, unsafe_allow_html=True)

def card(title: str, icon: str = ""):
    html(f'<div class="card"><div class="card-title">{icon} {title}</div>')

def end_card():
    html("</div>")

def verdict_box(label: str, prob: float, model_name: str):
    cls = "verdict-malicious" if label == "MALICIOUS" else "verdict-benign"
    icon = "⚠️" if label == "MALICIOUS" else "✅"
    color = "#FF3B30" if label == "MALICIOUS" else "#34C759"
    html(f"""
    <div class="{cls}">
        <div class="verdict-label" style="color:{color}">{icon} {label}</div>
        <div class="verdict-sub">P(malicious) = {prob:.4f} · {model_name}</div>
    </div>""")

def metric_row(metrics: list[tuple]):
    cols = st.columns(len(metrics))
    for col, (val, lbl) in zip(cols, metrics):
        with col:
            html(f'<div class="metric-box"><div class="metric-value">{val}</div>'
                 f'<div class="metric-label">{lbl}</div></div>')

def risk_badge(label: str) -> str:
    return f'<span class="risk-{label.lower()}">{label}</span>'

def phase_badge(text: str) -> str:
    return f'<span class="phase-badge">{text}</span>'


# ═══════════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════════════════

# ── Internal configuration (never shown or exposed to the user) ──────────────
# These used to be user-editable fields in the sidebar. The product now loads
# them automatically so end users never see file paths or engineering knobs.
_MODEL_PATH   = "models/model.joblib"
_FEATURES_PATH = "artifacts/case3_final_features.txt"
_DETECTION_THRESHOLD = 0.5
_AUTO_CDR_ON_MALICIOUS = True
_AUTO_SAVE_REPORT = True

_NAV_ITEMS = [
    ("🏠 Dashboard", "Overview"),
    ("🔍 Detection", "Scan a PDF"),
    ("🔬 Forensic Analysis", "Deep inspection"),
    ("🧹 CDR Remediation", "Sanitize a file"),
    ("📊 Full Pipeline", "End-to-end run"),
    ("ℹ️ About", "Project details"),
]


def sidebar():
    with st.sidebar:
        html("""
        <div style="text-align:center;padding:2rem 0 1.5rem;">
            <div style="width:64px;height:64px;margin:0 auto 0.9rem;border-radius:18px;
                        background:linear-gradient(160deg,#0071E3,#34AAFF);
                        display:flex;align-items:center;justify-content:center;
                        box-shadow:0 8px 24px rgba(0,113,227,0.35);">
                <span style="font-size:1.9rem;line-height:1">🛡️</span>
            </div>
            <div style="color:#1D1D1F;font-weight:700;font-size:1.08rem;letter-spacing:-0.01em">
                PDF Malware Shield
            </div>
            <div style="color:#6E6E73;font-size:0.76rem;margin-top:0.25rem;letter-spacing:0.01em">
                Detection · Forensics · Remediation
            </div>
        </div>
        """)

        page = st.radio(
            "Navigate",
            [label for label, _ in _NAV_ITEMS],
            label_visibility="collapsed"
        )

        html("""
        <div style="margin-top:2.5rem;padding-top:1.25rem;border-top:1px solid #E5E5EA;
                    text-align:center;">
            <div style="color:#6E6E73;font-size:0.7rem;letter-spacing:0.03em;line-height:1.6">
                MUET · BS Cyber Security<br/>Final Year Project
            </div>
        </div>
        """)

    return page, _MODEL_PATH, _FEATURES_PATH, _DETECTION_THRESHOLD, \
        _AUTO_CDR_ON_MALICIOUS, _AUTO_SAVE_REPORT


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

def page_dashboard():
    html("""
    <div class="main-header">
        <div style="font-size:3rem">🛡️</div>
        <div>
            <h1>PDF Malware Detection Suite</h1>
            <p>An Integrated AI System for Detection, Remediation, and Forensic Analysis of PDF-Based Malware</p>
            <p style="color:#6E6E73;font-size:0.78rem;margin-top:0.15rem">
                MUET BS Cyber Security · Bilawal Ali & Sagar · Supervisor: Engr. Mehran Mamonai
            </p>
        </div>
    </div>
    """)

    # Status cards
    c1, c2, c3, c4, c5 = st.columns(5)
    status_data = [
        (c1, "✅", "Dataset", "30,244 Samples", "#34C759", "DONE"),
        (c2, "✅", "Feature Extraction", "28 + 12 Features", "#34C759", "DONE"),
        (c3, "✅", "ML Training", "RF · 99.98% Acc", "#34C759", "DONE"),
        (c4, "✅", "Forensic Engine", "YARA + MITRE", "#0071E3", "ACTIVE"),
        (c5, "✅", "CDR Engine", "Structural Rebuild", "#0071E3", "ACTIVE"),
    ]
    for col, icon, title, val, color, badge in status_data:
        with col:
            html(f"""
            <div class="metric-box" style="border-color:{color}30;">
                <div style="font-size:1.5rem">{icon}</div>
                <div style="color:{color};font-weight:600;font-size:0.85rem;margin:0.3rem 0">{title}</div>
                <div class="metric-label">{val}</div>
                <div style="color:{color};font-size:0.65rem;letter-spacing:0.1em;
                            margin-top:0.3rem;background:{color}15;padding:0.1rem 0.4rem;
                            border-radius:3px;display:inline-block">{badge}</div>
            </div>""")

    st.markdown("---")

    # System architecture flow
    html("""
    <div class="card">
        <div class="card-title">⚙️ System Architecture — Online Detection & Analysis Phase (Phase II)</div>
        <div style="display:flex;align-items:center;gap:0.5rem;flex-wrap:wrap;padding:0.5rem 0;">
            <div style="background:rgba(0,113,227,0.1);border:1px solid rgba(0,113,227,0.3);
                        border-radius:6px;padding:0.5rem 0.75rem;text-align:center;min-width:100px;">
                <div style="font-size:1.2rem">📄</div>
                <div style="color:#0071E3;font-size:0.75rem;font-weight:600">User Uploads PDF</div>
            </div>
            <div style="color:#6E6E73;font-size:1.2rem">→</div>
            <div style="background:rgba(0,113,227,0.1);border:1px solid rgba(0,113,227,0.3);
                        border-radius:6px;padding:0.5rem 0.75rem;text-align:center;min-width:110px;">
                <div style="font-size:1.2rem">🔎</div>
                <div style="color:#0071E3;font-size:0.75rem;font-weight:600">Feature Extraction</div>
                <div style="color:#6E6E73;font-size:0.65rem">28+ features</div>
            </div>
            <div style="color:#6E6E73;font-size:1.2rem">→</div>
            <div style="background:rgba(0,113,227,0.1);border:1px solid rgba(0,113,227,0.3);
                        border-radius:6px;padding:0.5rem 0.75rem;text-align:center;min-width:110px;">
                <div style="font-size:1.2rem">🤖</div>
                <div style="color:#0071E3;font-size:0.75rem;font-weight:600">ML Processing</div>
                <div style="color:#6E6E73;font-size:0.65rem">RF + Ensemble</div>
            </div>
            <div style="color:#6E6E73;font-size:1.2rem">→</div>
            <div style="background:rgba(0,113,227,0.1);border:1px solid rgba(0,113,227,0.3);
                        border-radius:6px;padding:0.5rem 0.75rem;text-align:center;min-width:120px;">
                <div style="font-size:1.2rem">📊</div>
                <div style="color:#0071E3;font-size:0.75rem;font-weight:600">Prediction Output</div>
                <div style="color:#6E6E73;font-size:0.65rem">Score + SHAP</div>
            </div>
            <div style="color:#6E6E73;font-size:1.2rem">→</div>
            <div style="background:rgba(255,59,48,0.1);border:1px solid rgba(255,59,48,0.3);
                        border-radius:6px;padding:0.5rem 0.75rem;text-align:center;min-width:130px;">
                <div style="font-size:1.2rem">⚠️</div>
                <div style="color:#FF3B30;font-size:0.75rem;font-weight:600">Malicious Path</div>
                <div style="color:#6E6E73;font-size:0.65rem">CDR + Forensic</div>
            </div>
            <div style="color:#6E6E73;font-size:1.2rem">→</div>
            <div style="background:rgba(52,199,89,0.1);border:1px solid rgba(52,199,89,0.3);
                        border-radius:6px;padding:0.5rem 0.75rem;text-align:center;min-width:120px;">
                <div style="font-size:1.2rem">✅</div>
                <div style="color:#34C759;font-size:0.75rem;font-weight:600">Report + Clean PDF</div>
                <div style="color:#6E6E73;font-size:0.65rem">JSON / HTML / CSV</div>
            </div>
        </div>
    </div>
    """)

    # FYP progress
    col1, col2 = st.columns(2)
    with col1:
        html("""
        <div class="card">
            <div class="card-title">📌 FYP-I Objectives (Completed)</div>
            <div style="display:flex;flex-direction:column;gap:0.4rem;">
                <div style="display:flex;align-items:center;gap:0.75rem;padding:0.4rem 0.6rem;
                            background:rgba(52,199,89,0.08);border-radius:6px;">
                    <span>✅</span>
                    <span style="font-size:0.82rem;color:#1D1D1F">
                        <b>Dataset Preparation</b> — 30,244 samples (CIC-EvasivePDFMal2022)
                    </span>
                </div>
                <div style="display:flex;align-items:center;gap:0.75rem;padding:0.4rem 0.6rem;
                            background:rgba(52,199,89,0.08);border-radius:6px;">
                    <span>✅</span>
                    <span style="font-size:0.82rem;color:#1D1D1F">
                        <b>ML Training + SHAP</b> — RF 99.98% Accuracy · AUC 1.0000
                    </span>
                </div>
            </div>
        </div>
        """)

    with col2:
        html("""
        <div class="card">
            <div class="card-title">🚀 FYP-II Objectives (This GUI)</div>
            <div style="display:flex;flex-direction:column;gap:0.4rem;">
                <div style="display:flex;align-items:center;gap:0.75rem;padding:0.4rem 0.6rem;
                            background:rgba(0,113,227,0.08);border-radius:6px;">
                    <span>🔵</span>
                    <span style="font-size:0.82rem;color:#1D1D1F">
                        <b>CDR Remediation</b> — Structural object-level sanitization
                    </span>
                </div>
                <div style="display:flex;align-items:center;gap:0.75rem;padding:0.4rem 0.6rem;
                            background:rgba(0,113,227,0.08);border-radius:6px;">
                    <span>🔵</span>
                    <span style="font-size:0.82rem;color:#1D1D1F">
                        <b>Forensic Analysis</b> — YARA + MITRE ATT&CK mapping
                    </span>
                </div>
                <div style="display:flex;align-items:center;gap:0.75rem;padding:0.4rem 0.6rem;
                            background:rgba(0,113,227,0.08);border-radius:6px;">
                    <span>🔵</span>
                    <span style="font-size:0.82rem;color:#1D1D1F">
                        <b>GUI Integration</b> — This unified dashboard system
                    </span>
                </div>
            </div>
        </div>
        """)

    # ML performance summary
    html("""
    <div class="card">
        <div class="card-title">📈 Best Model Performance — Random Forest (FYP-I Results)</div>
        <div style="display:flex;gap:1rem;flex-wrap:wrap;">
    """)
    perf = [("99.98%","Accuracy"),("100.00%","Precision"),
            ("99.97%","Recall"),("99.98%","F1 Score"),("1.0000","ROC-AUC")]
    for val, lbl in perf:
        html(f'<div class="metric-box" style="min-width:100px;flex:1">'
             f'<div class="metric-value">{val}</div>'
             f'<div class="metric-label">{lbl}</div></div>')
    html("</div></div>")


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def page_detection(model_path: str, feat_path: str, threshold: float):
    html('<div class="main-header"><div style="font-size:2rem">🔍</div>'
         '<div><h1>ML Detection</h1>'
         '<p>Upload a PDF — the trained Random Forest model classifies it with SHAP feature analysis.</p></div></div>')

    uploaded = st.file_uploader("Drop a PDF file here", type=["pdf"],
                                 help="Any PDF file — malicious or benign")
    if not uploaded:
        html('<div class="card" style="text-align:center;padding:2rem;">'
             '<div style="font-size:3rem;opacity:0.4">📄</div>'
             '<div style="color:#6E6E73;margin-top:0.5rem">Upload a PDF to begin detection</div></div>')
        return

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    try:
        col_info, col_action = st.columns([3,1])
        with col_info:
            size_kb = Path(tmp_path).stat().st_size / 1024
            html(f'<div class="card">'
                 f'<div class="card-title">📄 File Info</div>'
                 f'<div style="font-family:SF Mono,ui-monospace,monospace;font-size:0.82rem;color:#6E6E73;">'
                 f'Name: <span style="color:#1D1D1F">{uploaded.name}</span><br/>'
                 f'Size: <span style="color:#1D1D1F">{size_kb:.1f} KB</span>'
                 f'</div></div>')
        with col_action:
            run = st.button("🚀 Run Detection", use_container_width=True)

        if not run:
            return

        with st.spinner("Extracting features and running ML model..."):
            result = ml_detect(tmp_path, model_path, feat_path, threshold)

        if not result.get("available"):
            st.error(f"Detection failed: {result.get('error','Unknown error')}")
            st.info("Make sure model artifacts exist. Run: `python main.py train --csv your_data.csv`")
            return

        # ── Verdict ────────────────────────────────────────────────────────
        verdict_col, gauge_col, gauge_col2 = st.columns([2,1,1])
        with verdict_col:
            verdict_box(result["label"], result["probability_malicious"], result["model"])
        with gauge_col:
            fig = gauge_chart(result["probability_malicious"], "P(Malicious)",
                              "#FF3B30" if result["label"]=="MALICIOUS" else "#34C759")
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
        with gauge_col2:
            fig = gauge_chart(result["confidence_pct"]/100, "Confidence",
                              "#0071E3")
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})

        # ── Key metrics ───────────────────────────────────────────────────
        raw = result.get("raw_features", {})
        metric_row([
            (f"{result['probability_malicious']:.4f}", "P(Malicious)"),
            (f"{result['probability_benign']:.4f}", "P(Benign)"),
            (f"{result['confidence_pct']:.1f}%", "Confidence"),
            (str(raw.get("f1_obj","-")), "PDF Objects"),
            (str(raw.get("f2_pages","-")), "Pages"),
            (f"{raw.get('f2_filesize_kb',0):.1f}KB", "File Size"),
        ])

        st.markdown("---")

        # ── Feature importance ─────────────────────────────────────────────
        col_feat, col_raw = st.columns([3,2])
        with col_feat:
            html('<div class="card-title">📊 Top Feature Contributions</div>')
            fig = feature_importance_chart(result.get("top_features", []))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})

        with col_raw:
            html('<div class="card-title">🔢 Key Feature Values</div>')
            top_feats = result.get("top_features", [])[:12]
            max_imp = max((f["importance"] for f in top_feats), default=1) or 1
            for feat in top_feats:
                pct = int(feat["importance"] / max_imp * 100)
                color = "#FF3B30" if pct > 70 else "#FF9F0A" if pct > 40 else "#0071E3"
                html(f'<div class="feat-bar-wrap">'
                     f'<div class="feat-label">{feat["feature"][:18]}</div>'
                     f'<div class="feat-bar-bg"><div class="feat-bar-fill" '
                     f'style="width:{pct}%;background:{color}"></div></div>'
                     f'<div class="feat-val">{feat["value"]:.0f}</div>'
                     f'</div>')

        # ── Raw features expandable ────────────────────────────────────────
        with st.expander("📋 All Extracted Features"):
            raw_df = pd.DataFrame([raw]).T.reset_index()
            raw_df.columns = ["Feature", "Value"]
            st.dataframe(raw_df, use_container_width=True, height=300,
                         hide_index=True)

        # ── JSON export ────────────────────────────────────────────────────
        result_clean = {k:v for k,v in result.items() if k != "raw_features"}
        st.download_button(
            "⬇️ Download Detection Report (JSON)",
            json.dumps(result_clean, indent=2),
            file_name=f"detection_{uploaded.name}.json",
            mime="application/json",
        )

    finally:
        os.unlink(tmp_path)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: FORENSIC ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def page_forensic(model_path: str, feat_path: str, threshold: float):
    html('<div class="main-header"><div style="font-size:2rem">🔬</div>'
         '<div><h1>Static Forensic Analysis</h1>'
         '<p>YARA rule matching · IOC extraction · MITRE ATT&CK mapping · Attack type classification</p></div></div>')

    uploaded = st.file_uploader("Drop a PDF file here", type=["pdf"], key="forensic_upload")
    if not uploaded:
        html('<div class="card" style="text-align:center;padding:2rem;">'
             '<div style="font-size:3rem;opacity:0.4">🔬</div>'
             '<div style="color:#6E6E73;margin-top:0.5rem">Upload a PDF for forensic analysis</div></div>')
        return

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        pdf_bytes = uploaded.read()
        tmp.write(pdf_bytes)
        tmp_path = tmp.name

    try:
        run_col, _ = st.columns([1,3])
        with run_col:
            run = st.button("🔬 Run Forensic Analysis", use_container_width=True)
        if not run:
            return

        with st.spinner("Running static forensic analysis..."):
            ml_res = ml_detect(tmp_path, model_path, feat_path, threshold)
            report = forensic_analyse(pdf_bytes, tmp_path, ml_res)

        # ── Risk + verdict row ─────────────────────────────────────────────
        r1, r2, r3 = st.columns([1,1,2])
        with r1:
            fig = risk_score_gauge(report["risk_score"], report["risk_label"])
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
        with r2:
            html(f"""
            <div class="card" style="margin-top:0">
                <div class="card-title">🎯 Attack Type</div>
                <div style="font-size:1.1rem;font-weight:700;color:#FF9F0A;margin:0.5rem 0">
                    {report["attack_classification"]["primary_type"].replace("_"," ").title()}
                </div>
                <div style="font-size:0.78rem;color:#6E6E73">
                    Confidence: {report["attack_classification"]["confidence"]}
                </div>
                <div style="font-size:0.78rem;color:#6E6E73;margin-top:0.4rem">
                    ML: {report["ml_verdict"].get("label","N/A") if report["ml_verdict"].get("available") else "N/A"}
                </div>
            </div>
            <div class="card">
                <div class="card-title">📂 File Info</div>
                <div style="font-size:0.75rem;font-family:SF Mono,ui-monospace,monospace;color:#6E6E73;line-height:1.7">
                    Size: {report["filesize_bytes"]//1024} KB<br/>
                    Entropy: {report["global_entropy"]} bits/byte<br/>
                    PDF ver: {report["pdf_header"]["version"]}<br/>
                    Time: {report["analysis_time_ms"]:.0f} ms
                </div>
            </div>
            """)
        with r3:
            fig = structural_radar(report["structural_counts"])
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})

        # ── Tabs for sections ──────────────────────────────────────────────
        tabs = st.tabs(["🔑 IOCs", "🔴 YARA Matches", "🗺️ MITRE ATT&CK",
                         "⚠️ Anomalies", "📋 Hashes", "🗂️ Metadata"])

        with tabs[0]:  # IOCs
            col_urls, col_misc = st.columns([2,1])
            with col_urls:
                html('<div class="card-title">🌐 URLs / Domains</div>')
                if report["iocs"]["urls"]:
                    for url in report["iocs"]["urls"][:15]:
                        html(f'<div class="ioc-chip">{url[:80]}</div>')
                else:
                    html('<div style="color:#6E6E73;font-size:0.82rem">No URLs detected</div>')
                if report["iocs"]["ip_addresses"]:
                    html('<div class="card-title" style="margin-top:0.75rem">🖥️ IP Addresses</div>')
                    for ip in report["iocs"]["ip_addresses"]:
                        html(f'<div class="ioc-chip">{ip}</div>')
            with col_misc:
                html('<div class="card-title">📌 IOC Summary</div>')
                metric_row([
                    (len(report["iocs"]["urls"]),         "URLs"),
                    (len(report["iocs"]["ip_addresses"]), "IPs"),
                ])
                metric_row([
                    (len(report["iocs"]["cve_refs"]),     "CVEs"),
                    (report["iocs"]["long_base64"],       "Base64 blobs"),
                ])
                metric_row([
                    (report["iocs"]["shellcode_seqs"],    "Shellcode seqs"),
                    (len(report["iocs"]["domains"]),      "Domains"),
                ])
                if report["iocs"]["cve_refs"]:
                    html('<div class="card-title" style="margin-top:0.75rem">🛡️ CVE References</div>')
                    for cve in report["iocs"]["cve_refs"]:
                        html(f'<div class="ioc-chip">{cve}</div>')

        with tabs[1]:  # YARA
            if report["yara_matches"]:
                html(f'<div style="color:#FF9F0A;font-weight:600;margin-bottom:0.5rem">'
                     f'{len(report["yara_matches"])} rule(s) matched</div>')
                for m in report["yara_matches"]:
                    sev_color = "#FF3B30" if m["severity"]=="CRITICAL" else \
                                "#FF9F0A" if m["severity"]=="HIGH" else "#FFCC00"
                    html(f"""
                    <div class="yara-match">
                        <div class="yara-rule">{m["rule"]}</div>
                        <div style="display:flex;gap:0.5rem;margin-top:0.3rem;flex-wrap:wrap;">
                            <span style="background:{sev_color}20;color:{sev_color};border:1px solid {sev_color}40;
                                         border-radius:4px;padding:0.1rem 0.4rem;font-size:0.7rem;font-weight:600">
                                {m["severity"]}
                            </span>
                            <span class="mitre-id">{m["technique"]}</span>
                            <span style="color:#6E6E73;font-size:0.75rem">{m["attack_type"].replace("_"," ")}</span>
                        </div>
                    </div>""")
            else:
                html('<div style="color:#6E6E73;padding:1rem">No YARA rules matched — file may be benign or use novel techniques</div>')

        with tabs[2]:  # MITRE
            if report["mitre_attack"]:
                for entry in report["mitre_attack"]:
                    html(f"""
                    <div class="mitre-row">
                        <div>
                            <div style="display:flex;gap:0.5rem;align-items:center;margin-bottom:0.3rem">
                                <span class="mitre-id">{entry["tactic_id"]}</span>
                                <span style="color:#6E6E73;font-size:0.8rem;font-weight:600">{entry["tactic"]}</span>
                            </div>
                            <div style="display:flex;gap:0.5rem;align-items:center">
                                <span class="mitre-id">{entry["technique_id"]}</span>
                                <span style="color:#1D1D1F;font-size:0.82rem">{entry["technique"]}</span>
                            </div>
                            <div style="color:#6E6E73;font-size:0.75rem;margin-top:0.3rem">{entry["evidence"]}</div>
                        </div>
                    </div>""")
            else:
                html('<div style="color:#6E6E73;padding:1rem">No MITRE techniques mapped — insufficient indicators</div>')

        with tabs[3]:  # Anomalies
            if report["anomalies"]:
                for anom in report["anomalies"]:
                    html(f'<div style="background:rgba(255,204,0,0.08);border-left:3px solid #FFCC00;'
                         f'border-radius:0 6px 6px 0;padding:0.6rem 1rem;margin-bottom:0.4rem;'
                         f'font-size:0.82rem;color:#FF9F0A">⚠️ {anom}</div>')
            else:
                html('<div style="color:#34C759;padding:1rem">✅ No structural anomalies detected</div>')

        with tabs[4]:  # Hashes
            h = report["hashes"]
            html(f"""
            <div class="card">
                <div class="card-title">🔐 Cryptographic Hashes</div>
                <table style="width:100%;border-collapse:collapse;">
                    <tr><td style="color:#6E6E73;font-size:0.78rem;padding:0.4rem 0;width:60px">MD5</td>
                        <td style="font-family:SF Mono,ui-monospace,monospace;font-size:0.78rem;color:#1D1D1F;word-break:break-all">{h["md5"]}</td></tr>
                    <tr><td style="color:#6E6E73;font-size:0.78rem;padding:0.4rem 0">SHA1</td>
                        <td style="font-family:SF Mono,ui-monospace,monospace;font-size:0.78rem;color:#1D1D1F;word-break:break-all">{h["sha1"]}</td></tr>
                    <tr><td style="color:#6E6E73;font-size:0.78rem;padding:0.4rem 0">SHA256</td>
                        <td style="font-family:SF Mono,ui-monospace,monospace;font-size:0.78rem;color:#1D1D1F;word-break:break-all">{h["sha256"]}</td></tr>
                </table>
            </div>
            """)
            fig = entropy_bar_chart(report["global_entropy"])
            html('<div class="card-title">📊 Shannon Entropy</div>')
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})

        with tabs[5]:  # Metadata
            meta = {k:v for k,v in report["metadata"].items() if v}
            if meta:
                for k, v in meta.items():
                    html(f'<div style="padding:0.3rem 0;border-bottom:1px solid #D2D2D7;">'
                         f'<span style="color:#6E6E73;font-size:0.78rem;width:120px;display:inline-block">{k}</span>'
                         f'<span style="color:#1D1D1F;font-size:0.82rem">{v}</span></div>')
            else:
                html('<div style="color:#6E6E73;padding:1rem">No metadata fields found — possible stripping for evasion</div>')

        # ── Export ────────────────────────────────────────────────────────
        st.markdown("---")
        col_dl1, col_dl2, _ = st.columns([1,1,2])
        with col_dl1:
            st.download_button(
                "⬇️ Download JSON Report",
                json.dumps(report, indent=2),
                file_name=f"forensic_{uploaded.name}.json",
                mime="application/json",
            )
        with col_dl2:
            # Simple HTML report
            html_report = _generate_html_report(report)
            st.download_button(
                "⬇️ Download HTML Report",
                html_report,
                file_name=f"forensic_{uploaded.name}.html",
                mime="text/html",
            )

    finally:
        os.unlink(tmp_path)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: CDR REMEDIATION
# ═══════════════════════════════════════════════════════════════════════════════

def page_cdr(model_path: str, feat_path: str, threshold: float):
    html('<div class="main-header"><div style="font-size:2rem">🧹</div>'
         '<div><h1>CDR Remediation</h1>'
         '<p>Content Disarm & Reconstruction — parses PDF object tree, removes dangerous objects, '
         'rebuilds safe document.</p></div></div>')

    html("""
    <div class="card">
        <div class="card-title">ℹ️ How CDR Works</div>
        <div style="display:flex;gap:1rem;flex-wrap:wrap;font-size:0.82rem;color:#6E6E73;">
            <div style="flex:1;min-width:160px;padding:0.5rem;background:rgba(0,113,227,0.06);border-radius:6px;">
                <b style="color:#0071E3">1. Parse</b><br/>Reads cross-reference table, extracts all PDF indirect objects
            </div>
            <div style="flex:1;min-width:160px;padding:0.5rem;background:rgba(0,113,227,0.06);border-radius:6px;">
                <b style="color:#0071E3">2. Classify</b><br/>Checks each object's dict keywords and decoded stream content
            </div>
            <div style="flex:1;min-width:160px;padding:0.5rem;background:rgba(255,59,48,0.06);border-radius:6px;">
                <b style="color:#FF3B30">3. Remove</b><br/>Discards /JS, /Launch, /EmbeddedFile, eval(), shellcode objects
            </div>
            <div style="flex:1;min-width:160px;padding:0.5rem;background:rgba(52,199,89,0.06);border-radius:6px;">
                <b style="color:#34C759">4. Rebuild</b><br/>Reconstructs clean PDF with renumbered xref, preserving fonts/images
            </div>
        </div>
    </div>
    """)

    uploaded = st.file_uploader("Drop a PDF file here", type=["pdf"], key="cdr_upload")
    if not uploaded:
        html('<div class="card" style="text-align:center;padding:2rem;">'
             '<div style="font-size:3rem;opacity:0.4">🧹</div>'
             '<div style="color:#6E6E73;margin-top:0.5rem">Upload a PDF to sanitize</div></div>')
        return

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        pdf_bytes = uploaded.read()
        tmp.write(pdf_bytes)
        tmp_path = tmp.name

    try:
        options_col, _ = st.columns([2,2])
        with options_col:
            dry_run = st.checkbox("Dry run (analyse only, don't write output)", value=False)
            verify_ml = st.checkbox("Verify with ML before/after", value=True)

        run = st.button("🧹 Run CDR Disarm", use_container_width=False)
        if not run:
            return

        with st.spinner("Running pikepdf disarm & reconstruct pipeline..."):
            t0 = time.perf_counter()
            cdr_result = cdr_disarm(pdf_bytes, tmp_path)
            elapsed = (time.perf_counter() - t0)*1000

        if "error" in cdr_result:
            st.error(f"CDR failed: {cdr_result['error']}")
            if cdr_result.get("traceback"):
                with st.expander("Show technical details"):
                    st.code(cdr_result["traceback"])
            return

        rep = cdr_result["report"]
        removed_cats = cdr_result["removed_by_category"]
        found_cats   = cdr_result["found_by_category"]

        # ── Summary metrics ────────────────────────────────────────────────
        metric_row([
            (rep["objects_total"],    "Total Found"),
            (rep["objects_removed"],  "Removed"),
            (rep["objects_kept"],     "Kept"),
            (f"{rep['size_reduction_pct']}%", "Size Reduction"),
            (f"{rep['original_size_bytes']//1024}KB", "Original"),
            (f"{rep['cleaned_size_bytes']//1024}KB",  "Clean Size"),
        ])

        st.markdown("---")
        col_rem, col_kept = st.columns(2)

        with col_rem:
            html(f'<div class="card-title" style="color:#FF3B30">🗑️ Removed by Attack Vector ({len(removed_cats)})</div>')
            if removed_cats:
                for cat, n in sorted(removed_cats.items(), key=lambda kv: -kv[1]):
                    html(f'<div class="cdr-removed">{cat.replace("_"," ").title()} — {n} removed</div>')
            else:
                html('<div style="color:#34C759;font-size:0.82rem">✅ No dangerous content detected</div>')

        with col_kept:
            html('<div class="card-title" style="color:#34C759">✅ Renderability &amp; Warnings</div>')
            render_ok = rep.get("renderable")
            html(f'<div class="cdr-kept">{"✅" if render_ok else "⚠️"} {rep.get("render_detail","")}</div>')
            for w in rep.get("warnings", [])[:10]:
                html(f'<div class="cdr-kept">⚠️ {w}</div>')
            if not rep.get("warnings"):
                html('<div style="color:#6E6E73;font-size:0.78rem">No warnings.</div>')

        # ── ML Verification ────────────────────────────────────────────────
        if verify_ml:
            st.markdown("---")
            html('<div class="card-title">🤖 ML Verification (Before vs After)</div>')

            if Path(model_path).exists() and Path(feat_path).exists():
                with st.spinner("Running ML on original and cleaned PDFs..."):
                    ml_before = ml_detect(tmp_path, model_path, feat_path, threshold)

                    if not dry_run:
                        with tempfile.NamedTemporaryFile(suffix="_clean.pdf", delete=False) as ctmp:
                            ctmp.write(cdr_result["clean_bytes"])
                            clean_tmp = ctmp.name
                        try:
                            ml_after = ml_detect(clean_tmp, model_path, feat_path, threshold)
                        finally:
                            os.unlink(clean_tmp)
                    else:
                        ml_after = None

                v_col1, v_col2 = st.columns(2)
                with v_col1:
                    html('<div style="text-align:center;color:#6E6E73;font-size:0.8rem;margin-bottom:0.4rem">BEFORE CDR</div>')
                    if ml_before.get("available"):
                        verdict_box(ml_before["label"], ml_before["probability_malicious"], ml_before["model"])
                    else:
                        st.warning(ml_before.get("error","ML unavailable"))
                with v_col2:
                    html('<div style="text-align:center;color:#6E6E73;font-size:0.8rem;margin-bottom:0.4rem">AFTER CDR</div>')
                    if ml_after and ml_after.get("available"):
                        verdict_box(ml_after["label"], ml_after["probability_malicious"], ml_after["model"])
                    elif dry_run:
                        html('<div class="metric-box" style="text-align:center;padding:1.5rem"><div style="color:#6E6E73">Dry run — no output written</div></div>')
                    else:
                        st.warning("ML verification failed")
            else:
                st.info("ML model/features not found — skipping verification")

        # ── Download clean PDF ─────────────────────────────────────────────
        if not dry_run and cdr_result["clean_bytes"]:
            st.markdown("---")
            col_dl, _ = st.columns([1,3])
            with col_dl:
                st.download_button(
                    "⬇️ Download Clean PDF",
                    cdr_result["clean_bytes"],
                    file_name=f"clean_{uploaded.name}",
                    mime="application/pdf",
                )
            st.download_button(
                "⬇️ Download CDR Report (JSON)",
                json.dumps(rep, indent=2),
                file_name=f"cdr_report_{uploaded.name}.json",
                mime="application/json",
            )

    finally:
        os.unlink(tmp_path)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: FULL PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def page_pipeline(model_path: str, feat_path: str, threshold: float,
                  auto_cdr: bool, save_report: bool):
    html('<div class="main-header"><div style="font-size:2rem">📊</div>'
         '<div><h1>Full Pipeline</h1>'
         '<p>One-click end-to-end: Feature Extraction → ML Detection → Forensic Analysis → CDR Remediation → Report</p></div></div>')

    # Pipeline flow diagram
    html("""
    <div class="card">
        <div style="display:flex;align-items:center;gap:0.5rem;justify-content:center;flex-wrap:wrap;padding:0.5rem;">
            <div style="text-align:center;padding:0.4rem 0.6rem;background:rgba(0,113,227,0.1);
                        border:1px solid rgba(0,113,227,0.3);border-radius:6px;min-width:80px;">
                <div>📄</div><div style="color:#0071E3;font-size:0.7rem">Upload</div>
            </div>
            <div style="color:#6E6E73">→</div>
            <div style="text-align:center;padding:0.4rem 0.6rem;background:rgba(0,113,227,0.1);
                        border:1px solid rgba(0,113,227,0.3);border-radius:6px;min-width:80px;">
                <div>🔢</div><div style="color:#0071E3;font-size:0.7rem">Features</div>
            </div>
            <div style="color:#6E6E73">→</div>
            <div style="text-align:center;padding:0.4rem 0.6rem;background:rgba(0,113,227,0.1);
                        border:1px solid rgba(0,113,227,0.3);border-radius:6px;min-width:80px;">
                <div>🤖</div><div style="color:#0071E3;font-size:0.7rem">ML Detect</div>
            </div>
            <div style="color:#6E6E73">→</div>
            <div style="text-align:center;padding:0.4rem 0.6rem;background:rgba(0,113,227,0.1);
                        border:1px solid rgba(0,113,227,0.3);border-radius:6px;min-width:80px;">
                <div>🔬</div><div style="color:#0071E3;font-size:0.7rem">Forensics</div>
            </div>
            <div style="color:#6E6E73">→</div>
            <div style="text-align:center;padding:0.4rem 0.6rem;background:rgba(255,59,48,0.1);
                        border:1px solid rgba(255,59,48,0.3);border-radius:6px;min-width:80px;">
                <div>🧹</div><div style="color:#FF3B30;font-size:0.7rem">CDR</div>
            </div>
            <div style="color:#6E6E73">→</div>
            <div style="text-align:center;padding:0.4rem 0.6rem;background:rgba(52,199,89,0.1);
                        border:1px solid rgba(52,199,89,0.3);border-radius:6px;min-width:80px;">
                <div>📋</div><div style="color:#34C759;font-size:0.7rem">Report</div>
            </div>
        </div>
    </div>
    """)

    uploaded = st.file_uploader("Drop a PDF file here", type=["pdf"], key="pipeline_upload")
    if not uploaded:
        html('<div class="card" style="text-align:center;padding:2rem;">'
             '<div style="font-size:3rem;opacity:0.4">📊</div>'
             '<div style="color:#6E6E73;margin-top:0.5rem">Upload a PDF to run the complete pipeline</div></div>')
        return

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        pdf_bytes = uploaded.read()
        tmp.write(pdf_bytes)
        tmp_path = tmp.name

    try:
        run = st.button("▶️ Run Full Pipeline", use_container_width=False,
                         help="Runs: Feature extraction → ML → Forensics → CDR")
        if not run:
            return

        progress = st.progress(0, text="Starting pipeline...")
        status_area = st.empty()

        # Step 1: ML Detection
        status_area.info("⚙️ Step 1/3 — Running ML detection...")
        progress.progress(25, text="ML Detection...")
        ml_result = ml_detect(tmp_path, model_path, feat_path, threshold)
        progress.progress(50, text="Forensic Analysis...")

        # Step 2: Forensics
        status_area.info("🔬 Step 2/3 — Running forensic analysis...")
        forensic_report = forensic_analyse(pdf_bytes, tmp_path, ml_result)
        progress.progress(75, text="CDR Remediation...")

        # Step 3: CDR (if malicious or always)
        cdr_result = None
        do_cdr = auto_cdr and (ml_result.get("label") == "MALICIOUS" or
                                forensic_report["risk_score"] >= 25)
        if do_cdr:
            status_area.info("🧹 Step 3/3 — Running CDR remediation...")
            cdr_result = cdr_disarm(pdf_bytes, tmp_path)
            if cdr_result is not None and "error" in cdr_result:
                st.warning(f"CDR remediation failed: {cdr_result['error']}")
                cdr_result = None

        progress.progress(100, text="Complete!")
        status_area.empty()
        progress.empty()

        # ── Pipeline Summary ───────────────────────────────────────────────
        html('<div class="card-title" style="font-size:0.9rem;margin-bottom:0.75rem">📋 Pipeline Results</div>')

        prow = st.columns(4)
        with prow[0]:
            verdict = ml_result.get("label","N/A") if ml_result.get("available") else "N/A"
            color = "#FF3B30" if verdict=="MALICIOUS" else "#34C759" if verdict=="BENIGN" else "#6E6E73"
            html(f'<div class="metric-box"><div class="metric-value" style="color:{color};font-size:1.2rem">{verdict}</div>'
                 f'<div class="metric-label">ML Verdict</div></div>')
        with prow[1]:
            rl = forensic_report["risk_label"]
            rc = "#FF3B30" if rl=="CRITICAL" else "#FF9F0A" if rl=="HIGH" else "#FFCC00" if rl=="MEDIUM" else "#34C759"
            html(f'<div class="metric-box"><div class="metric-value" style="color:{rc};font-size:1.2rem">{rl}</div>'
                 f'<div class="metric-label">Risk Level ({forensic_report["risk_score"]}/100)</div></div>')
        with prow[2]:
            at = forensic_report["attack_classification"]["primary_type"].replace("_"," ").title()
            html(f'<div class="metric-box"><div class="metric-value" style="font-size:0.9rem;color:#FF9F0A">{at}</div>'
                 f'<div class="metric-label">Attack Type</div></div>')
        with prow[3]:
            cdr_status = f"{cdr_result['report']['objects_removed']} objs removed" if cdr_result else "Not run"
            html(f'<div class="metric-box"><div class="metric-value" style="font-size:0.85rem;color:#0071E3">{cdr_status}</div>'
                 f'<div class="metric-label">CDR Status</div></div>')

        st.markdown("---")
        # Expandable sections
        with st.expander("🤖 ML Detection Detail"):
            if ml_result.get("available"):
                verdict_box(ml_result["label"], ml_result["probability_malicious"], ml_result["model"])
                if ml_result.get("top_features"):
                    fig = feature_importance_chart(ml_result["top_features"])
                    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
            else:
                st.warning(ml_result.get("error","Model not available"))

        with st.expander("🔬 Forensic Analysis Detail"):
            col1, col2 = st.columns(2)
            with col1:
                fig = risk_score_gauge(forensic_report["risk_score"], forensic_report["risk_label"])
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
            with col2:
                fig = structural_radar(forensic_report["structural_counts"])
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
            if forensic_report["yara_matches"]:
                html('<div class="card-title">🔴 YARA Matches</div>')
                for m in forensic_report["yara_matches"]:
                    html(f'<div class="yara-match"><div class="yara-rule">{m["rule"]}</div>'
                         f'<div style="color:#6E6E73;font-size:0.75rem">{m["severity"]} · {m["technique"]}</div></div>')
            if forensic_report["mitre_attack"]:
                html('<div class="card-title" style="margin-top:0.75rem">🗺️ MITRE ATT&CK</div>')
                for entry in forensic_report["mitre_attack"][:4]:
                    html(f'<div class="mitre-row">'
                         f'<span class="mitre-id">{entry["technique_id"]}</span>'
                         f'<span style="color:#1D1D1F;font-size:0.82rem">{entry["technique"]}</span>'
                         f'</div>')

        with st.expander("🧹 CDR Remediation Detail"):
            if cdr_result:
                rep = cdr_result["report"]
                metric_row([
                    (rep["objects_total"],   "Objects Total"),
                    (rep["objects_removed"], "Removed"),
                    (rep["objects_kept"],    "Kept"),
                    (f"{rep['size_reduction_pct']}%","Size Reduction"),
                ])
                if cdr_result["removed_by_category"]:
                    html('<div class="card-title" style="margin-top:0.75rem;color:#FF3B30">Removed by Attack Vector</div>')
                    for cat, n in sorted(cdr_result["removed_by_category"].items(), key=lambda kv: -kv[1]):
                        html(f'<div class="cdr-removed">{cat.replace("_"," ").title()} — {n} removed</div>')
            else:
                html('<div style="color:#6E6E73;padding:1rem">CDR not run — file risk below threshold or auto-CDR disabled</div>')

        # ── Downloads ─────────────────────────────────────────────────────
        st.markdown("---")
        html('<div class="card-title">⬇️ Export Results</div>')
        dcols = st.columns(4)
        full_report = {
            "pipeline_timestamp": datetime.now(timezone.utc).isoformat(),
            "file": uploaded.name,
            "ml_result": {k:v for k,v in ml_result.items() if k not in ("raw_features","top_features")},
            "forensic_report": forensic_report,
            "cdr_report": cdr_result["report"] if cdr_result else None,
        }
        with dcols[0]:
            st.download_button("📋 JSON Report", json.dumps(full_report, indent=2),
                               file_name=f"pipeline_{uploaded.name}.json", mime="application/json")
        with dcols[1]:
            st.download_button("🔬 Forensic Report", json.dumps(forensic_report, indent=2),
                               file_name=f"forensic_{uploaded.name}.json", mime="application/json")
        if cdr_result:
            with dcols[2]:
                st.download_button("🧹 CDR Report", json.dumps(cdr_result["report"], indent=2),
                                   file_name=f"cdr_{uploaded.name}.json", mime="application/json")
            with dcols[3]:
                st.download_button("⬇️ Clean PDF", cdr_result["clean_bytes"],
                                   file_name=f"clean_{uploaded.name}", mime="application/pdf")

    finally:
        os.unlink(tmp_path)


# ═══════════════════════════════════════════════════════════════════════════════
# PAGE: ABOUT
# ═══════════════════════════════════════════════════════════════════════════════

def page_about():
    html("""
    <div class="main-header">
        <div style="font-size:2rem">ℹ️</div>
        <div><h1>About This System</h1>
        <p>An Integrated AI System for Detection, Remediation, and Forensic Analysis of PDF-Based Malware</p>
        </div>
    </div>
    """)

    col1, col2 = st.columns(2)
    with col1:
        html("""
        <div class="card">
            <div class="card-title">👥 Project Team</div>
            <table style="width:100%;font-size:0.82rem;color:#6E6E73;">
                <tr><td style="color:#0071E3;font-weight:600;padding:0.3rem 0">Bilawal Ali (GL)</td><td>22BSCYS002</td></tr>
                <tr><td style="color:#0071E3;font-weight:600;padding:0.3rem 0">Sagar</td><td>22BSCYS049</td></tr>
                <tr><td style="color:#6E6E73;padding:0.3rem 0">Supervisor</td><td>Engr. Mehran Mamonai</td></tr>
                <tr><td style="color:#6E6E73;padding:0.3rem 0">Co-Supervisor</td><td>Dr. Mohsin Ali Memon</td></tr>
                <tr><td style="color:#6E6E73;padding:0.3rem 0">Department</td><td>BS Cyber Security, MUET</td></tr>
                <tr><td style="color:#6E6E73;padding:0.3rem 0">Batch</td><td>22BSCYS</td></tr>
            </table>
        </div>
        """)
        html("""
        <div class="card">
            <div class="card-title">🗂️ Dataset</div>
            <div style="font-size:0.82rem;color:#6E6E73;line-height:1.7">
                <b style="color:#1D1D1F">CIC-EvasivePDFMal2022</b><br/>
                University of New Brunswick — Canadian Institute for Cybersecurity<br/><br/>
                30,244 total samples · 15,513 Benign · 14,731 Malicious<br/>
                28 raw + 12 engineered features<br/>
                RF accuracy: <b style="color:#34C759">99.98%</b> · AUC: <b style="color:#34C759">1.0000</b>
            </div>
        </div>
        """)

    with col2:
        html("""
        <div class="card">
            <div class="card-title">🛠️ System Modules</div>
            <div style="font-size:0.82rem;color:#6E6E73;line-height:2">
                <span style="color:#0071E3">extract_features.py</span> — F1/F2/F3 + derived feature extractor<br/>
                <span style="color:#0071E3">feature_selection.py / train_final_model.py</span> — training pipeline<br/>
                <span style="color:#0071E3">predict_pdf.py</span> — ML inference (bundle-based)<br/>
                <span style="color:#0071E3">pdf_forensic_v2.py</span> — Forensic analysis engine<br/>
                <span style="color:#0071E3">pdf_cdr_v4.py</span> — pikepdf-based CDR engine<br/>
                <span style="color:#0071E3">app.py</span> — This unified application interface
            </div>
        </div>
        """)
        html("""
        <div class="card">
            <div class="card-title">📚 Key References</div>
            <div style="font-size:0.78rem;color:#6E6E73;line-height:2">
                [1] Dubin et al., PdfCDR, IEEE TIFS 2023<br/>
                [2] Hossain et al., Feature-based PDF detection, 2024<br/>
                [3] Smutz & Stavrou, RF + SHAP PDF detection, ACM ACSAC 2022<br/>
                [4] Issakhani et al., Stacking learning, ICISS 2022<br/>
                [5] CIC-EvasivePDFMal2022 Dataset, UNB 2022
            </div>
        </div>
        """)

    html("""
    <div class="card">
        <div class="card-title">🚀 Quick Start</div>
        <div style="display:flex;flex-direction:column;gap:0.6rem;">
            <div style="display:flex;align-items:center;gap:0.85rem;padding:0.6rem 0.7rem;
                        background:rgba(0,113,227,0.06);border-radius:12px;">
                <div style="width:26px;height:26px;border-radius:8px;background:var(--accent);
                            color:#fff;display:flex;align-items:center;justify-content:center;
                            font-size:0.78rem;font-weight:700;flex-shrink:0">1</div>
                <span style="font-size:0.85rem;color:#1D1D1F">Open <b>Detection</b> and upload a PDF to get an instant verdict</span>
            </div>
            <div style="display:flex;align-items:center;gap:0.85rem;padding:0.6rem 0.7rem;
                        background:rgba(0,113,227,0.06);border-radius:12px;">
                <div style="width:26px;height:26px;border-radius:8px;background:var(--accent);
                            color:#fff;display:flex;align-items:center;justify-content:center;
                            font-size:0.78rem;font-weight:700;flex-shrink:0">2</div>
                <span style="font-size:0.85rem;color:#1D1D1F">Use <b>Forensic Analysis</b> for a deep structural and IOC breakdown</span>
            </div>
            <div style="display:flex;align-items:center;gap:0.85rem;padding:0.6rem 0.7rem;
                        background:rgba(0,113,227,0.06);border-radius:12px;">
                <div style="width:26px;height:26px;border-radius:8px;background:var(--accent);
                            color:#fff;display:flex;align-items:center;justify-content:center;
                            font-size:0.78rem;font-weight:700;flex-shrink:0">3</div>
                <span style="font-size:0.85rem;color:#1D1D1F">Run <b>CDR Remediation</b> to receive a sanitized, safe copy of a malicious file</span>
            </div>
            <div style="display:flex;align-items:center;gap:0.85rem;padding:0.6rem 0.7rem;
                        background:rgba(0,113,227,0.06);border-radius:12px;">
                <div style="width:26px;height:26px;border-radius:8px;background:var(--accent);
                            color:#fff;display:flex;align-items:center;justify-content:center;
                            font-size:0.78rem;font-weight:700;flex-shrink:0">4</div>
                <span style="font-size:0.85rem;color:#1D1D1F">Or use <b>Full Pipeline</b> to run detection, forensics, and remediation in one pass</span>
            </div>
        </div>
    </div>
    """)


# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════

def _generate_html_report(report: dict) -> str:
    risk_color = {"CRITICAL":"#FF3B30","HIGH":"#FF9F0A","MEDIUM":"#FFCC00","LOW":"#34C759"}
    rc = risk_color.get(report["risk_label"],"#6E6E73")
    yara_rows = "".join(
        f'<tr><td style="font-family:monospace;color:#FF9F0A">{m["rule"]}</td>'
        f'<td>{m["severity"]}</td><td>{m["technique"]}</td>'
        f'<td>{m["attack_type"]}</td></tr>'
        for m in report.get("yara_matches",[])
    )
    mitre_rows = "".join(
        f'<tr><td style="font-family:monospace">{e["tactic_id"]}</td><td>{e["tactic"]}</td>'
        f'<td style="font-family:monospace">{e["technique_id"]}</td><td>{e["technique"]}</td></tr>'
        for e in report.get("mitre_attack",[])
    )
    ioc_urls = "".join(f'<li style="word-break:break-all">{u}</li>' for u in report["iocs"]["urls"][:10])
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<title>Forensic Report — {report["filename"]}</title>
<style>
:root{{--bg:#F5F5F7;--card:#FFFFFF;--text:#1D1D1F;--text2:#6E6E73;--border:#D2D2D7;--accent:#0071E3;}}
*{{box-sizing:border-box}}
body{{font-family:'Inter',-apple-system,'SF Pro Display','Segoe UI','Helvetica Neue',sans-serif;background:var(--bg);color:var(--text);padding:0;margin:0;}}
.report-wrap{{max-width:860px;margin:0 auto;padding:3rem 2rem;}}
h1{{color:var(--text);font-size:1.9rem;font-weight:700;letter-spacing:-0.02em;margin:0 0 0.3rem 0}}
h2{{color:var(--text);font-size:0.8rem;font-weight:600;letter-spacing:0.08em;text-transform:uppercase;border-bottom:1px solid var(--border);padding-bottom:0.5rem;margin-top:2.25rem}}
.badge{{display:inline-block;padding:0.5rem 1rem;border-radius:999px;font-weight:700;font-size:1rem;color:{rc};background:{rc}15;border:1px solid {rc}40;margin-top:0.75rem}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:20px;box-shadow:0 10px 40px rgba(0,0,0,0.06);padding:0.25rem 1.25rem;margin-top:0.75rem}}
table{{width:100%;border-collapse:collapse;margin-top:0.25rem}}
th{{background:#FAFAFC;color:var(--text2);font-size:0.72rem;letter-spacing:0.06em;text-transform:uppercase;padding:0.6rem;text-align:left}}
td{{padding:0.6rem;border-bottom:1px solid var(--border);font-size:0.85rem;color:var(--text)}}
tr:last-child td{{border-bottom:none}}
.mono{{font-family:'SF Mono','SFMono-Regular',ui-monospace,Menlo,monospace;font-size:0.78rem;word-break:break-all}}
ul{{margin:0.5rem 0 0 0;padding-left:1.25rem}}
li{{font-size:0.85rem;margin-bottom:0.3rem}}
</style></head><body>
<div class="report-wrap">
<h1>🛡️ PDF Forensic Report</h1>
<p style="color:#6E6E73">{report["timestamp"]} · {report["filename"]}</p>
<div class="badge">{report["risk_label"]} RISK — {report["risk_score"]}/100</div>
<h2>File Information</h2>
<div class="card"><table><tr><th>Field</th><th>Value</th></tr>
<tr><td>Filename</td><td>{report["filename"]}</td></tr>
<tr><td>Size</td><td>{report["filesize_bytes"]:,} bytes</td></tr>
<tr><td>PDF Version</td><td>{report["pdf_header"]["version"]}</td></tr>
<tr><td>Entropy</td><td>{report["global_entropy"]} bits/byte</td></tr>
<tr><td>Analysis Time</td><td>{report["analysis_time_ms"]:.0f} ms</td></tr>
</table></div>
<h2>Hashes</h2>
<div class="card"><table><tr><th>Algorithm</th><th>Hash</th></tr>
<tr><td>MD5</td><td class="mono">{report["hashes"]["md5"]}</td></tr>
<tr><td>SHA1</td><td class="mono">{report["hashes"]["sha1"]}</td></tr>
<tr><td>SHA256</td><td class="mono">{report["hashes"]["sha256"]}</td></tr>
</table></div>
<h2>Attack Classification</h2>
<div class="card" style="padding:1rem 1.25rem"><p style="margin:0"><b style="color:#FF9F0A">{report["attack_classification"]["primary_type"].replace("_"," ").title()}</b>
— Confidence: {report["attack_classification"]["confidence"]}</p></div>
<h2>YARA Matches</h2>
<div class="card"><table><tr><th>Rule</th><th>Severity</th><th>Technique</th><th>Attack Type</th></tr>
{yara_rows if yara_rows else "<tr><td colspan=4>No matches</td></tr>"}
</table></div>
<h2>MITRE ATT&CK</h2>
<div class="card"><table><tr><th>Tactic ID</th><th>Tactic</th><th>Technique ID</th><th>Technique</th></tr>
{mitre_rows if mitre_rows else "<tr><td colspan=4>No techniques mapped</td></tr>"}
</table></div>
<h2>IOCs — URLs</h2>
<div class="card" style="padding:1rem 1.25rem"><ul style="color:#FF3B30;font-size:0.85rem">{ioc_urls if ioc_urls else "<li style='color:#34C759'>None detected</li>"}</ul></div>
<h2>Anomalies</h2>
<div class="card" style="padding:1rem 1.25rem"><ul>{"".join(f"<li style='color:#FF9F0A'>{a}</li>" for a in report.get("anomalies",[])) or "<li style='color:#34C759'>None detected</li>"}</ul></div>
<p style="color:#6E6E73;font-size:0.72rem;margin-top:3rem;border-top:1px solid #D2D2D7;padding-top:1rem">
Generated by PDF Malware Shield · MUET BS Cyber Security FYP · {report["timestamp"]}
</p>
</div>
</body></html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    page, model_path, feat_path, threshold, auto_cdr, save_report = sidebar()

    if page == "🏠 Dashboard":
        page_dashboard()
    elif page == "🔍 Detection":
        page_detection(model_path, feat_path, threshold)
    elif page == "🔬 Forensic Analysis":
        page_forensic(model_path, feat_path, threshold)
    elif page == "🧹 CDR Remediation":
        page_cdr(model_path, feat_path, threshold)
    elif page == "📊 Full Pipeline":
        page_pipeline(model_path, feat_path, threshold, auto_cdr, save_report)
    elif page == "ℹ️ About":
        page_about()


if __name__ == "__main__":
    main()
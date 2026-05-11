"""
PDF Malware Forensic Report Generator
=======================================
FYP: An Integrated AI System for Detection, Remediation, and Forensic Analysis
     of PDF-Based Malware
Team: Bilawal Ali (22BSCYS002) & Sagar (22BSCYS049)
Dept: BS Cyber Security, MUET
Supervisor: Engr. Mehran Mamonai

Generates a professional multi-page PDF forensic report containing:
  Page 1  — Cover page with verdict & risk level
  Page 2  — Executive Summary
  Page 3  — File Identification (hashes, metadata, properties)
  Page 4  — ML Model Analysis (all 6 model predictions + bar chart)
  Page 5  — Threat Indicator Analysis (detailed breakdown)
  Page 6  — Structural Analysis (PDF object tree stats)
  Page 7  — Remediation Summary (what was removed, before/after)
  Page 8  — Recommendations & Conclusion

Usage:
  python forensic_report.py suspicious.pdf
  python forensic_report.py suspicious.pdf --models models_comparison
  python forensic_report.py suspicious.pdf --remediation-report report.json
  python forensic_report.py --batch ./folder/ --out-dir ./forensic_reports/
"""

import os
import re
import sys
import csv
import json
import hashlib
import argparse
import subprocess
import numpy as np
from pathlib import Path
from datetime import datetime
from collections import Counter

# ReportLab
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm, mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF
from reportlab.pdfgen import canvas as rl_canvas


# ─────────────────────────────────────────────
# COLOUR PALETTE
# ─────────────────────────────────────────────

C_DARK      = colors.HexColor("#1A1A2E")   # dark navy
C_PRIMARY   = colors.HexColor("#16213E")   # deep blue
C_ACCENT    = colors.HexColor("#0F3460")   # mid blue
C_HIGHLIGHT = colors.HexColor("#E94560")   # red accent
C_GREEN     = colors.HexColor("#2ECC71")   # clean/safe
C_ORANGE    = colors.HexColor("#E67E22")   # warning
C_YELLOW    = colors.HexColor("#F39C12")   # medium risk
C_LIGHT     = colors.HexColor("#F5F5F5")   # light bg
C_WHITE     = colors.white
C_GREY      = colors.HexColor("#7F8C8D")
C_BORDER    = colors.HexColor("#BDC3C7")

RISK_COLORS = {
    "CRITICAL": C_HIGHLIGHT,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_YELLOW,
    "LOW":      C_GREEN,
}

RISK_ICONS = {
    "CRITICAL": "CRITICAL",
    "HIGH":     "HIGH",
    "MEDIUM":   "MEDIUM",
    "LOW":      "LOW",
}

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm


# ─────────────────────────────────────────────
# FEATURE EXTRACTION  (self-contained)
# ─────────────────────────────────────────────

def safe_float(v, d=0.0):
    try: return float(v)
    except: return d

def encode_header(h):
    m = re.search(r'PDF-([\d.]+)', str(h))
    try: return float(m.group(1)) if m else 0.0
    except: return 0.0

def file_hash(path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def count_kw(data, kw):
    return len(re.findall(kw, data))

def extract_raw_features(path):
    with open(path, "rb") as f:
        data = f.read()
    feat = {}
    feat["pdfsize"]      = round(os.path.getsize(path) / 1024, 2)
    m = re.search(rb'(%PDF-[\d.\\x]+)', data[:1024])
    feat["header"]       = m.group(1).decode(errors="replace").strip() if m else "unknown"
    vm = re.search(r'PDF-([\d.]+)', feat["header"])
    feat["pdf_version"]  = float(vm.group(1)) if vm else 0.0
    feat["obj"]          = count_kw(data, rb'\bobj\b')
    feat["endobj"]       = count_kw(data, rb'\bendobj\b')
    feat["stream"]       = count_kw(data, rb'\bstream\b')
    feat["endstream"]    = count_kw(data, rb'\bendstream\b')
    feat["xref"]         = count_kw(data, rb'\bxref\b')
    feat["trailer"]      = count_kw(data, rb'\btrailer\b')
    feat["startxref"]    = count_kw(data, rb'\bstartxref\b')
    feat["pageno"]       = count_kw(data, rb'/Page\b')
    feat["encrypt"]      = count_kw(data, rb'/Encrypt\b')
    feat["ObjStm"]       = count_kw(data, rb'/ObjStm\b')
    feat["JS"]           = count_kw(data, rb'/JS\b')
    feat["Javascript"]   = count_kw(data, rb'/JavaScript\b')
    feat["AA"]           = count_kw(data, rb'/AA\b')
    feat["OpenAction"]   = count_kw(data, rb'/OpenAction\b')
    feat["Acroform"]     = count_kw(data, rb'/AcroForm\b')
    feat["JBIG2Decode"]  = count_kw(data, rb'/JBIG2Decode\b')
    feat["RichMedia"]    = count_kw(data, rb'/RichMedia\b')
    feat["launch"]       = count_kw(data, rb'/Launch\b')
    feat["EmbeddedFile"] = count_kw(data, rb'/EmbeddedFile\b')
    feat["XFA"]          = count_kw(data, rb'/XFA\b')
    feat["Colors"]       = count_kw(data, rb'/Colors\b')
    meta_m = re.search(rb'<<(.{0,2000}?)>>', data[:8192], re.DOTALL)
    feat["metadata size"]  = len(meta_m.group(0)) if meta_m else 0
    xref_m = re.search(rb'xref\s+\d+\s+(\d+)', data)
    feat["xref Length"]    = int(xref_m.group(1)) if xref_m else 0
    title_m = re.search(rb'/Title\s*\(([^)]*)\)', data)
    feat["title characters"] = len(title_m.group(1)) if title_m else 0
    feat["embedded files"] = feat["EmbeddedFile"]
    feat["images"]         = count_kw(data, rb'/Image\b')
    feat["isEncrypted"]    = 1 if b'/Encrypt' in data else 0
    feat["pages"]          = count_kw(data, rb'/Type\s*/Page\b')
    try:
        r = subprocess.run(["pdfinfo", path], capture_output=True, text=True, timeout=8)
        pm = re.search(r'Pages:\s+(\d+)', r.stdout)
        if pm: feat["pages"] = int(pm.group(1))
        em = re.search(r'Encrypted:\s+(\w+)', r.stdout)
        if em: feat["isEncrypted"] = 1 if em.group(1).lower() == "yes" else 0
    except Exception:
        pass
    ts = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', data[:50000], re.DOTALL)
    feat["text_encoded"] = 1 if any(b'BT' in s and b'ET' in s for s in ts) else 0

    # Extract PDF metadata strings
    author_m  = re.search(rb'/Author\s*\(([^)]*)\)', data)
    creator_m = re.search(rb'/Creator\s*\(([^)]*)\)', data)
    subject_m = re.search(rb'/Subject\s*\(([^)]*)\)', data)
    title_str = re.search(rb'/Title\s*\(([^)]*)\)', data)
    feat["meta_author"]  = author_m.group(1).decode(errors="replace")  if author_m  else "N/A"
    feat["meta_creator"] = creator_m.group(1).decode(errors="replace") if creator_m else "N/A"
    feat["meta_subject"] = subject_m.group(1).decode(errors="replace") if subject_m else "N/A"
    feat["meta_title"]   = title_str.group(1).decode(errors="replace") if title_str else "N/A"

    return feat, data


FEATURE_ORDER = [
    "pdfsize","metadata size","pages","xref Length","title characters",
    "isEncrypted","embedded files","images",
    "obj","endobj","stream","endstream","xref","trailer","startxref",
    "pageno","encrypt","ObjStm","JS","Javascript","AA","OpenAction",
    "Acroform","JBIG2Decode","RichMedia","launch","EmbeddedFile","XFA","Colors",
    "text_encoded","pdf_version",
]

THREAT_KEYWORDS = {
    "JS":           ("Inline JavaScript",           "CRITICAL", "Code Execution"),
    "Javascript":   ("JavaScript Action",           "CRITICAL", "Code Execution"),
    "OpenAction":   ("Auto-Execute on Open",        "CRITICAL", "Code Execution"),
    "AA":           ("Additional Actions",          "HIGH",     "Code Execution"),
    "launch":       ("Launch External Program",     "CRITICAL", "Command Execution"),
    "JBIG2Decode":  ("JBIG2 Heap Overflow",         "CRITICAL", "Memory Exploit"),
    "RichMedia":    ("Rich Media Exploit",          "HIGH",     "Media Exploit"),
    "XFA":          ("XML Forms Architecture",      "HIGH",     "Form Exploit"),
    "ObjStm":       ("Object Stream Obfuscation",   "MEDIUM",   "Obfuscation"),
    "EmbeddedFile": ("Embedded File Payload",       "HIGH",     "Payload Delivery"),
    "encrypt":      ("Encryption (Content Hidden)", "MEDIUM",   "Obfuscation"),
    "Acroform":     ("AcroForm (JS-enabled Form)",  "MEDIUM",   "Code Execution"),
}


# ─────────────────────────────────────────────
# ML PREDICTION
# ─────────────────────────────────────────────

def run_ml_prediction(feat_dict, model_dir):
    try:
        import joblib
    except ImportError:
        return None

    files = {
        "imputer": os.path.join(model_dir, "imputer.pkl"),
        "scaler":  os.path.join(model_dir, "scaler.pkl"),
    }
    if not all(os.path.isfile(p) for p in files.values()):
        return None

    imputer = joblib.load(files["imputer"])
    scaler  = joblib.load(files["scaler"])

    model_files = {
        "Random Forest":    "rf_model.pkl",
        "Decision Tree":    "dt_model.pkl",
        "SVM":              "svm_model.pkl",
        "Isolation Forest": "isolation_forest.pkl",
    }

    vec = [safe_float(feat_dict.get(c, 0)) for c in FEATURE_ORDER]
    X   = np.array([vec], dtype=np.float32)
    Xi  = imputer.transform(X)
    Xs  = scaler.transform(Xi)

    results = {}
    for name, fname in model_files.items():
        fpath = os.path.join(model_dir, fname)
        if not os.path.isfile(fpath):
            continue
        model = joblib.load(fpath)
        pred  = model.predict(Xs)[0]

        if name == "Isolation Forest":
            label    = 1 if pred == -1 else 0
            sc_raw   = model.decision_function(Xs)[0]
            prob_mal = float(1 / (1 + np.exp(sc_raw)))
            results[name] = {"label": label, "prob_mal": prob_mal,
                             "prob_ben": 1 - prob_mal, "anomaly": float(sc_raw)}
        else:
            prob = model.predict_proba(Xs)[0]
            results[name] = {"label": int(pred), "prob_mal": float(prob[1]),
                             "prob_ben": float(prob[0]), "anomaly": None}

    return results


def compute_verdict(ml_results, threats_found):
    if not ml_results:
        return "UNKNOWN", "LOW", 0.5
    sup = ["Random Forest", "Decision Tree", "SVM"]
    votes = [ml_results[m]["label"] for m in sup if m in ml_results]
    mal_votes = sum(votes)
    verdict = "MALICIOUS" if mal_votes >= 2 else "BENIGN"
    rf_conf = ml_results.get("Random Forest", {}).get("prob_mal", 0.5)

    score = rf_conf * 40 + len(threats_found) * 10
    crit  = {"JS","Javascript","OpenAction","launch","JBIG2Decode"}
    if any(t in crit for t in threats_found): score += 20

    if score >= 75:   risk = "CRITICAL"
    elif score >= 50: risk = "HIGH"
    elif score >= 25: risk = "MEDIUM"
    else:             risk = "LOW"

    return verdict, risk, rf_conf


# ─────────────────────────────────────────────
# REPORT STYLES
# ─────────────────────────────────────────────

def make_styles():
    base = getSampleStyleSheet()

    def style(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "title": style("RTitle",
            fontSize=28, textColor=C_WHITE, fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=8),

        "subtitle": style("RSub",
            fontSize=13, textColor=colors.HexColor("#B0C4DE"),
            fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4),

        "section": style("RSec",
            fontSize=14, textColor=C_ACCENT, fontName="Helvetica-Bold",
            spaceBefore=14, spaceAfter=6,
            borderPad=4),

        "body": style("RBody",
            fontSize=9.5, textColor=C_DARK, fontName="Helvetica",
            leading=15, spaceAfter=4, alignment=TA_JUSTIFY),

        "body_bold": style("RBold",
            fontSize=9.5, textColor=C_DARK, fontName="Helvetica-Bold",
            leading=15, spaceAfter=4),

        "small": style("RSmall",
            fontSize=8, textColor=C_GREY, fontName="Helvetica",
            leading=12, spaceAfter=2),

        "code": style("RCode",
            fontSize=8, textColor=C_DARK, fontName="Courier",
            leading=12, spaceAfter=2, backColor=C_LIGHT,
            leftIndent=8, rightIndent=8),

        "verdict_mal": style("RVerdMal",
            fontSize=22, textColor=C_HIGHLIGHT, fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=4),

        "verdict_ben": style("RVerdBen",
            fontSize=22, textColor=C_GREEN, fontName="Helvetica-Bold",
            alignment=TA_CENTER, spaceAfter=4),

        "caption": style("RCaption",
            fontSize=8, textColor=C_GREY, fontName="Helvetica-Oblique",
            alignment=TA_CENTER, spaceAfter=8),

        "footer": style("RFoot",
            fontSize=7.5, textColor=C_GREY, fontName="Helvetica",
            alignment=TA_CENTER),
    }


# ─────────────────────────────────────────────
# PAGE TEMPLATE  (header + footer on every page)
# ─────────────────────────────────────────────

class ForensicPageTemplate:
    def __init__(self, filename, verdict, risk):
        self.filename = filename
        self.verdict  = verdict
        self.risk     = risk
        self.total    = 0

    def __call__(self, canvas, doc):
        canvas.saveState()
        w, h = A4
        page = doc.page

        # ── Header bar ──────────────────────────────────────────
        canvas.setFillColor(C_PRIMARY)
        canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(C_WHITE)
        canvas.drawString(MARGIN, h - 0.8*cm, "PDF MALWARE FORENSIC REPORT")
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(w - MARGIN, h - 0.8*cm, f"File: {self.filename}")

        # ── Footer bar ──────────────────────────────────────────
        canvas.setFillColor(C_LIGHT)
        canvas.rect(0, 0, w, 1.0*cm, fill=1, stroke=0)
        canvas.setStrokeColor(C_BORDER)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, 1.0*cm, w - MARGIN, 1.0*cm)

        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C_GREY)
        canvas.drawString(MARGIN, 0.35*cm,
            "FYP: Integrated AI System for PDF Malware Detection | MUET Cyber Security")
        canvas.drawRightString(w - MARGIN, 0.35*cm, f"Page {page}")

        # Risk badge on every page (top right corner of content)
        risk_col = RISK_COLORS.get(self.risk, C_GREY)
        bx, by = w - MARGIN - 2.5*cm, h - 2.0*cm
        canvas.setFillColor(risk_col)
        canvas.roundRect(bx, by, 2.5*cm, 0.55*cm, 3, fill=1, stroke=0)
        canvas.setFillColor(C_WHITE)
        canvas.setFont("Helvetica-Bold", 7.5)
        canvas.drawCentredString(bx + 1.25*cm, by + 0.15*cm, self.risk)

        canvas.restoreState()


# ─────────────────────────────────────────────
# COVER PAGE
# ─────────────────────────────────────────────

def make_cover(styles, filename, verdict, risk, rf_conf, generated_at):
    story = []
    w     = PAGE_W - 2 * MARGIN
    risk_col = RISK_COLORS.get(risk, C_GREY)

    # Big coloured header block
    def header_block():
        d = Drawing(w, 7*cm)
        d.add(Rect(0, 0, w, 7*cm, fillColor=C_PRIMARY, strokeColor=None))
        d.add(Rect(0, 0, w, 0.4*cm, fillColor=C_HIGHLIGHT, strokeColor=None))

        title = String(w/2, 5.2*cm, "PDF FORENSIC ANALYSIS REPORT",
                       fontSize=20, fontName="Helvetica-Bold",
                       fillColor=colors.white, textAnchor="middle")
        sub   = String(w/2, 4.4*cm,
                       "Integrated AI System for PDF Malware Detection",
                       fontSize=11, fontName="Helvetica",
                       fillColor=colors.HexColor("#B0C4DE"), textAnchor="middle")
        team  = String(w/2, 3.5*cm,
                       "Bilawal Ali (22BSCYS002) & Sagar (22BSCYS049)",
                       fontSize=9, fontName="Helvetica",
                       fillColor=colors.HexColor("#90A4AE"), textAnchor="middle")
        dept  = String(w/2, 2.9*cm,
                       "BS Cyber Security | MUET | Supervisor: Engr. Mehran Mamonai",
                       fontSize=8.5, fontName="Helvetica",
                       fillColor=colors.HexColor("#90A4AE"), textAnchor="middle")
        d.add(title); d.add(sub); d.add(team); d.add(dept)
        return d

    story.append(header_block())
    story.append(Spacer(1, 0.8*cm))

    # File info box
    file_data = [
        ["Analysed File", filename],
        ["Generated",     generated_at],
        ["Report Type",   "Full Forensic Analysis"],
    ]
    file_tbl = Table(file_data, colWidths=[3.5*cm, w - 3.5*cm])
    file_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), C_ACCENT),
        ("TEXTCOLOR",  (0,0), (0,-1), C_WHITE),
        ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",   (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (1,0), (1,-1), [C_LIGHT, C_WHITE]),
        ("GRID", (0,0), (-1,-1), 0.3, C_BORDER),
        ("PADDING", (0,0), (-1,-1), 7),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]))
    story.append(file_tbl)
    story.append(Spacer(1, 0.8*cm))

    # Verdict block
    verdict_col = C_HIGHLIGHT if verdict == "MALICIOUS" else C_GREEN
    verdict_txt = f"VERDICT:  {verdict}"
    verd_data = [[verdict_txt]]
    verd_tbl  = Table(verd_data, colWidths=[w])
    verd_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), verdict_col),
        ("TEXTCOLOR",  (0,0), (-1,-1), C_WHITE),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 20),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("PADDING",    (0,0), (-1,-1), 16),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(verd_tbl)
    story.append(Spacer(1, 0.5*cm))

    # Risk + Confidence side by side
    risk_data = [
        [f"Risk Level: {risk}", f"RF Confidence: {rf_conf*100:.1f}%"],
    ]
    risk_tbl = Table(risk_data, colWidths=[w/2, w/2])
    risk_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,0), risk_col),
        ("BACKGROUND", (1,0), (1,0), C_ACCENT),
        ("TEXTCOLOR",  (0,0), (-1,-1), C_WHITE),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 13),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("PADDING",    (0,0), (-1,-1), 12),
    ]))
    story.append(risk_tbl)
    story.append(Spacer(1, 0.8*cm))

    # Confidentiality notice
    notice_data = [[
        "CONFIDENTIAL — This report is generated by the FYP AI-based PDF Malware "
        "Detection System. It is intended for cybersecurity research and academic "
        "purposes only. All findings are based on static analysis and ML model "
        "predictions and should be verified by a qualified security analyst."
    ]]
    notice_tbl = Table(notice_data, colWidths=[w])
    notice_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#FFF3CD")),
        ("TEXTCOLOR",  (0,0), (-1,-1), colors.HexColor("#856404")),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Oblique"),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("PADDING",    (0,0), (-1,-1), 10),
        ("BOX",        (0,0), (-1,-1), 0.5, colors.HexColor("#FFEAA7")),
    ]))
    story.append(notice_tbl)
    story.append(PageBreak())
    return story


# ─────────────────────────────────────────────
# SECTION BUILDERS
# ─────────────────────────────────────────────

def section_header(title, styles):
    w = PAGE_W - 2 * MARGIN
    tbl = Table([[title]], colWidths=[w])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_ACCENT),
        ("TEXTCOLOR",  (0,0), (-1,-1), C_WHITE),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 11),
        ("PADDING",    (0,0), (-1,-1), 8),
        ("LEFTPADDING",(0,0), (-1,-1), 12),
    ]))
    return [tbl, Spacer(1, 0.3*cm)]


def kv_table(rows, col_widths=None, styles=None):
    """Two-column key-value table."""
    w = PAGE_W - 2 * MARGIN
    if col_widths is None:
        col_widths = [4*cm, w - 4*cm]
    tbl = Table(rows, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ("FONTNAME",      (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",      (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE",      (0,0), (-1,-1), 8.5),
        ("ROWBACKGROUNDS",(0,0), (-1,-1), [C_LIGHT, C_WHITE]),
        ("GRID",          (0,0), (-1,-1), 0.3, C_BORDER),
        ("PADDING",       (0,0), (-1,-1), 6),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
        ("TEXTCOLOR",     (0,0), (0,-1), C_ACCENT),
    ]))
    return tbl


def make_bar_chart(labels, values, colors_list, title="", w=14*cm, h=5*cm):
    """Simple horizontal-style bar chart via Drawing."""
    d     = Drawing(w, h + 1*cm)
    max_v = max(values) if values else 1
    bar_h = (h - 1.5*cm) / len(values)
    bar_h = min(bar_h, 0.8*cm)

    for i, (label, val, col) in enumerate(zip(labels, values, colors_list)):
        y   = h - (i + 1) * (bar_h + 0.15*cm)
        bar = val / max_v * (w - 4.5*cm)

        # Background track
        d.add(Rect(4*cm, y, w - 4.5*cm, bar_h,
                   fillColor=colors.HexColor("#ECF0F1"), strokeColor=None))
        # Value bar
        if bar > 0:
            d.add(Rect(4*cm, y, bar, bar_h, fillColor=col, strokeColor=None))

        # Label
        d.add(String(0, y + bar_h * 0.25, label,
                     fontSize=7.5, fontName="Helvetica", fillColor=C_DARK))
        # Value text
        d.add(String(4*cm + bar + 3, y + bar_h * 0.25,
                     f"{val:.1%}" if val <= 1 else str(int(val)),
                     fontSize=7, fontName="Helvetica-Bold", fillColor=C_DARK))

    if title:
        d.add(String(w/2, h + 0.3*cm, title,
                     fontSize=9, fontName="Helvetica-Bold",
                     fillColor=C_ACCENT, textAnchor="middle"))
    return d


# ─────────────────────────────────────────────
# REPORT SECTIONS
# ─────────────────────────────────────────────

def section_executive_summary(styles, verdict, risk, rf_conf,
                               threats_found, feat, ml_results):
    story = []
    story += section_header("1. EXECUTIVE SUMMARY", styles)

    risk_col = RISK_COLORS.get(risk, C_GREY)
    verdict_str = "MALICIOUS" if verdict == "MALICIOUS" else "BENIGN (SAFE)"

    summary_rows = [
        ["Verdict",           verdict_str],
        ["Risk Level",        risk],
        ["RF Confidence",     f"{rf_conf*100:.2f}%"],
        ["Threats Detected",  str(len(threats_found))],
        ["File Size",         f"{feat.get('pdfsize','N/A')} KB"],
        ["Pages",             str(feat.get('pages', 'N/A'))],
        ["Encrypted",         "Yes" if feat.get("isEncrypted") else "No"],
        ["PDF Version",       feat.get("header", "N/A")],
    ]
    story.append(kv_table(summary_rows, styles=styles))
    story.append(Spacer(1, 0.4*cm))

    # Narrative
    if verdict == "MALICIOUS":
        narrative = (
            f"This PDF file has been classified as <b>MALICIOUS</b> with a risk level of "
            f"<b>{risk}</b>. The AI-based detection system identified {len(threats_found)} "
            f"threat indicator(s) within the file's structure. The primary model (Random Forest) "
            f"reports a malicious probability of {rf_conf*100:.1f}%. "
            f"This file should be quarantined immediately and must not be opened in a "
            f"standard PDF viewer. A remediated clean copy can be generated using the "
            f"Remediation Module."
        )
    else:
        narrative = (
            f"This PDF file has been classified as <b>BENIGN</b> with a risk level of "
            f"<b>{risk}</b>. The AI-based detection system did not identify significant "
            f"threat indicators within the file's structure. The primary model (Random Forest) "
            f"reports a benign probability of {(1-rf_conf)*100:.1f}%. "
            f"Standard precautions are still recommended when handling files from unknown sources."
        )

    story.append(Paragraph(narrative, styles["body"]))
    story.append(PageBreak())
    return story


def section_file_identification(styles, path, feat):
    story = []
    story += section_header("2. FILE IDENTIFICATION", styles)

    rows = [
        ["Filename",    Path(path).name],
        ["Full Path",   path],
        ["Size",        f"{feat.get('pdfsize','N/A')} KB  ({os.path.getsize(path):,} bytes)"],
        ["SHA-256",     file_hash(path, "sha256")],
        ["MD5",         file_hash(path, "md5")],
        ["SHA-1",       file_hash(path, "sha1")],
        ["PDF Version", feat.get("header", "N/A")],
        ["Encrypted",   "Yes" if feat.get("isEncrypted") else "No"],
        ["Pages",       str(feat.get("pages", "N/A"))],
        ["Title",       feat.get("meta_title", "N/A") or "N/A"],
        ["Author",      feat.get("meta_author", "N/A") or "N/A"],
        ["Creator",     feat.get("meta_creator", "N/A") or "N/A"],
        ["Subject",     feat.get("meta_subject", "N/A") or "N/A"],
        ["Analysed At", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
    ]

    w = PAGE_W - 2 * MARGIN
    tbl = Table(rows, colWidths=[3.5*cm, w - 3.5*cm])
    tbl.setStyle(TableStyle([
        ("FONTNAME",       (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME",       (1,0), (1,-1), "Courier"),
        ("FONTSIZE",       (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_LIGHT, C_WHITE]),
        ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
        ("PADDING",        (0,0), (-1,-1), 6),
        ("TEXTCOLOR",      (0,0), (0,-1), C_ACCENT),
        ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
        # Highlight hash rows
        ("BACKGROUND",     (0,1), (-1,3), colors.HexColor("#EBF5FB")),
        ("TEXTCOLOR",      (1,1), (1,3),  C_DARK),
    ]))
    story.append(tbl)
    story.append(PageBreak())
    return story


def section_ml_analysis(styles, ml_results, verdict, risk):
    story = []
    story += section_header("3. ML MODEL ANALYSIS", styles)

    if not ml_results:
        story.append(Paragraph("No trained models found. Run compare_models.py first.",
                               styles["body"]))
        story.append(PageBreak())
        return story

    w = PAGE_W - 2 * MARGIN

    # Results table
    header = ["Model", "Type", "Verdict", "P(Malicious)", "P(Benign)", "Anomaly Score"]
    rows   = [header]
    sup    = {"Random Forest","Decision Tree","SVM"}

    for name, r in ml_results.items():
        mtype   = "Supervised" if name in sup else "Unsupervised"
        verdict_cell = "MALICIOUS" if r["label"] == 1 else "BENIGN"
        anom    = f"{r['anomaly']:.4f}" if r["anomaly"] is not None else "N/A"
        rows.append([
            name, mtype, verdict_cell,
            f"{r['prob_mal']*100:.2f}%",
            f"{r['prob_ben']*100:.2f}%",
            anom,
        ])

    col_w = [3.8*cm, 2.5*cm, 2.3*cm, 2.5*cm, 2.3*cm, 2.5*cm]
    tbl   = Table(rows, colWidths=col_w)

    style_cmds = [
        ("BACKGROUND",  (0,0), (-1,0), C_PRIMARY),
        ("TEXTCOLOR",   (0,0), (-1,0), C_WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.3, C_BORDER),
        ("PADDING",     (0,0), (-1,-1), 6),
        ("ALIGN",       (1,0), (-1,-1), "CENTER"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_LIGHT, C_WHITE]),
    ]
    # Colour the verdict cells
    for i, (name, r) in enumerate(ml_results.items(), 1):
        col = C_HIGHLIGHT if r["label"] == 1 else C_GREEN
        style_cmds.append(("TEXTCOLOR", (2,i), (2,i), col))
        style_cmds.append(("FONTNAME",  (2,i), (2,i), "Helvetica-Bold"))

    tbl.setStyle(TableStyle(style_cmds))
    story.append(tbl)
    story.append(Spacer(1, 0.5*cm))

    # Bar chart — P(Malicious) per model
    labels  = list(ml_results.keys())
    values  = [r["prob_mal"] for r in ml_results.values()]
    sup_set = {"Random Forest","Decision Tree","SVM"}
    cols    = [C_HIGHLIGHT if v > 0.5 else C_GREEN for v in values]

    chart = make_bar_chart(labels, values, cols,
                           title="P(Malicious) per Model", w=w, h=5.5*cm)
    story.append(chart)
    story.append(Paragraph(
        "Figure 1: Probability of malicious classification across all models. "
        "Values above 50% indicate a malicious prediction.",
        styles["caption"]))

    # Majority vote summary
    sup_votes = sum(1 for n, r in ml_results.items() if n in sup_set and r["label"]==1)
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(
        f"<b>Majority Vote Result:</b> {sup_votes}/3 supervised models classify "
        f"this file as MALICIOUS. Final verdict: <b>{verdict}</b>.",
        styles["body"]))
    story.append(PageBreak())
    return story


def section_threat_analysis(styles, feat, threats_found):
    story = []
    story += section_header("4. THREAT INDICATOR ANALYSIS", styles)

    w = PAGE_W - 2 * MARGIN

    if not threats_found:
        story.append(Paragraph(
            "No threat indicators were detected in this PDF file.",
            styles["body"]))
        story.append(PageBreak())
        return story

    # Threat table
    header = ["Indicator", "Count", "Severity", "Attack Type", "Description"]
    rows   = [header]
    for t in threats_found:
        info  = THREAT_KEYWORDS.get(t, (t, "MEDIUM", "Unknown"))
        count = feat.get(t, 0)
        rows.append([t, str(count), info[1], info[2], info[0]])

    col_w = [2.5*cm, 1.3*cm, 1.8*cm, 3.2*cm, w - 8.8*cm]
    tbl   = Table(rows, colWidths=col_w)

    sev_colors = {"CRITICAL": C_HIGHLIGHT, "HIGH": C_ORANGE,
                  "MEDIUM": C_YELLOW, "LOW": C_GREEN}
    style_cmds = [
        ("BACKGROUND",  (0,0), (-1,0), C_PRIMARY),
        ("TEXTCOLOR",   (0,0), (-1,0), C_WHITE),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.3, C_BORDER),
        ("PADDING",     (0,0), (-1,-1), 6),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_LIGHT, C_WHITE]),
        ("FONTNAME",    (0,1), (0,-1), "Helvetica-Bold"),
    ]
    for i, t in enumerate(threats_found, 1):
        info  = THREAT_KEYWORDS.get(t, (t, "MEDIUM", "Unknown"))
        col   = sev_colors.get(info[1], C_GREY)
        style_cmds += [
            ("TEXTCOLOR",  (2,i), (2,i), col),
            ("FONTNAME",   (2,i), (2,i), "Helvetica-Bold"),
        ]
    tbl.setStyle(TableStyle(style_cmds))
    story.append(tbl)
    story.append(Spacer(1, 0.4*cm))

    # Severity breakdown
    sev_count = Counter(THREAT_KEYWORDS.get(t, (t,"MEDIUM",""))[1]
                        for t in threats_found)
    story.append(Paragraph("<b>Severity Breakdown:</b>", styles["body_bold"]))
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
        if sev in sev_count:
            col_hex = {
                "CRITICAL":"#E94560","HIGH":"#E67E22",
                "MEDIUM":"#F39C12","LOW":"#2ECC71"
            }[sev]
            story.append(Paragraph(
                f'<font color="{col_hex}">■</font>  '
                f'<b>{sev}</b>: {sev_count[sev]} indicator(s)',
                styles["body"]))

    story.append(Spacer(1, 0.4*cm))
    story.append(Paragraph(
        "<b>Attack Vector Summary:</b> The threat indicators found suggest this "
        "PDF may attempt one or more of the following attack techniques:",
        styles["body"]))

    attack_types = set(THREAT_KEYWORDS.get(t, (t,"","Unknown"))[2]
                       for t in threats_found)
    for at in sorted(attack_types):
        story.append(Paragraph(f"• {at}", styles["body"]))

    story.append(PageBreak())
    return story


def section_structural_analysis(styles, feat):
    story = []
    story += section_header("5. STRUCTURAL ANALYSIS", styles)

    story.append(Paragraph(
        "The following table shows the raw structural features extracted from "
        "the PDF's internal object tree. These features were used as input to "
        "the ML classification models.",
        styles["body"]))
    story.append(Spacer(1, 0.3*cm))

    groups = {
        "File Properties": [
            ("File Size (KB)",     feat.get("pdfsize")),
            ("Pages",              feat.get("pages")),
            ("PDF Version",        feat.get("header")),
            ("Encrypted",          "Yes" if feat.get("isEncrypted") else "No"),
            ("Has Text",           "Yes" if feat.get("text_encoded") else "No"),
            ("Images",             feat.get("images")),
            ("Embedded Files",     feat.get("embedded files")),
        ],
        "Object Structure": [
            ("Objects (obj)",      feat.get("obj")),
            ("End Objects",        feat.get("endobj")),
            ("Streams",            feat.get("stream")),
            ("End Streams",        feat.get("endstream")),
            ("XRef Tables",        feat.get("xref")),
            ("XRef Length",        feat.get("xref Length")),
            ("Trailers",           feat.get("trailer")),
            ("StartXRef",          feat.get("startxref")),
            ("Page Objects",       feat.get("pageno")),
            ("Metadata Size",      feat.get("metadata size")),
            ("Title Characters",   feat.get("title characters")),
        ],
        "Active Content": [
            ("JavaScript /JS",     feat.get("JS")),
            ("JavaScript Action",  feat.get("Javascript")),
            ("OpenAction",         feat.get("OpenAction")),
            ("Additional Actions", feat.get("AA")),
            ("Launch",             feat.get("launch")),
            ("Object Streams",     feat.get("ObjStm")),
            ("JBIG2Decode",        feat.get("JBIG2Decode")),
            ("RichMedia",          feat.get("RichMedia")),
            ("XFA",                feat.get("XFA")),
            ("AcroForm",           feat.get("Acroform")),
            ("EmbeddedFile",       feat.get("EmbeddedFile")),
            ("Encrypt Obj",        feat.get("encrypt")),
            ("Colors",             feat.get("Colors")),
        ],
    }

    w = PAGE_W - 2 * MARGIN

    for group_name, fields in groups.items():
        story.append(Paragraph(f"<b>{group_name}</b>", styles["body_bold"]))
        rows = [[k, str(v) if v is not None else "0"] for k, v in fields]
        tbl  = Table(rows, colWidths=[5*cm, w - 5*cm])
        tbl.setStyle(TableStyle([
            ("FONTNAME",       (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTNAME",       (1,0), (1,-1), "Helvetica"),
            ("FONTSIZE",       (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_LIGHT, C_WHITE]),
            ("GRID",           (0,0), (-1,-1), 0.3, C_BORDER),
            ("PADDING",        (0,0), (-1,-1), 5),
            ("TEXTCOLOR",      (0,0), (0,-1), C_ACCENT),
        ]))

        # Highlight non-zero active content
        if group_name == "Active Content":
            for i, (k, v) in enumerate(fields):
                if v and str(v) not in ("0", "0.0", "None", ""):
                    tbl.setStyle(TableStyle([
                        ("BACKGROUND", (0,i), (-1,i), colors.HexColor("#FDEDEC")),
                        ("TEXTCOLOR",  (1,i), (1,i),  C_HIGHLIGHT),
                        ("FONTNAME",   (1,i), (1,i),  "Helvetica-Bold"),
                    ]))

        story.append(tbl)
        story.append(Spacer(1, 0.3*cm))

    story.append(PageBreak())
    return story


def section_remediation(styles, remediation_data):
    story = []
    story += section_header("6. REMEDIATION SUMMARY", styles)

    if not remediation_data:
        story.append(Paragraph(
            "No remediation has been performed on this file. "
            "To sanitize this PDF, run:\n\n"
            "    python remediate.py suspicious.pdf",
            styles["body"]))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            "The remediation module will strip all active/executable content "
            "while preserving the document's readable text and images.",
            styles["body"]))
        story.append(PageBreak())
        return story

    rem = remediation_data.get("remediation", {})
    thr = remediation_data.get("threats", {})
    siz = remediation_data.get("size_reduction", {})

    rows = [
        ["Status",          "FULLY CLEAN" if rem.get("is_clean") else "PARTIALLY CLEANED"],
        ["Method",          rem.get("method","N/A")],
        ["Duration",        f"{rem.get('duration_s','N/A')}s"],
        ["Items Removed",   str(rem.get("items_removed", 0))],
        ["Size Before",     f"{siz.get('original_kb','N/A')} KB"],
        ["Size After",      f"{siz.get('cleaned_kb','N/A')} KB"],
        ["Size Reduction",  f"{siz.get('reduction_pct','N/A')}%"],
    ]
    story.append(kv_table(rows, styles=styles))
    story.append(Spacer(1, 0.4*cm))

    resolved = thr.get("resolved", {})
    remaining = thr.get("remaining", {})

    if resolved:
        story.append(Paragraph("<b>Threats Removed:</b>", styles["body_bold"]))
        for name, count in resolved.items():
            story.append(Paragraph(
                f'<font color="#2ECC71">✓</font>  {name} (was {count}×)',
                styles["body"]))

    if remaining:
        story.append(Spacer(1, 0.2*cm))
        story.append(Paragraph("<b>Threats Remaining:</b>", styles["body_bold"]))
        for name, count in remaining.items():
            story.append(Paragraph(
                f'<font color="#E94560">!</font>  {name} (still {count}×) '
                f'— may be embedded in binary image data',
                styles["body"]))

    story.append(PageBreak())
    return story


def section_recommendations(styles, verdict, risk, threats_found, ml_results):
    story = []
    story += section_header("7. RECOMMENDATIONS & CONCLUSION", styles)

    if verdict == "MALICIOUS":
        recs = [
            ("Immediate Action",
             "Do NOT open this PDF in any standard PDF viewer. Quarantine the file "
             "immediately by moving it to an isolated directory with restricted access."),
            ("Remediation",
             "Run the Remediation Module to generate a sanitized copy: "
             "python remediate.py <filename>. The clean copy will have all "
             "executable content stripped while preserving readable text and images."),
            ("Forensic Preservation",
             "Preserve the original malicious file (with this report) as evidence. "
             "Compute and record all hash values before any modification."),
            ("Incident Response",
             "If this file was already opened, treat the system as potentially "
             "compromised. Isolate the machine, check for suspicious processes, "
             "and review system logs for anomalous activity."),
            ("Threat Intelligence",
             f"The detected indicators ({', '.join(threats_found[:5])}) suggest "
             "potential exploit techniques. Cross-reference with CVE databases "
             "and threat intelligence feeds for known campaigns."),
        ]
    else:
        recs = [
            ("Verification",
             "The file appears benign based on static analysis. However, dynamic "
             "analysis in a sandboxed environment is recommended for complete assurance."),
            ("Source Verification",
             "Always verify the authenticity of PDF files, even if classified as benign. "
             "Check sender identity and digital signatures where available."),
            ("Keep Software Updated",
             "Ensure your PDF reader and operating system are fully patched to protect "
             "against zero-day exploits not covered by static analysis."),
        ]

    for i, (title, text) in enumerate(recs, 1):
        story.append(Paragraph(f"<b>{i}. {title}</b>", styles["body_bold"]))
        story.append(Paragraph(text, styles["body"]))
        story.append(Spacer(1, 0.2*cm))

    story.append(Spacer(1, 0.4*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 0.3*cm))

    # Conclusion
    conclusion = (
        f"<b>Conclusion:</b> Based on combined supervised and unsupervised machine "
        f"learning analysis of {len(FEATURE_ORDER)} structural features, this PDF file "
        f"has been classified as <b>{verdict}</b> with a risk level of <b>{risk}</b>. "
        f"This report was generated by the FYP AI-based PDF Malware Detection System "
        f"developed at MUET, Department of Cyber Security. All findings are based on "
        f"static feature analysis and should be interpreted by a qualified security analyst."
    )
    story.append(Paragraph(conclusion, styles["body"]))
    story.append(Spacer(1, 1*cm))

    # Sign-off box
    w = PAGE_W - 2 * MARGIN
    sign_data = [[
        "Bilawal Ali\n22BSCYS002",
        "Sagar\n22BSCYS049",
        "Engr. Mehran Mamonai\nSupervisor",
    ]]
    sign_tbl = Table(sign_data, colWidths=[w/3]*3)
    sign_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",  (0,0), (-1,-1), 8.5),
        ("ALIGN",     (0,0), (-1,-1), "CENTER"),
        ("VALIGN",    (0,0), (-1,-1), "MIDDLE"),
        ("PADDING",   (0,0), (-1,-1), 12),
        ("BOX",       (0,0), (-1,-1), 0.5, C_BORDER),
        ("INNERGRID", (0,0), (-1,-1), 0.5, C_BORDER),
        ("BACKGROUND",(0,0), (-1,-1), C_LIGHT),
        ("TOPPADDING",(0,0), (-1,-1), 20),
    ]))
    story.append(sign_tbl)
    return story


# ─────────────────────────────────────────────
# MAIN GENERATOR
# ─────────────────────────────────────────────

def generate_report(pdf_path, model_dir="models_comparison",
                    remediation_json=None, out_path=None):

    pdf_path = str(pdf_path)
    if not os.path.isfile(pdf_path):
        print(f"[ERROR] File not found: {pdf_path}")
        return None

    if out_path is None:
        stem    = Path(pdf_path).stem
        out_path = str(Path(pdf_path).parent / f"{stem}_FORENSIC_REPORT.pdf")

    print(f"\n[*] Generating forensic report for: {Path(pdf_path).name}")

    # 1. Extract features
    print("  [1/5] Extracting features...")
    feat, _ = extract_raw_features(pdf_path)

    # 2. ML prediction
    print("  [2/5] Running ML models...")
    ml_results = run_ml_prediction(feat, model_dir)

    # 3. Determine verdict
    threats_found = [k for k in THREAT_KEYWORDS if feat.get(k, 0) > 0]
    verdict, risk, rf_conf = compute_verdict(ml_results, threats_found)

    # 4. Load remediation report if provided
    rem_data = None
    if remediation_json and os.path.isfile(remediation_json):
        with open(remediation_json) as f:
            rem_data = json.load(f)
        print("  [3/5] Loaded remediation report")
    else:
        print("  [3/5] No remediation report provided (skipping section)")

    # 5. Build PDF report
    print("  [4/5] Building PDF report...")
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    styles       = make_styles()

    doc = SimpleDocTemplate(
        out_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=1.8*cm, bottomMargin=1.5*cm,
        title=f"Forensic Report — {Path(pdf_path).name}",
        author="FYP PDF Malware Detection System",
    )

    tmpl  = ForensicPageTemplate(Path(pdf_path).name, verdict, risk)
    story = []

    story += make_cover(styles, Path(pdf_path).name, verdict, risk,
                        rf_conf, generated_at)
    story += section_executive_summary(styles, verdict, risk, rf_conf,
                                       threats_found, feat, ml_results)
    story += section_file_identification(styles, pdf_path, feat)
    story += section_ml_analysis(styles, ml_results, verdict, risk)
    story += section_threat_analysis(styles, feat, threats_found)
    story += section_structural_analysis(styles, feat)
    story += section_remediation(styles, rem_data)
    story += section_recommendations(styles, verdict, risk, threats_found, ml_results)

    doc.build(story, onFirstPage=tmpl, onLaterPages=tmpl)

    print(f"  [5/5] Saved: {out_path}")
    print(f"\n  {'═'*55}")
    print(f"  FORENSIC REPORT GENERATED")
    print(f"  File    : {Path(out_path).name}")
    print(f"  Pages   : 8")
    print(f"  Verdict : {verdict}  |  Risk: {risk}")
    print(f"  Threats : {len(threats_found)}")
    print(f"  {'═'*55}\n")

    return out_path


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Forensic Report Generator — FYP PDF Malware Detection"
    )
    parser.add_argument("pdf", nargs="?", help="PDF file to analyse")
    parser.add_argument("--models",  default="models_comparison",
                        help="Trained models folder (default: models_comparison)")
    parser.add_argument("--remediation-report", metavar="JSON",
                        help="Path to remediation JSON report to include")
    parser.add_argument("--out",     metavar="OUTPUT",
                        help="Output PDF path (default: <name>_FORENSIC_REPORT.pdf)")
    parser.add_argument("--batch",   metavar="FOLDER",
                        help="Generate reports for all PDFs in a folder")
    parser.add_argument("--out-dir", default="forensic_reports",
                        help="Output folder for batch mode")
    args = parser.parse_args()

    if args.batch:
        Path(args.out_dir).mkdir(exist_ok=True)
        pdfs = list(Path(args.batch).rglob("*.pdf"))
        print(f"[*] Generating reports for {len(pdfs)} PDFs...")
        for pdf in pdfs:
            out = str(Path(args.out_dir) / f"{pdf.stem}_FORENSIC_REPORT.pdf")
            generate_report(str(pdf), args.models, None, out)
    elif args.pdf:
        generate_report(args.pdf, args.models, args.remediation_report, args.out)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

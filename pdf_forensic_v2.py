#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         PDF FORENSIC ANALYSER v2  —  Static Forensic Analysis           ║
║                                                                          ║
║  Addresses Objective 4:                                                  ║
║    4.1  Attack type classification                                       ║
║         credential_phishing | drive_by_download | c2_callback |         ║
║         exploit_delivery | dropper | unknown                             ║
║    4.2  YARA rule matching + MalwareBazaar hash lookup                  ║
║    4.3  MITRE ATT&CK mapping (Tactic / Technique IDs)                  ║
║    4.4  Structured JSON forensic report with defined schema              ║
║                                                                          ║
║  Usage                                                                   ║
║    python pdf_forensic.py --pdf sample.pdf                           ║
║    python pdf_forensic.py --pdf sample.pdf --json                    ║
║    python pdf_forensic.py --pdf sample.pdf --out report.json         ║
║    python pdf_forensic.py --batch ./folder --output results.csv      ║
║    python pdf_forensic.py --pdf sample.pdf --no-lookup               ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import csv
import hashlib
import json
import math
import os
import re
import sys
import time
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# ── Optional deps ─────────────────────────────────────────────────────────────
try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    import joblib, numpy as np, pandas as pd
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False

try:
    from feature_extraction import extract_features, is_pdf_file
    _EXTRACTOR_AVAILABLE = True
except ImportError:
    _EXTRACTOR_AVAILABLE = False

try:
    import pikepdf
    _PIKEPDF_AVAILABLE = True
except ImportError:
    _PIKEPDF_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════════
# ANSI HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def _ansi(code, t):
    return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t

RED    = lambda t: _ansi("91", t)
GREEN  = lambda t: _ansi("92", t)
YELLOW = lambda t: _ansi("93", t)
CYAN   = lambda t: _ansi("96", t)
BOLD   = lambda t: _ansi("1",  t)
DIM    = lambda t: _ansi("2",  t)
W = 68


# ═══════════════════════════════════════════════════════════════════════════════
# FORMAL JSON REPORT SCHEMA  (Obj 4.4)
# ═══════════════════════════════════════════════════════════════════════════════

REPORT_SCHEMA_VERSION = "2.0"

# Field definitions for documentation / validation
SCHEMA_FIELDS = {
    "schema_version":    "str  — always '2.0'",
    "file":              "str  — absolute resolved path",
    "filename":          "str  — basename",
    "filesize_bytes":    "int",
    "analysis_time_ms":  "float",
    "timestamp":         "str  — ISO-8601 UTC",
    "hashes": {
        "md5":    "str",
        "sha1":   "str",
        "sha256": "str",
    },
    "pdf_header": {
        "valid":   "bool",
        "version": "str  e.g. '1.6'",
        "offset":  "int  — byte offset of %PDF (>0 means junk prepended)",
    },
    "structural_counts":  "dict[str, int]  — raw keyword counts",
    "global_entropy":     "float  — Shannon bits/byte",
    "metadata":           "dict[str, str|null]",
    "iocs": {
        "urls":           "list[str]",
        "ip_addresses":   "list[str]",
        "domains":        "list[str]",
        "cve_refs":       "list[str]",
        "shellcode_seqs": "int",
        "long_base64":    "int",
    },
    "anomalies":          "list[str]",
    "yara_matches": [
        {
            "rule":      "str",
            "tags":      "list[str]",
            "meta":      "dict",
            "strings":   "list[dict]  — {identifier, offset, data_hex}",
        }
    ],
    "malwarebazaar": {
        "queried":        "bool",
        "found":          "bool",
        "query_error":    "str|null",
        "tags":           "list[str]",
        "file_type":      "str|null",
        "reporter":       "str|null",
        "first_seen":     "str|null",
        "signature":      "str|null",
        "vendor_verdicts":"dict[str, str]",
    },
    "attack_classification": {
        "primary_type":   "str  — one of the ATTACK_TYPES enum",
        "confidence":     "str  — HIGH | MEDIUM | LOW",
        "evidence":       "list[str]",
        "secondary_types":"list[str]",
    },
    "mitre_attack": [
        {
            "tactic":        "str  — e.g. 'Initial Access'",
            "tactic_id":     "str  — e.g. 'TA0001'",
            "technique":     "str  — e.g. 'Spearphishing Attachment'",
            "technique_id":  "str  — e.g. 'T1566.001'",
            "evidence":      "str",
        }
    ],
    "risk_score":         "int  0–100",
    "risk_label":         "str  LOW | MEDIUM | HIGH | CRITICAL",
    "ml_verdict": {
        "available":               "bool",
        "label":                   "str  MALICIOUS | BENIGN",
        "probability_malicious":   "float",
        "probability_benign":      "float",
        "confidence_pct":          "float",
        "model":                   "str",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# YARA RULES  (Obj 4.2)  — compiled inline, no external .yar files needed
# ═══════════════════════════════════════════════════════════════════════════════

YARA_RULES_SOURCE = r"""
rule PDF_JavaScript_Execution {
    meta:
        description = "PDF contains JavaScript execution keywords"
        attack_type = "drive_by_download"
        mitre_technique = "T1059.007"
        severity = "HIGH"
    strings:
        $js1  = "/JavaScript" nocase
        $js2  = "/JS " nocase
        $eval = "eval(" nocase
        $unesc = "unescape(" nocase
        $fromcc = "String.fromCharCode" nocase
    condition:
        uint32(0) == 0x46445025 and  // %PDF
        (($js1 or $js2) and ($eval or $unesc or $fromcc))
}

rule PDF_OpenAction_AutoExec {
    meta:
        description = "PDF auto-executes action on open"
        attack_type = "drive_by_download"
        mitre_technique = "T1204.002"
        severity = "HIGH"
    strings:
        $oa = "/OpenAction" nocase
    condition:
        uint32(0) == 0x46445025 and $oa
}

rule PDF_Launch_Action {
    meta:
        description = "PDF contains /Launch to execute external programs"
        attack_type = "dropper"
        mitre_technique = "T1059"
        severity = "CRITICAL"
    strings:
        $launch = "/Launch" nocase
    condition:
        uint32(0) == 0x46445025 and $launch
}

rule PDF_EmbeddedFile_Drop {
    meta:
        description = "PDF embeds a file — possible dropper"
        attack_type = "dropper"
        mitre_technique = "T1027.002"
        severity = "HIGH"
    strings:
        $ef = "/EmbeddedFile" nocase
    condition:
        uint32(0) == 0x46445025 and $ef
}

rule PDF_SubmitForm_Exfil {
    meta:
        description = "PDF submits form data to external URI — credential phishing"
        attack_type = "credential_phishing"
        mitre_technique = "T1056.003"
        severity = "HIGH"
    strings:
        $sf = "/SubmitForm" nocase
        $uri = "/URI" nocase
    condition:
        uint32(0) == 0x46445025 and $sf and $uri
}

rule PDF_URI_External {
    meta:
        description = "PDF references external URI — possible C2 or phishing"
        attack_type = "c2_callback"
        mitre_technique = "T1071.001"
        severity = "MEDIUM"
    strings:
        $uri1 = "/URI (http" nocase
        $uri2 = "/URI (ftp"  nocase
    condition:
        uint32(0) == 0x46445025 and ($uri1 or $uri2)
}

rule PDF_XFA_Form_Attack {
    meta:
        description = "PDF uses XFA forms — known exploit delivery vector"
        attack_type = "exploit_delivery"
        mitre_technique = "T1203"
        severity = "HIGH"
    strings:
        $xfa = "/XFA" nocase
    condition:
        uint32(0) == 0x46445025 and $xfa
}

rule PDF_Shellcode_Hex {
    meta:
        description = "Shellcode-like hex escape sequences in PDF"
        attack_type = "exploit_delivery"
        mitre_technique = "T1203"
        severity = "CRITICAL"
    strings:
        $sc = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){7,}/
    condition:
        uint32(0) == 0x46445025 and $sc
}

rule PDF_Obfuscated_JS_Unescape {
    meta:
        description = "Obfuscated JavaScript using unescape/eval"
        attack_type = "drive_by_download"
        mitre_technique = "T1027"
        severity = "HIGH"
    strings:
        $unesc  = "unescape(" nocase
        $eval   = "eval(" nocase
        $fromcc = "String.fromCharCode" nocase
    condition:
        uint32(0) == 0x46445025 and
        (($unesc and $eval) or ($fromcc and $eval))
}

rule PDF_Multiple_EOF {
    meta:
        description = "Multiple %%EOF markers — possible polyglot or appended payload"
        attack_type = "exploit_delivery"
        mitre_technique = "T1027.001"
        severity = "MEDIUM"
    strings:
        $eof = "%%EOF"
    condition:
        uint32(0) == 0x46445025 and #eof > 1
}

rule PDF_C2_Callback_Pattern {
    meta:
        description = "PDF contains app.getURL or external callback patterns"
        attack_type = "c2_callback"
        mitre_technique = "T1071.001"
        severity = "HIGH"
    strings:
        $geturl   = "app.getURL" nocase
        $launchurl = "app.launchURL" nocase
        $opendoc  = "app.openDoc" nocase
    condition:
        uint32(0) == 0x46445025 and
        ($geturl or $launchurl or $opendoc)
}

rule PDF_Credential_Form {
    meta:
        description = "PDF appears to collect credentials via AcroForm"
        attack_type = "credential_phishing"
        mitre_technique = "T1056.003"
        severity = "MEDIUM"
    strings:
        $acroform = "/AcroForm" nocase
        $password = "password" nocase wide ascii
        $login    = "login" nocase wide ascii
        $username = "username" nocase wide ascii
    condition:
        uint32(0) == 0x46445025 and $acroform and
        ($password or $login or $username)
}

rule PDF_RichMedia_Flash {
    meta:
        description = "PDF embeds Flash/RichMedia — legacy exploit vector"
        attack_type = "exploit_delivery"
        mitre_technique = "T1203"
        severity = "HIGH"
    strings:
        $rm = "/RichMedia" nocase
    condition:
        uint32(0) == 0x46445025 and $rm
}
"""

# Compile once at module load
_YARA_RULES = None

def _get_yara_rules():
    global _YARA_RULES
    if _YARA_RULES is None and _YARA_AVAILABLE:
        try:
            _YARA_RULES = yara.compile(source=YARA_RULES_SOURCE)
        except Exception as e:
            print(f"  [WARN] YARA compile failed: {e}", file=sys.stderr)
    return _YARA_RULES


def run_yara(data: bytes) -> list[dict]:
    """Run YARA rules against raw PDF bytes. Returns list of match dicts."""
    rules = _get_yara_rules()
    if rules is None:
        return []
    try:
        matches = rules.match(data=data)
    except Exception:
        return []

    results = []
    for m in matches:
        string_hits = []
        for s in m.strings:
            # s is a StringMatch object; instances is a list of StringMatchInstance
            for inst in s.instances:
                string_hits.append({
                    "identifier": s.identifier,
                    "offset":     inst.offset,
                    "data_hex":   inst.matched_data.hex()[:64],
                })
        results.append({
            "rule":    m.rule,
            "tags":    list(m.tags),
            "meta":    dict(m.meta),
            "strings": string_hits,
        })
    return results


# ═══════════════════════════════════════════════════════════════════════════════
# MALWAREBAZAAR HASH LOOKUP  (Obj 4.2)
# ═══════════════════════════════════════════════════════════════════════════════

MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"

def lookup_malwarebazaar(sha256: str, timeout: int = 8) -> dict:
    """
    Query MalwareBazaar for the given SHA-256.
    Returns structured dict with found/not-found and metadata.
    """
    result = {
        "queried":         True,
        "found":           False,
        "query_error":     None,
        "tags":            [],
        "file_type":       None,
        "reporter":        None,
        "first_seen":      None,
        "signature":       None,
        "vendor_verdicts": {},
    }

    if not _REQUESTS_AVAILABLE:
        result["queried"]     = False
        result["query_error"] = "requests library not installed"
        return result

    try:
        resp = requests.post(
            MALWAREBAZAAR_API,
            data={"query": "get_info", "hash": sha256},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()

        if data.get("query_status") == "hash_not_found":
            return result  # found=False, no error

        if data.get("query_status") != "ok":
            result["query_error"] = data.get("query_status", "unknown")
            return result

        info = data.get("data", [{}])[0]
        result["found"]           = True
        result["tags"]            = info.get("tags") or []
        result["file_type"]       = info.get("file_type")
        result["reporter"]        = info.get("reporter")
        result["first_seen"]      = info.get("first_seen")
        result["signature"]       = info.get("signature")
        result["vendor_verdicts"] = info.get("vendor_intel", {})

    except requests.exceptions.Timeout:
        result["query_error"] = "timeout"
    except requests.exceptions.ConnectionError:
        result["query_error"] = "connection_error"
    except Exception as e:
        result["query_error"] = str(e)[:120]

    return result


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK TYPE CLASSIFICATION  (Obj 4.1)
# ═══════════════════════════════════════════════════════════════════════════════

ATTACK_TYPES = [
    "credential_phishing",
    "drive_by_download",
    "c2_callback",
    "exploit_delivery",
    "dropper",
    "unknown",
]

# Scoring rules: (signal_fn, attack_type, points, evidence_str)
def _classify_attack(data: bytes, yara_matches: list, iocs: dict,
                     structural_counts: dict) -> dict:
    """
    Rule-based attack type classification.
    Returns primary type, confidence, evidence list, and secondary types.
    """
    scores: dict[str, int] = {t: 0 for t in ATTACK_TYPES}
    evidence: dict[str, list] = {t: [] for t in ATTACK_TYPES}

    def add(atype, pts, ev):
        scores[atype] += pts
        evidence[atype].append(ev)

    c = structural_counts

    # ── YARA-driven signals ────────────────────────────────────────────────
    for m in yara_matches:
        at = m.get("meta", {}).get("attack_type", "")
        sev = m.get("meta", {}).get("severity", "MEDIUM")
        pts = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(sev, 10)
        if at in scores:
            add(at, pts, f"YARA:{m['rule']}")

    # ── Structural signals ─────────────────────────────────────────────────
    if c.get("/JS+/JavaScript", 0) > 0 or c.get("/OpenAction", 0) > 0:
        add("drive_by_download", 15, "JavaScript/OpenAction present")
    if c.get("/Launch", 0) > 0:
        add("dropper", 25, "/Launch action — executes external program")
    if c.get("/EmbeddedFile", 0) > 0:
        add("dropper", 20, "/EmbeddedFile — drops payload")
    if c.get("/XFA", 0) > 0:
        add("exploit_delivery", 15, "/XFA form exploit vector")
    if c.get("/RichMedia", 0) > 0:
        add("exploit_delivery", 20, "/RichMedia (Flash) exploit vector")
    if c.get("/AcroForm", 0) > 0:
        # AcroForm alone isn't malicious; weight by whether SubmitForm is present
        if c.get("/SubmitForm", 0) > 0:
            add("credential_phishing", 25, "AcroForm + /SubmitForm — data exfiltration")
        else:
            add("credential_phishing", 5, "AcroForm present")

    # ── IOC signals ────────────────────────────────────────────────────────
    urls = iocs.get("urls", [])
    ips  = iocs.get("ip_addresses", [])
    if urls:
        add("c2_callback", 10, f"{len(urls)} external URL(s)")
        # Check for phishing keywords in URLs
        phish_kw = ["login", "signin", "account", "secure", "verify", "bank",
                    "paypal", "microsoft", "google", "update"]
        if any(kw in u.lower() for u in urls for kw in phish_kw):
            add("credential_phishing", 20, "Phishing-like URL keywords detected")
    if ips:
        add("c2_callback", 15, f"{len(ips)} raw IP address(es) — possible C2")

    # ── Content signals ────────────────────────────────────────────────────
    if iocs.get("shellcode_seqs", 0) > 0:
        add("exploit_delivery", 25, "Shellcode-like hex sequences")
    if iocs.get("long_base64", 0) > 3:
        add("exploit_delivery", 10, "Multiple long Base64 blobs — obfuscated payload")
    if iocs.get("cve_refs"):
        add("exploit_delivery", 20, f"CVE references: {iocs['cve_refs']}")

    # ── Credential keyword scan ───────────────────────────────────────────
    cred_kw = [b"password", b"passwd", b"login", b"username", b"credential",
               b"social security", b"bank account", b"credit card", b"ssn"]
    hits = [kw.decode() for kw in cred_kw if kw in data.lower()]
    if hits:
        add("credential_phishing", len(hits) * 5,
            f"Credential keywords: {hits[:4]}")

    # ── Determine primary + secondary ────────────────────────────────────
    sorted_types = sorted(
        [(t, s) for t, s in scores.items() if t != "unknown"],
        key=lambda x: -x[1]
    )

    if not sorted_types or sorted_types[0][1] == 0:
        primary    = "unknown"
        confidence = "LOW"
        ev_list    = ["No strong indicators found"]
    else:
        primary    = sorted_types[0][0]
        top_score  = sorted_types[0][1]
        confidence = ("HIGH" if top_score >= 40 else
                      "MEDIUM" if top_score >= 20 else "LOW")
        ev_list    = evidence[primary]

    secondary = [t for t, s in sorted_types[1:] if s >= 10 and t != primary]

    return {
        "primary_type":    primary,
        "confidence":      confidence,
        "evidence":        ev_list,
        "secondary_types": secondary,
        "scores":          {t: s for t, s in scores.items() if s > 0},
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK MAPPING  (Obj 4.3)
# ═══════════════════════════════════════════════════════════════════════════════

# (tactic, tactic_id, technique, technique_id, trigger_fn)
MITRE_MAPPINGS = [
    # Initial Access
    ("Initial Access", "TA0001",
     "Spearphishing Attachment", "T1566.001",
     lambda c, iocs, yara: c.get("/OpenAction", 0) > 0 or c.get("/JS+/JavaScript", 0) > 0),

    # Execution
    ("Execution", "TA0002",
     "User Execution: Malicious File", "T1204.002",
     lambda c, iocs, yara: c.get("/OpenAction", 0) > 0 or c.get("/Launch", 0) > 0),

    ("Execution", "TA0002",
     "Command and Scripting Interpreter: JavaScript", "T1059.007",
     lambda c, iocs, yara: c.get("/JS+/JavaScript", 0) > 0),

    # Defense Evasion
    ("Defense Evasion", "TA0005",
     "Obfuscated Files or Information", "T1027",
     lambda c, iocs, yara: iocs.get("long_base64", 0) > 2 or iocs.get("shellcode_seqs", 0) > 0),

    ("Defense Evasion", "TA0005",
     "Obfuscated Files or Information: Software Packing", "T1027.002",
     lambda c, iocs, yara: c.get("/EmbeddedFile", 0) > 0),

    ("Defense Evasion", "TA0005",
     "Obfuscated Files or Information: Binary Padding", "T1027.001",
     lambda c, iocs, yara: c.get("eof_markers", 0) > 1),

    # Collection
    ("Collection", "TA0009",
     "Input Capture: Web Portal Capture", "T1056.003",
     lambda c, iocs, yara: c.get("/SubmitForm", 0) > 0 or c.get("/AcroForm", 0) > 0),

    # Command and Control
    ("Command and Control", "TA0011",
     "Application Layer Protocol: Web Protocols", "T1071.001",
     lambda c, iocs, yara: len(iocs.get("urls", [])) > 0 or len(iocs.get("ip_addresses", [])) > 0),

    # Exfiltration
    ("Exfiltration", "TA0010",
     "Exfiltration Over C2 Channel", "T1041",
     lambda c, iocs, yara: c.get("/SubmitForm", 0) > 0 and len(iocs.get("urls", [])) > 0),

    # Resource Development
    ("Resource Development", "TA0042",
     "Obtain Capabilities: Exploits", "T1588.005",
     lambda c, iocs, yara: len(iocs.get("cve_refs", [])) > 0),

    # Impact / Exploitation
    ("Execution", "TA0002",
     "Exploitation for Client Execution", "T1203",
     lambda c, iocs, yara: (c.get("/XFA", 0) > 0 or c.get("/RichMedia", 0) > 0
                              or iocs.get("shellcode_seqs", 0) > 0)),

    # Persistence
    ("Persistence", "TA0003",
     "Boot or Logon Autostart Execution", "T1547",
     lambda c, iocs, yara: c.get("/Launch", 0) > 0),
]


def map_mitre(structural_counts: dict, iocs: dict, yara_matches: list) -> list[dict]:
    """Return list of triggered MITRE ATT&CK technique dicts."""
    triggered = []
    seen_ids   = set()
    for tactic, tac_id, technique, tech_id, trigger_fn in MITRE_MAPPINGS:
        try:
            if trigger_fn(structural_counts, iocs, yara_matches):
                if tech_id not in seen_ids:
                    seen_ids.add(tech_id)
                    # Build evidence string
                    ev_parts = []
                    if structural_counts.get(technique.split(":")[0].strip()):
                        ev_parts.append(technique)
                    for m in yara_matches:
                        if m.get("meta", {}).get("mitre_technique") == tech_id:
                            ev_parts.append(f"YARA:{m['rule']}")
                    triggered.append({
                        "tactic":       tactic,
                        "tactic_id":    tac_id,
                        "technique":    technique,
                        "technique_id": tech_id,
                        "evidence":     "; ".join(ev_parts) if ev_parts else "structural indicator",
                    })
        except Exception:
            pass
    return triggered


# ═══════════════════════════════════════════════════════════════════════════════
# REGEX PATTERNS  (mirrors pdf_forensic.py)
# ═══════════════════════════════════════════════════════════════════════════════

RE_OBJ       = re.compile(rb"(\d+)\s+(\d+)\s+obj")
RE_ENDOBJ    = re.compile(rb"\bendobj\b")
RE_STREAM    = re.compile(rb"\bstream\b")
RE_ENDSTREAM = re.compile(rb"\bendstream\b")
RE_XREF      = re.compile(rb"\bxref\b")
RE_EOF       = re.compile(rb"%%EOF")
RE_HEADER    = re.compile(rb"%PDF-(\d+\.\d+)")
RE_JS        = re.compile(rb"/JS\b|/JavaScript\b", re.IGNORECASE)
RE_OPENACTION= re.compile(rb"/OpenAction\b")
RE_AA        = re.compile(rb"/AA\b")
RE_LAUNCH    = re.compile(rb"/Launch\b")
RE_XFA       = re.compile(rb"/XFA\b")
RE_EMBFILE   = re.compile(rb"/EmbeddedFile\b")
RE_SUBMITFORM= re.compile(rb"/SubmitForm\b")
RE_RICHMEDIA = re.compile(rb"/RichMedia\b")
RE_OBJSTM    = re.compile(rb"/ObjStm\b")
RE_ENCRYPT   = re.compile(rb"/Encrypt\b")
RE_ACROFORM  = re.compile(rb"/AcroForm\b")
RE_URI       = re.compile(rb"/URI\s*\(([^)]{1,512})\)")
RE_CREATOR   = re.compile(rb"/Creator\s*\(([^)]{0,256})\)")
RE_PRODUCER  = re.compile(rb"/Producer\s*\(([^)]{0,256})\)")
RE_AUTHOR    = re.compile(rb"/Author\s*\(([^)]{0,256})\)")
RE_TITLE     = re.compile(rb"/Title\s*\(([^)]{0,256})\)")
RE_CREDATE   = re.compile(rb"/CreationDate\s*\(([^)]{0,64})\)")
RE_MODDATE   = re.compile(rb"/ModDate\s*\(([^)]{0,64})\)")
RE_URL       = re.compile(rb"(https?://[^\s\x00-\x1f\x7f-\xff>)]{4,512})")
RE_IP        = re.compile(rb"\b(\d{1,3}\.){3}\d{1,3}\b")
RE_DOMAIN    = re.compile(rb"(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)")
RE_CVE       = re.compile(rb"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
RE_SHELLCODE = re.compile(rb"(\\x[0-9a-fA-F]{2}){8,}")
RE_B64_LONG  = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")


def shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data)
    t = len(data)
    return -sum((v/t) * math.log2(v/t) for v in c.values())


def _first(pattern, data):
    m = pattern.search(data)
    return m.group(1).decode("latin-1", errors="replace").strip() if m else None


# ═══════════════════════════════════════════════════════════════════════════════
# FORENSIC EXTRACTION  (Obj 4 — "Extract scripts / Extract objects" step,
# only run on the MALICIOUS path per the System Methodology diagram)
# ═══════════════════════════════════════════════════════════════════════════════

def _pikepdf_text(obj) -> str:
    """Best-effort decode of a pikepdf String/Stream object to Python text."""
    try:
        if isinstance(obj, pikepdf.Stream):
            return obj.read_bytes().decode("utf-8", errors="replace")
        return str(obj)
    except Exception:
        return ""


def extract_artifacts(pdf_path: str) -> dict:
    """
    Objective 4 'Forensic Extraction' step — pulls out the actual malicious
    content (not just presence flags) so an analyst has real evidence to look
    at: JavaScript source, embedded-file identity, and launch/URI targets.
    Only meant to run once a file has already been flagged malicious — it's
    the heavier, pikepdf-based step the diagram gates behind the ML decision.
    """
    artifacts = {
        "javascript_snippets": [],   # [{code_preview, full_length, sha256}]
        "embedded_files":      [],   # [{size_bytes, sha256, subtype}]
        "uri_targets":         [],   # [str]
        "launch_targets":      [],   # [str]
        "extraction_errors":   [],
    }
    if not _PIKEPDF_AVAILABLE:
        artifacts["extraction_errors"].append("pikepdf not installed — pip install pikepdf")
        return artifacts

    try:
        pdf = pikepdf.open(pdf_path)
    except Exception as e:
        artifacts["extraction_errors"].append(f"pikepdf could not open file: {e}")
        return artifacts

    seen_js = set()
    seen_embedded_sha = set()
    seen_objects = set()   # (obj_num, gen_num) of already-visited indirect objects

    def scan(obj, depth=0):
        # Actions/annotations can be nested many layers deep (/Annots -> /A ->
        # /Next -> ...); the depth cap alone is NOT enough protection, though —
        # PDFs are graphs, not trees. A font, image, or /Resources dict is
        # typically referenced by every single page, so without tracking
        # object identity, each shared object gets re-walked once per path
        # that reaches it — exponential blowup on any real-world file with
        # more than a couple of pages (confirmed hang on a 37-page deck).
        if depth > 15:
            return
        try:
            # Indirect objects (the vast majority of real content) carry a
            # stable (obj_num, gen_num) identity via pikepdf — skip anything
            # already visited instead of re-walking it from a new path.
            objgen = getattr(obj, "objgen", None)
            if objgen and objgen != (0, 0):
                if objgen in seen_objects:
                    return
                seen_objects.add(objgen)

            if isinstance(obj, pikepdf.Array):
                for item in obj:
                    scan(item, depth + 1)
                return

            if isinstance(obj, pikepdf.Stream) and "/Type" in obj \
                    and str(obj.get("/Type")) == "/EmbeddedFile":
                try:
                    raw = obj.read_bytes()
                    sha = hashlib.sha256(raw).hexdigest()
                    if sha not in seen_embedded_sha:
                        seen_embedded_sha.add(sha)
                        artifacts["embedded_files"].append({
                            "size_bytes": len(raw),
                            "sha256":     sha,
                            "subtype":    str(obj.get("/Subtype", "unknown")),
                        })
                except Exception:
                    pass

            if not hasattr(obj, "get") or not hasattr(obj, "keys"):
                return  # scalar (int/name/string/etc) — nothing to recurse into

            action_type = str(obj.get("/S", "")) if "/S" in obj else ""

            if action_type == "/JavaScript" and "/JS" in obj:
                code = _pikepdf_text(obj.get("/JS"))
                if code and code not in seen_js:
                    seen_js.add(code)
                    artifacts["javascript_snippets"].append({
                        "code_preview": code[:500],
                        "full_length":  len(code),
                        "sha256":       hashlib.sha256(code.encode("utf-8", "replace")).hexdigest(),
                    })

            if action_type == "/Launch" and "/F" in obj:
                target = str(obj.get("/F"))
                if target not in artifacts["launch_targets"]:
                    artifacts["launch_targets"].append(target)

            if action_type == "/URI" and "/URI" in obj:
                uri = str(obj.get("/URI"))
                if uri not in artifacts["uri_targets"]:
                    artifacts["uri_targets"].append(uri)

            # Recurse into every child value — covers /A, /AA (keyed by trigger
            # name: /O /C /WC ...), /Next (action chains), /Annots, /Kids,
            # /Names, and anything else, without hardcoding every key name.
            for key in obj.keys():
                try:
                    scan(obj[key], depth + 1)
                except Exception:
                    continue
        except Exception:
            return

    try:
        scan(pdf.Root, 0)
        for page in pdf.pages:
            scan(page.obj, 0)
        # Some PDF malware places actions in objects that aren't reachable
        # from /Root at all (broken/unusual xref structure but still parsed
        # by lenient readers) — catch those too.
        for obj in pdf.objects:
            scan(obj, depth=10)
    finally:
        pdf.close()

    return artifacts


# ═══════════════════════════════════════════════════════════════════════════════
# CHEAP PRE-CLASSIFICATION SCAN
# Used only as a fallback gate when the ML model/artifacts aren't available,
# so the detect→branch pipeline still has *something* to decide on.
# ═══════════════════════════════════════════════════════════════════════════════

def quick_heuristic_scan(data: bytes) -> dict:
    js  = len(RE_JS.findall(data))
    oa  = len(RE_OPENACTION.findall(data))
    lau = len(RE_LAUNCH.findall(data))
    ef  = len(RE_EMBFILE.findall(data))
    sf  = len(RE_SUBMITFORM.findall(data))
    suspicious = (js > 0 and oa > 0) or lau > 0 or ef > 0 or sf > 0
    return {"suspicious": suspicious, "/JS": js, "/OpenAction": oa,
            "/Launch": lau, "/EmbeddedFile": ef, "/SubmitForm": sf}


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ANALYSIS FUNCTION
# ═══════════════════════════════════════════════════════════════════════════════

def forensic_analyse_v2(pdf_path:            str,
                        model_path:           str   = "artifacts/model_random_forest.pkl",
                        features_path:        str   = "artifacts/final_features.csv",
                        threshold:            float = 0.5,
                        do_lookup:            bool  = True,
                        precomputed_ml_verdict: dict = None,
                        deep_extraction:      bool  = True) -> dict:
    """
    Full forensic analysis — returns structured dict conforming to SCHEMA v2.0.

    precomputed_ml_verdict : reuse an already-computed ML verdict instead of
        re-running feature extraction + prediction (used by detect_and_analyze
        so the model only scores each file once).
    deep_extraction : whether to run the pikepdf-based script/object
        extraction step (Obj 4 "Forensic Extraction"). Left on by default for
        direct forensic_analyse_v2() callers/tests; detect_and_analyze() turns
        it off for files the model already classified benign.
    """
    path = Path(pdf_path)
    if not path.exists():
        return {"error": f"File not found: {pdf_path}",
                "schema_version": REPORT_SCHEMA_VERSION}

    t0 = time.perf_counter()

    with open(pdf_path, "rb") as fh:
        data = fh.read()

    # ── Hashes ──────────────────────────────────────────────────────────────
    hashes = {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    # ── PDF header ──────────────────────────────────────────────────────────
    hm = RE_HEADER.search(data[:1024])
    pdf_header = {
        "valid":   hm is not None,
        "version": hm.group(1).decode() if hm else "UNKNOWN",
        "offset":  hm.start() if hm else -1,
    }

    # ── Structural counts ────────────────────────────────────────────────────
    structural_counts = {
        "obj":              len(RE_OBJ.findall(data)),
        "endobj":           len(RE_ENDOBJ.findall(data)),
        "streams":          len(RE_STREAM.findall(data)),
        "endstreams":       len(RE_ENDSTREAM.findall(data)),
        "xref":             len(RE_XREF.findall(data)),
        "eof_markers":      len(RE_EOF.findall(data)),
        "/JS+/JavaScript":  len(RE_JS.findall(data)),
        "/OpenAction":      len(RE_OPENACTION.findall(data)),
        "/AA":              len(RE_AA.findall(data)),
        "/Launch":          len(RE_LAUNCH.findall(data)),
        "/XFA":             len(RE_XFA.findall(data)),
        "/EmbeddedFile":    len(RE_EMBFILE.findall(data)),
        "/SubmitForm":      len(RE_SUBMITFORM.findall(data)),
        "/RichMedia":       len(RE_RICHMEDIA.findall(data)),
        "/ObjStm":          len(RE_OBJSTM.findall(data)),
        "/Encrypt":         1 if RE_ENCRYPT.search(data) else 0,
        "/AcroForm":        1 if RE_ACROFORM.search(data) else 0,
    }

    # ── Global entropy ───────────────────────────────────────────────────────
    global_entropy = round(shannon_entropy(data), 4)

    # ── Metadata ─────────────────────────────────────────────────────────────
    metadata = {
        "pdf_version": pdf_header["version"],
        "creator":     _first(RE_CREATOR, data),
        "producer":    _first(RE_PRODUCER, data),
        "author":      _first(RE_AUTHOR, data),
        "title":       _first(RE_TITLE, data),
        "created":     _first(RE_CREDATE, data),
        "modified":    _first(RE_MODDATE, data),
    }

    # ── IOCs ──────────────────────────────────────────────────────────────────
    raw_urls  = list({m.group(1).decode("latin-1", errors="replace")
                      for m in RE_URL.finditer(data)})
    raw_ips   = list({m.group(0).decode("latin-1", errors="replace")
                      for m in RE_IP.finditer(data)
                      if not m.group(0).startswith(b"127.")
                         and m.group(0) != b"255.255.255.255"})
    domains   = list({m.group(1).decode("latin-1", errors="replace")
                      for m in RE_DOMAIN.finditer(data)
                      if len(m.group(1)) > 4})[:20]
    cve_refs  = list({m.group(0).decode("latin-1", errors="replace")
                      for m in RE_CVE.finditer(data)})
    sc_seqs   = len(RE_SHELLCODE.findall(data))
    b64_count = len(RE_B64_LONG.findall(data))

    iocs = {
        "urls":           raw_urls[:20],
        "ip_addresses":   raw_ips[:20],
        "domains":        domains,
        "cve_refs":       cve_refs,
        "shellcode_seqs": sc_seqs,
        "long_base64":    b64_count,
    }

    # ── Anomalies ─────────────────────────────────────────────────────────────
    anomalies = []
    c = structural_counts
    if c["eof_markers"] > 1:
        anomalies.append(f"Multiple %%EOF markers ({c['eof_markers']}) — polyglot/append attack")
    if abs(c["obj"] - c["endobj"]) > 2:
        anomalies.append(f"obj/endobj mismatch ({c['obj']} vs {c['endobj']})")
    if c["/ObjStm"] > 0:
        anomalies.append(f"/ObjStm present ({c['/ObjStm']}) — compressed objects")
    if c["/Encrypt"]:
        anomalies.append("/Encrypt — document encrypted, analysis may be incomplete")
    if global_entropy >= 7.5:
        anomalies.append(f"Very high global entropy ({global_entropy}) — compressed/encrypted content")
    if c["/Launch"]:
        anomalies.append("/Launch — can execute external programs")
    if c["/EmbeddedFile"]:
        anomalies.append(f"/EmbeddedFile ({c['/EmbeddedFile']}) — file drop vector")
    if c["/RichMedia"]:
        anomalies.append("/RichMedia — Flash/multimedia exploit vector")
    if sc_seqs > 0:
        anomalies.append(f"Shellcode-like hex patterns ({sc_seqs} occurrences)")
    if len(raw_ips) > 0:
        anomalies.append(f"Raw IP addresses ({len(raw_ips)}) — possible C2")
    if cve_refs:
        anomalies.append(f"CVE references inside PDF: {cve_refs}")
    if pdf_header["offset"] > 0:
        anomalies.append(f"%PDF header at offset {pdf_header['offset']} — junk bytes prepended (evasion)")
    if c["/JS+/JavaScript"] > 0 and c["/OpenAction"] > 0:
        anomalies.append("JavaScript AND OpenAction — auto-execute JS pattern")

    # ── YARA ─────────────────────────────────────────────────────────────────
    yara_matches = run_yara(data)

    # ── MalwareBazaar ────────────────────────────────────────────────────────
    mb_result = (lookup_malwarebazaar(hashes["sha256"])
                 if do_lookup else
                 {"queried": False, "found": False, "query_error": "skipped"})

    # ── Attack classification ─────────────────────────────────────────────────
    attack_class = _classify_attack(data, yara_matches, iocs, structural_counts)

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    mitre = map_mitre(structural_counts, iocs, yara_matches)

    # ── Risk score ────────────────────────────────────────────────────────────
    risk = 0
    risk += min(c["/JS+/JavaScript"] * 15, 25)
    risk += min(c["/OpenAction"] * 10, 15)
    risk += min(c["/Launch"] * 20, 20)
    risk += min(c["/XFA"] * 10, 10)
    risk += min(c["/EmbeddedFile"] * 10, 10)
    risk += min(len(anomalies) * 5, 20)
    risk += 5 if global_entropy >= 7.5 else (3 if global_entropy >= 6.5 else 0)
    risk += min(len(raw_urls) * 2, 10)
    risk += min(sc_seqs * 5, 15)
    risk += 10 if mb_result.get("found") else 0
    risk += min(len(yara_matches) * 8, 30)
    risk = min(risk, 100)
    risk_label = ("CRITICAL" if risk >= 75 else
                  "HIGH"     if risk >= 50 else
                  "MEDIUM"   if risk >= 25 else "LOW")

    # ── ML verdict ────────────────────────────────────────────────────────────
    ml_verdict = (precomputed_ml_verdict if precomputed_ml_verdict is not None
                  else _get_ml_verdict(pdf_path, model_path, features_path, threshold))

    # ── Forensic extraction (Obj 4 — scripts/objects), malicious path only ────
    forensic_extraction = extract_artifacts(pdf_path) if deep_extraction else None

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    return {
        "schema_version":        REPORT_SCHEMA_VERSION,
        "file":                  str(path.resolve()),
        "filename":              path.name,
        "filesize_bytes":        len(data),
        "filesize_kb":           round(len(data) / 1024, 2),
        "analysis_time_ms":      elapsed_ms,
        "timestamp":             datetime.now(timezone.utc).isoformat(),
        "hashes":                hashes,
        "pdf_header":            pdf_header,
        "global_entropy":        global_entropy,
        "metadata":              metadata,
        "structural_counts":     structural_counts,
        "iocs":                  iocs,
        "anomalies":             anomalies,
        "yara_matches":          yara_matches,
        "malwarebazaar":         mb_result,
        "attack_classification": attack_class,
        "mitre_attack":          mitre,
        "risk_score":            risk,
        "risk_label":            risk_label,
        "ml_verdict":            ml_verdict,
        "forensic_extraction":   forensic_extraction,
    }


_ML_MODEL_CACHE = {}  # (model_path, features_path) -> (model, features_list)

def _load_ml_artifacts(model_path, features_path):
    """Load model + feature list once per (path) pair and reuse across calls,
    instead of paying joblib deserialization cost on every single PDF."""
    key = (model_path, features_path)
    if key not in _ML_MODEL_CACHE:
        model   = joblib.load(model_path)
        feat_df = pd.read_csv(features_path)
        col     = feat_df.columns[0] if len(feat_df.columns) == 1 else "feature"
        features = feat_df[col].tolist()
        _ML_MODEL_CACHE[key] = (model, features)
    return _ML_MODEL_CACHE[key]


def _get_ml_verdict(pdf_path, model_path, features_path, threshold):
    if not (_ML_AVAILABLE and _EXTRACTOR_AVAILABLE):
        return {"available": False, "reason": "ML dependencies not installed"}
    if not os.path.exists(model_path) or not os.path.exists(features_path):
        return {"available": False, "reason": "artifacts/ not found"}
    try:
        model, features = _load_ml_artifacts(model_path, features_path)
        raw = extract_features(pdf_path)
        if raw is None:
            return {"available": False, "reason": "feature extraction failed"}
        # Derived features
        raw["js_total"]       = raw.get("/JavaScript", 0) + raw.get("/JS", 0)
        raw["has_js_any"]     = int(raw["js_total"] > 0)
        raw["has_action_any"] = int(raw.get("/OpenAction", 0) > 0)
        raw["has_xfa_any"]    = int(raw.get("/XFA", 0) > 0)
        obj = raw.get("obj", 0); endobj = raw.get("endobj", 0)
        raw["obj_balance"]    = abs(obj - endobj) / (obj + endobj + 1)
        raw["stream_density"] = raw.get("stream", 0) / (obj + 1)
        raw["xref_ratio"]     = raw.get("xref", 0) / (obj + 1)
        raw["ref_density"]    = raw.get("Referencing", 0) / (obj + 1)
        raw["font_per_page"]  = raw.get("/Font", 0) / (raw.get("Pages", 0) + 1)
        raw["multi_eof"]      = int(raw.get("%EOF", 0) > 1)
        raw["trigger_score"]  = sum(raw.get(k, 0) for k in
                                    ["/JavaScript", "/JS", "/OpenAction", "/XFA"])
        raw["metadata_count"] = sum(1 for f in ["/Producer", "/CreationDate", "/Info", "/ID"]
                                    if raw.get(f, 0) > 0)
        row   = {c: raw.get(c, 0) for c in features}
        X     = pd.DataFrame([row], columns=features)
        proba = model.predict_proba(X)[0]
        p_mal = float(proba[1])
        return {
            "available":               True,
            "label":                   "MALICIOUS" if p_mal >= threshold else "BENIGN",
            "probability_malicious":   round(p_mal, 4),
            "probability_benign":      round(float(proba[0]), 4),
            "confidence_pct":          round(max(proba) * 100, 1),
            "threshold":               threshold,
            "model":                   type(model).__name__,
        }
    except Exception as e:
        return {"available": False, "reason": str(e)[:120]}


# ═══════════════════════════════════════════════════════════════════════════════
# DETECT → BRANCH PIPELINE
# Mirrors the FYP-I "System Methodology Overview" diagram exactly:
#   Prediction Output -> Classification Decision (Malicious/Benign)
#     MALICIOUS PATH -> Forensic Extraction (scripts/objects/indicators)
#                        -> Report Generation (JSON/HTML)
#     BENIGN PATH    -> Basic Report Generation (JSON/HTML)
# ═══════════════════════════════════════════════════════════════════════════════

def detect_and_analyze(pdf_path:      str,
                       model_path:    str   = "artifacts/model_random_forest.pkl",
                       features_path: str   = "artifacts/final_features.csv",
                       threshold:     float = 0.5,
                       do_lookup:     bool  = True) -> dict:
    """
    Entry point for the real workflow: classify first with the trained ML
    model, then only pay for the expensive forensic steps (MalwareBazaar hash
    lookup, pikepdf script/object extraction) when the file is actually
    flagged malicious. Benign files still get a real report — hashes,
    structural counts, entropy, IOCs, YARA, attack classification, MITRE
    mapping, risk score — just without the network call or deep extraction.

    Decision rule:
      - If the ML model is available, its label decides the path.
      - If the ML model is unavailable, fall back to a cheap structural
        pre-scan (quick_heuristic_scan) so the pipeline still works without
        trained artifacts.
      - Regardless of the ML label, a heuristic risk_label of HIGH/CRITICAL
        also forces the malicious path — a model miss shouldn't suppress
        forensic detail on a file that structurally looks dangerous.
    """
    path = Path(pdf_path)
    if not path.exists():
        return {"error": f"File not found: {pdf_path}",
                "schema_version": REPORT_SCHEMA_VERSION}

    ml_verdict = _get_ml_verdict(pdf_path, model_path, features_path, threshold)

    if ml_verdict.get("available"):
        ml_says_malicious = ml_verdict["label"] == "MALICIOUS"
    else:
        with open(pdf_path, "rb") as fh:
            quick = quick_heuristic_scan(fh.read())
        ml_says_malicious = quick["suspicious"]
        ml_verdict["quick_scan"] = quick  # keep the fallback evidence visible

    # First pass without the expensive steps, to also read the heuristic risk_label
    result = forensic_analyse_v2(
        pdf_path, model_path, features_path, threshold,
        do_lookup=False, precomputed_ml_verdict=ml_verdict, deep_extraction=False,
    )
    if "error" in result:
        return result

    is_malicious = ml_says_malicious or result["risk_label"] in ("HIGH", "CRITICAL")

    if is_malicious:
        # ---- MALICIOUS PATH: add the expensive steps in-place ----
        result["malwarebazaar"] = (lookup_malwarebazaar(result["hashes"]["sha256"])
                                    if do_lookup else
                                    {"queried": False, "found": False, "query_error": "skipped"})
        result["forensic_extraction"] = extract_artifacts(pdf_path)
    # else: BENIGN PATH — result already has everything except MB lookup /
    # extraction, which stay at their "skipped" defaults from the first pass.

    result["path_taken"] = "MALICIOUS" if is_malicious else "BENIGN"
    return result


# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT GENERATOR  (Obj 4.4 — diagram lists JSON / HTML / CSV outputs)
# ═══════════════════════════════════════════════════════════════════════════════

def generate_html_report(r: dict) -> str:
    if "error" in r:
        return f"<html><body><h1>Error</h1><p>{r['error']}</p></body></html>"

    risk_colour = {"CRITICAL": "#b71c1c", "HIGH": "#d32f2f",
                   "MEDIUM": "#f9a825", "LOW": "#2e7d32"}.get(r["risk_label"], "#555")
    path_taken = r.get("path_taken", "MALICIOUS" if r.get("forensic_extraction") else "BENIGN")
    path_colour = "#d32f2f" if path_taken == "MALICIOUS" else "#2e7d32"

    def esc(s):
        return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))

    rows = []
    rows.append(f"<h2>PDF Forensic Report</h2>")
    rows.append(f"<p><b>File:</b> {esc(r.get('filename'))} &nbsp; "
                f"<b>Path taken:</b> <span style='color:{path_colour};font-weight:bold'>{path_taken}</span></p>")
    rows.append(f"<p><b>Risk:</b> <span style='color:{risk_colour};font-weight:bold'>"
                f"{r.get('risk_label')} ({r.get('risk_score')}/100)</span></p>")

    ml = r.get("ml_verdict", {})
    if ml.get("available"):
        rows.append(f"<p><b>ML verdict:</b> {esc(ml.get('label'))} "
                    f"(P(malicious)={ml.get('probability_malicious')}, model={esc(ml.get('model'))})</p>")

    ac = r.get("attack_classification")
    if ac:
        rows.append(f"<h3>Attack Classification</h3><p><b>{esc(ac['primary_type'])}</b> "
                    f"(confidence: {ac['confidence']})</p><ul>")
        for e in ac.get("evidence", []):
            rows.append(f"<li>{esc(e)}</li>")
        rows.append("</ul>")

    mitre = r.get("mitre_attack") or []
    if mitre:
        rows.append("<h3>MITRE ATT&CK Mapping</h3><table border=1 cellpadding=4 cellspacing=0>")
        rows.append("<tr><th>Tactic</th><th>Technique</th><th>ID</th></tr>")
        for m in mitre:
            rows.append(f"<tr><td>{esc(m['tactic'])}</td><td>{esc(m['technique'])}</td>"
                        f"<td>{esc(m['technique_id'])}</td></tr>")
        rows.append("</table>")

    fe = r.get("forensic_extraction")
    if fe:
        rows.append("<h3>Forensic Extraction</h3>")
        if fe.get("javascript_snippets"):
            rows.append("<h4>JavaScript</h4>")
            for js in fe["javascript_snippets"]:
                rows.append(f"<pre style='background:#f4f4f4;padding:8px'>{esc(js['code_preview'])}</pre>")
        if fe.get("embedded_files"):
            rows.append("<h4>Embedded Files</h4><ul>")
            for ef in fe["embedded_files"]:
                rows.append(f"<li>{ef['size_bytes']} bytes, sha256={ef['sha256'][:16]}…, {esc(ef['subtype'])}</li>")
            rows.append("</ul>")
        if fe.get("uri_targets"):
            rows.append("<h4>URI Targets</h4><ul>" +
                        "".join(f"<li>{esc(u)}</li>" for u in fe["uri_targets"]) + "</ul>")
        if fe.get("launch_targets"):
            rows.append("<h4>Launch Targets</h4><ul>" +
                        "".join(f"<li>{esc(t)}</li>" for t in fe["launch_targets"]) + "</ul>")

    anomalies = r.get("anomalies") or []
    if anomalies:
        rows.append("<h3>Structural Anomalies</h3><ul>" +
                    "".join(f"<li>{esc(a)}</li>" for a in anomalies) + "</ul>")

    body = "\n".join(rows)
    return (f"<html><head><meta charset='utf-8'><title>Forensic Report — "
            f"{esc(r.get('filename'))}</title></head><body style='font-family:sans-serif'>"
            f"{body}</body></html>")


# ═══════════════════════════════════════════════════════════════════════════════
# PRETTY PRINTER
# ═══════════════════════════════════════════════════════════════════════════════

def print_report(r: dict) -> None:
    if "error" in r:
        print(RED(f"\n  [ERROR] {r['error']}\n")); return

    def section(title):
        print(f"\n  {BOLD(CYAN('═' * W))}")
        print(f"  {BOLD(CYAN(title.center(W)))}")
        print(f"  {BOLD(CYAN('═' * W))}")

    def row(label, value, colour=None):
        vs = colour(str(value)) if colour else str(value)
        print(f"  {label:<30} {vs}")

    risk_col = (RED if r["risk_label"] in ("CRITICAL","HIGH")
                else YELLOW if r["risk_label"] == "MEDIUM" else GREEN)

    section("PDF FORENSIC REPORT v2")
    if "path_taken" in r:
        pt_col = RED if r["path_taken"] == "MALICIOUS" else GREEN
        row("Path taken", pt_col(r["path_taken"]))
    row("File",          r["filename"])
    row("Size",          f"{r['filesize_kb']} KB  ({r['filesize_bytes']:,} bytes)")
    row("Analysis time", f"{r['analysis_time_ms']} ms")
    row("Timestamp",     r["timestamp"])
    row("Schema",        r["schema_version"])

    section("FILE HASHES")
    for k, v in r["hashes"].items():
        row(k.upper(), v, DIM)

    section("PDF HEADER")
    h = r["pdf_header"]
    row("Valid",   "YES" if h["valid"] else "NO", GREEN if h["valid"] else RED)
    row("Version", h["version"])
    if h["offset"] > 0:
        row("Offset", RED(f"{h['offset']} bytes  ⚠ junk prepended"))

    section("STRUCTURAL COUNTS")
    c = r["structural_counts"]
    for k, v in c.items():
        col = RED if (k not in ("obj","endobj","streams","endstreams","xref","eof_markers") and v > 0) else None
        row(k, v, col)

    section("METADATA")
    for k, v in r["metadata"].items():
        row(k.replace("_"," ").title(), v or DIM("(not present)"))

    section("INDICATORS OF COMPROMISE")
    ioc = r["iocs"]
    if ioc["urls"]:
        print(f"  URLs ({len(ioc['urls'])}):")
        for u in ioc["urls"][:8]: print(f"    {RED(u)}")
    if ioc["ip_addresses"]:
        print(f"  IPs ({len(ioc['ip_addresses'])}):")
        for ip in ioc["ip_addresses"][:8]: print(f"    {YELLOW(ip)}")
    if ioc["cve_refs"]:
        print(f"  CVEs: {RED(', '.join(ioc['cve_refs']))}")
    if ioc["shellcode_seqs"]:
        row("Shellcode seqs", ioc["shellcode_seqs"], RED)
    if ioc["long_base64"]:
        row("Long Base64 blobs", ioc["long_base64"], YELLOW)
    if not any([ioc["urls"], ioc["ip_addresses"], ioc["cve_refs"],
                ioc["shellcode_seqs"], ioc["long_base64"]]):
        print(f"  {GREEN('No IOCs found.')}")

    section("YARA MATCHES")
    if not _YARA_AVAILABLE:
        print(f"  {YELLOW('yara-python not installed — pip install yara-python')}")
    elif r["yara_matches"]:
        for m in r["yara_matches"]:
            sev = m.get("meta", {}).get("severity", "")
            col = RED if sev in ("CRITICAL","HIGH") else YELLOW
            print(f"  {col('⚡')} {BOLD(m['rule'])}  [{sev}]")
            desc = m.get("meta", {}).get("description", "")
            if desc: print(f"     {DIM(desc)}")
            if m["strings"]:
                for s in m["strings"][:3]:
                    print(f"     {DIM(s['identifier'])} @ {s['offset']}: {s['data_hex'][:32]}…")
    else:
        print(f"  {GREEN('No YARA rules matched.')}")

    section("MALWAREBAZAAR LOOKUP")
    mb = r["malwarebazaar"]
    if not mb.get("queried"):
        print(f"  {DIM('Lookup skipped (use --no-lookup to suppress)')}")
    elif mb.get("query_error"):
        print(f"  {YELLOW('Error: ' + str(mb['query_error']))}")
    elif mb.get("found"):
        print(f"  {RED('⚠  HASH FOUND IN MALWAREBAZAAR')}")
        row("Signature",   mb.get("signature", "?"), RED)
        row("First seen",  mb.get("first_seen", "?"))
        row("Reporter",    mb.get("reporter", "?"))
        row("Tags",        ", ".join(mb.get("tags", [])))
    else:
        print(f"  {GREEN('Hash not found in MalwareBazaar.')}")

    section("ATTACK CLASSIFICATION  (Obj 4.1)")
    ac = r["attack_classification"]
    conf_col = RED if ac["confidence"] == "HIGH" else YELLOW if ac["confidence"] == "MEDIUM" else DIM
    row("Primary type",    BOLD(ac["primary_type"].replace("_", " ").upper()), conf_col)
    row("Confidence",      ac["confidence"], conf_col)
    if ac["secondary_types"]:
        row("Secondary",   ", ".join(ac["secondary_types"]))
    if ac["evidence"]:
        print(f"  Evidence:")
        for e in ac["evidence"][:6]: print(f"    · {e}")

    section("MITRE ATT&CK MAPPING  (Obj 4.3)")
    if r["mitre_attack"]:
        for m in r["mitre_attack"]:
            print(f"  {YELLOW(m['tactic_id'])}  {m['tactic']}")
            print(f"    {RED(m['technique_id'])}  {m['technique']}")
            print(f"    {DIM('Evidence: ' + m['evidence'])}")
    else:
        print(f"  {GREEN('No ATT&CK techniques triggered.')}")

    fe = r.get("forensic_extraction")
    if fe:
        section("FORENSIC EXTRACTION  (scripts / objects)")
        if fe.get("extraction_errors"):
            for e in fe["extraction_errors"]:
                print(f"  {YELLOW('⚠')} {e}")
        if fe.get("javascript_snippets"):
            print(f"  JavaScript snippets ({len(fe['javascript_snippets'])}):")
            for js in fe["javascript_snippets"][:3]:
                print(f"    {DIM(js['code_preview'][:120])}{'…' if js['full_length'] > 120 else ''}")
        if fe.get("embedded_files"):
            print(f"  Embedded files ({len(fe['embedded_files'])}):")
            for ef in fe["embedded_files"][:5]:
                print(f"    {RED('⚠')} {ef['size_bytes']} bytes, sha256={ef['sha256'][:16]}…, {ef['subtype']}")
        if fe.get("uri_targets"):
            print(f"  URI targets: {', '.join(fe['uri_targets'][:5])}")
        if fe.get("launch_targets"):
            print(f"  Launch targets: {', '.join(fe['launch_targets'][:5])}")
        if not any([fe.get("javascript_snippets"), fe.get("embedded_files"),
                    fe.get("uri_targets"), fe.get("launch_targets")]):
            print(f"  {GREEN('No extractable script/object artifacts found.')}")

    section("STRUCTURAL ANOMALIES")
    if r["anomalies"]:
        for a in r["anomalies"]: print(f"  {RED('⚠')}  {a}")
    else:
        print(f"  {GREEN('No anomalies detected.')}")

    section("VERDICT")
    print(f"  {'Heuristic risk score':<30} "
          f"{risk_col(str(r['risk_score']) + '/100')}  [{risk_col(r['risk_label'])}]")
    ml = r["ml_verdict"]
    if ml.get("available"):
        mc = RED if ml["label"] == "MALICIOUS" else GREEN
        print(f"  {'ML Model verdict':<30} {mc(ml['label'])}  "
              f"P(mal)={ml['probability_malicious']:.4f}  "
              f"conf={ml['confidence_pct']}%  [{ml['model']}]")
    else:
        print(f"  {'ML Model verdict':<30} {DIM('Not available — ' + ml.get('reason',''))}")

    print(f"\n  {'─'*W}\n")


# ═══════════════════════════════════════════════════════════════════════════════
# BATCH MODE
# ═══════════════════════════════════════════════════════════════════════════════

def batch_forensic_v2(folder, output_csv,
                      model_path="artifacts/model_random_forest.pkl",
                      features_path="artifacts/final_features.csv",
                      threshold=0.5, do_lookup=False, force_forensic=False):
    """
    Batch mode. By default runs the detect-then-branch pipeline per file
    (ML classifies first; only malicious files pay for MalwareBazaar lookup +
    pikepdf extraction) — much faster across a large mixed folder than always
    running the full forensic engine. Pass force_forensic=True to always run
    the deep analysis regardless of the ML verdict (useful for validation
    against a known-malicious folder, e.g. testing recall).
    """
    if _EXTRACTOR_AVAILABLE:
        pdfs = [f for f in Path(folder).rglob("*") if f.is_file() and is_pdf_file(f)]
    else:
        pdfs = [f for f in Path(folder).rglob("*.pdf") if f.is_file()]

    if not pdfs:
        print(RED(f"  No PDFs found in {folder}")); return

    mode = "full forensic (forced)" if force_forensic else "detect-then-branch"
    print(f"  Found {len(pdfs)} PDFs. Running {mode} analysis...\n")
    rows = []

    for i, pdf in enumerate(pdfs, 1):
        if force_forensic:
            r = forensic_analyse_v2(str(pdf), model_path, features_path,
                                    threshold, do_lookup)
        else:
            r = detect_and_analyze(str(pdf), model_path, features_path,
                                   threshold, do_lookup)
        if "error" in r:
            print(f"  [{i:>4}/{len(pdfs)}]  {YELLOW('ERROR')}  {pdf.name}")
            continue

        rl = r["risk_label"]
        rl_col = RED if rl in ("CRITICAL","HIGH") else YELLOW if rl == "MEDIUM" else GREEN
        at = r["attack_classification"]["primary_type"]
        ml = r["ml_verdict"].get("label", "N/A") if r["ml_verdict"].get("available") else "N/A"
        mb_flag = "MB:HIT" if r["malwarebazaar"].get("found") else ""
        yara_n  = len(r["yara_matches"])
        path_taken = r.get("path_taken", "MALICIOUS" if force_forensic else "?")

        print(f"  [{i:>4}/{len(pdfs)}]  Path={path_taken:<9}  Risk={rl_col(rl):<10}  "
              f"ML={ml:<10}  YARA={yara_n}  {RED(mb_flag) if mb_flag else ''}  "
              f"Type={at[:20]}  {pdf.name[:40]}")

        mitre_ids = ";".join(m["technique_id"] for m in r["mitre_attack"])
        yara_rules = ";".join(m["rule"] for m in r["yara_matches"])
        fe = r.get("forensic_extraction") or {}
        rows.append({
            "File":            pdf.name,
            "SHA256":          r["hashes"]["sha256"],
            "Path_taken":      path_taken,
            "Risk_score":      r["risk_score"],
            "Risk_label":      r["risk_label"],
            "Attack_type":     r["attack_classification"]["primary_type"],
            "Attack_conf":     r["attack_classification"]["confidence"],
            "YARA_rules":      yara_rules,
            "MITRE_techniques":mitre_ids,
            "MB_found":        r["malwarebazaar"].get("found", False),
            "MB_signature":    r["malwarebazaar"].get("signature", ""),
            "ML_label":        ml,
            "P_malicious":     r["ml_verdict"].get("probability_malicious", ""),
            "JS_snippets":     len(fe.get("javascript_snippets", [])),
            "Embedded_files":  len(fe.get("embedded_files", [])),
            "Anomalies":       " | ".join(r["anomalies"]),
            "Global_entropy":  r["global_entropy"],
        })

    if rows:
        with open(output_csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader(); w.writerows(rows)
        print(f"\n  Results saved → {output_csv}")
        if not force_forensic:
            n_mal = sum(1 for r in rows if r["Path_taken"] == "MALICIOUS")
            print(f"  Path split: {n_mal} MALICIOUS (full forensic) / "
                  f"{len(rows) - n_mal} BENIGN (basic report)")


# ═══════════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog="pdf_forensic_v2.py",
        description="PDF Forensic Analyser v2 — YARA, MITRE ATT&CK, attack classification",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python pdf_forensic_v2.py --pdf sample.pdf\n"
            "  python pdf_forensic_v2.py --pdf sample.pdf --json\n"
            "  python pdf_forensic_v2.py --pdf sample.pdf --out report.json\n"
            "  python pdf_forensic_v2.py --pdf sample.pdf --no-lookup\n"
            "  python pdf_forensic_v2.py --batch ./pdfs --output results.csv\n"
        ),
    )
    parser.add_argument("--pdf",       metavar="FILE")
    parser.add_argument("--batch",     metavar="FOLDER")
    parser.add_argument("--output",    metavar="FILE",  default="forensic_v2_results.csv")
    parser.add_argument("--out",       metavar="FILE",  help="Save JSON report to file")
    parser.add_argument("--html",      metavar="FILE",  help="Save HTML report to file")
    parser.add_argument("--json",      action="store_true", help="Print JSON to stdout")
    parser.add_argument("--no-lookup", action="store_true", dest="no_lookup",
                        help="Skip MalwareBazaar lookup")
    parser.add_argument("--force-forensic", action="store_true", dest="force_forensic",
                        help="Always run full forensic analysis, skipping the "
                             "ML detect-first gate (use for testing/validation "
                             "against a folder that's already known-malicious)")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--model",     metavar="FILE", default="artifacts/model_random_forest.pkl")
    parser.add_argument("--features",  metavar="FILE", default="artifacts/final_features.csv")

    args = parser.parse_args()
    if not args.pdf and not args.batch:
        parser.print_help(); sys.exit(1)

    if args.batch:
        batch_forensic_v2(args.batch, args.output, args.model, args.features,
                          args.threshold, do_lookup=not args.no_lookup,
                          force_forensic=args.force_forensic)
        return

    if not os.path.exists(args.pdf):
        sys.exit(RED(f"  [ERROR] File not found: {args.pdf}"))

    if args.force_forensic:
        result = forensic_analyse_v2(
            args.pdf, args.model, args.features, args.threshold,
            do_lookup=not args.no_lookup,
        )
        result["path_taken"] = "MALICIOUS"
    else:
        result = detect_and_analyze(
            args.pdf, args.model, args.features, args.threshold,
            do_lookup=not args.no_lookup,
        )

    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(generate_html_report(result))
        print(f"HTML report saved → {args.html}")

    if args.json or args.out:
        json_str = json.dumps(result, indent=2, default=str)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(json_str)
            print(f"Report saved → {args.out}")
        if args.json:
            print(json_str)
        return

    if not args.html:
        print_report(result)

    if result.get("risk_label") in ("CRITICAL", "HIGH"):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

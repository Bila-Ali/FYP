"""
PDF Malware Detection - Feature Extraction Pipeline
====================================================
FYP: An Integrated AI System for Detection, Remediation, and Forensic Analysis of PDF-Based Malware
Team: Bilawal Ali (22BSCYS002) & Sagar (22BSCYS049)
Dept: BS Cyber Security, MUET

This script extracts the same 32 features used in PDFMalware2022.csv from any raw PDF file.
It uses pdfid.py (Didier Stevens) + pdfinfo (poppler) + manual structural parsing.

Usage:
    python feature_extractor.py <pdf_file>
    python feature_extractor.py <pdf_file> --json
    python feature_extractor.py --batch <folder_of_pdfs> --output features.csv

Requirements:
    pip install pdfminer.six pypdf
    apt install poppler-utils   (for pdfinfo)
    Download pdfid.py from: https://github.com/DidierStevens/DidierStevensSuite
"""

import os
import re
import sys
import csv
import json
import struct
import argparse
import subprocess
from pathlib import Path


# ─────────────────────────────────────────────
# 1. LOW-LEVEL BINARY PARSER  (no external deps)
# ─────────────────────────────────────────────

def read_pdf_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def extract_header(data: bytes) -> str:
    """Return PDF header e.g. %PDF-1.6"""
    match = re.search(rb'(%PDF-[\d.\\x]+)', data[:1024])
    if match:
        return match.group(1).decode(errors="replace").strip()
    return "unknown"


def count_keyword(data: bytes, keyword: bytes) -> int:
    return len(re.findall(keyword, data))


def extract_binary_features(data: bytes) -> dict:
    """
    Counts structural PDF keywords directly from raw bytes.
    Matches the columns: obj, endobj, stream, endstream, xref,
    trailer, startxref, pageno, encrypt, ObjStm, JS, Javascript,
    AA, OpenAction, Acroform, JBIG2Decode, RichMedia, launch,
    EmbeddedFile, XFA, Colors
    """
    features = {}

    features["header"]      = extract_header(data)
    features["obj"]         = count_keyword(data, rb'\bobj\b')
    features["endobj"]      = count_keyword(data, rb'\bendobj\b')
    features["stream"]      = count_keyword(data, rb'\bstream\b')
    features["endstream"]   = count_keyword(data, rb'\bendstream\b')
    features["xref"]        = count_keyword(data, rb'\bxref\b')
    features["trailer"]     = count_keyword(data, rb'\btrailer\b')
    features["startxref"]   = count_keyword(data, rb'\bstartxref\b')
    features["pageno"]      = count_keyword(data, rb'/Page\b')
    features["encrypt"]     = count_keyword(data, rb'/Encrypt\b')

    # Suspicious / malicious keywords (key threat indicators)
    features["ObjStm"]      = count_keyword(data, rb'/ObjStm\b')
    features["JS"]          = count_keyword(data, rb'/JS\b')
    features["Javascript"]  = count_keyword(data, rb'/JavaScript\b')
    features["AA"]          = count_keyword(data, rb'/AA\b')
    features["OpenAction"]  = count_keyword(data, rb'/OpenAction\b')
    features["Acroform"]    = count_keyword(data, rb'/AcroForm\b')
    features["JBIG2Decode"] = count_keyword(data, rb'/JBIG2Decode\b')
    features["RichMedia"]   = count_keyword(data, rb'/RichMedia\b')
    features["launch"]      = count_keyword(data, rb'/Launch\b')
    features["EmbeddedFile"]= count_keyword(data, rb'/EmbeddedFile\b')
    features["XFA"]         = count_keyword(data, rb'/XFA\b')
    features["Colors"]      = count_keyword(data, rb'/Colors\b')

    return features


# ─────────────────────────────────────────────
# 2. METADATA FEATURES  (pdfinfo / pypdf)
# ─────────────────────────────────────────────

def extract_metadata_features(path: str, data: bytes) -> dict:
    """
    Extracts: pdfsize, metadata size, pages, xref Length,
    title characters, isEncrypted, embedded files, images, text
    """
    features = {}

    # File size in KB
    features["pdfsize"] = round(os.path.getsize(path) / 1024, 2)

    # Try pdfinfo (poppler) first — fast and reliable
    try:
        result = subprocess.run(
            ["pdfinfo", path],
            capture_output=True, text=True, timeout=10
        )
        info = result.stdout

        # Pages
        m = re.search(r'Pages:\s+(\d+)', info)
        features["pages"] = int(m.group(1)) if m else 0

        # Encrypted
        m = re.search(r'Encrypted:\s+(\w+)', info)
        features["isEncrypted"] = 1 if (m and m.group(1).lower() == "yes") else 0

        # File size from pdfinfo (more accurate)
        m = re.search(r'File size:\s+(\d+)', info)
        if m:
            features["pdfsize"] = round(int(m.group(1)) / 1024, 2)

    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Fallback: parse bytes manually
        features.setdefault("pages", count_keyword(data, rb'/Type\s*/Page\b'))
        features.setdefault("isEncrypted", 1 if b'/Encrypt' in data else 0)

    # Metadata block size (bytes between << ... >> near /Info or first trailer)
    meta_match = re.search(rb'<<(.{0,2000}?)>>', data[:8192], re.DOTALL)
    features["metadata size"] = len(meta_match.group(0)) if meta_match else 0

    # xref table length (number of entries)
    xref_match = re.search(rb'xref\s+\d+\s+(\d+)', data)
    features["xref Length"] = int(xref_match.group(1)) if xref_match else 0

    # Title characters (length of /Title string)
    title_match = re.search(rb'/Title\s*\(([^)]*)\)', data)
    features["title characters"] = len(title_match.group(1)) if title_match else 0

    # Embedded files count
    features["embedded files"] = count_keyword(data, rb'/EmbeddedFile\b')

    # Images count
    features["images"] = count_keyword(data, rb'/Image\b')

    # Text extractability
    # Check for readable text streams
    text_streams = re.findall(rb'stream\r?\n(.*?)\r?\nendstream', data[:50000], re.DOTALL)
    has_text = any(
        b'BT' in s and b'ET' in s  # Begin/End Text operators
        for s in text_streams
    )
    # Also check for /Text subtype
    has_text = has_text or b'/Text' in data[:50000]
    if has_text:
        features["text"] = "Yes"
    elif not text_streams:
        features["text"] = "unclear"
    else:
        features["text"] = "No"

    return features


# ─────────────────────────────────────────────
# 3. MAIN EXTRACTOR
# ─────────────────────────────────────────────

# These match EXACTLY the column order in PDFMalware2022.csv
FEATURE_COLUMNS = [
    "pdfsize", "metadata size", "pages", "xref Length", "title characters",
    "isEncrypted", "embedded files", "images", "text", "header",
    "obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref",
    "pageno", "encrypt", "ObjStm", "JS", "Javascript", "AA", "OpenAction",
    "Acroform", "JBIG2Decode", "RichMedia", "launch", "EmbeddedFile",
    "XFA", "Colors"
]


def extract_features(pdf_path: str) -> dict:
    """
    Main function: returns a flat dict of all 31 features for one PDF.
    Keys match the column names in PDFMalware2022.csv exactly.
    """
    path = str(pdf_path)

    try:
        data = read_pdf_bytes(path)
    except Exception as e:
        print(f"[ERROR] Cannot read {path}: {e}", file=sys.stderr)
        return None

    meta = extract_metadata_features(path, data)
    binary = extract_binary_features(data)

    # Merge, resolving any overlap (meta takes priority for shared keys)
    features = {**binary, **meta}

    # Ensure all expected columns exist with defaults
    result = {"File name": Path(path).name}
    for col in FEATURE_COLUMNS:
        result[col] = features.get(col, 0)

    return result


def print_features(features: dict, fmt: str = "table"):
    if fmt == "json":
        print(json.dumps(features, indent=2))
        return

    print(f"\n{'─'*55}")
    print(f"  PDF Feature Report: {features['File name']}")
    print(f"{'─'*55}")

    # Group display
    groups = {
        "📄 File Info": ["pdfsize", "pages", "isEncrypted", "text"],
        "🔧 Structure": ["obj", "endobj", "stream", "endstream", "xref",
                         "trailer", "startxref", "pageno", "xref Length",
                         "metadata size", "title characters", "header"],
        "🚨 Threat Indicators": ["encrypt", "ObjStm", "JS", "Javascript",
                                  "AA", "OpenAction", "Acroform", "JBIG2Decode",
                                  "RichMedia", "launch", "EmbeddedFile",
                                  "XFA", "Colors", "embedded files", "images"],
    }

    for group, cols in groups.items():
        print(f"\n  {group}")
        for col in cols:
            val = features.get(col, "N/A")
            # Highlight non-zero threat indicators
            flag = " ⚠️ " if (group == "🚨 Threat Indicators" and val not in (0, "0", "No", 0.0)) else "   "
            print(f"  {flag}{col:<20} {val}")

    # Quick threat summary
    threat_keys = ["JS", "Javascript", "OpenAction", "AA", "launch",
                   "JBIG2Decode", "RichMedia", "XFA", "ObjStm"]
    threats_found = [k for k in threat_keys if features.get(k, 0) not in (0, 0.0)]
    print(f"\n  {'─'*53}")
    if threats_found:
        print(f"  ⚠️  Suspicious keywords detected: {', '.join(threats_found)}")
    else:
        print(f"  ✅  No obvious threat keywords found")
    print(f"{'─'*55}\n")


# ─────────────────────────────────────────────
# 4. BATCH MODE
# ─────────────────────────────────────────────

def batch_extract(folder: str, output_csv: str):
    """
    Scan a folder for PDFs, extract features from each,
    and save to a CSV compatible with PDFMalware2022.csv format.
    """
    pdf_files = list(Path(folder).rglob("*.pdf"))
    if not pdf_files:
        print(f"[!] No PDF files found in {folder}")
        return

    print(f"[*] Found {len(pdf_files)} PDF files. Extracting features...")

    all_features = []
    for i, pdf_path in enumerate(pdf_files, 1):
        print(f"  [{i}/{len(pdf_files)}] {pdf_path.name}", end="\r")
        feats = extract_features(str(pdf_path))
        if feats:
            feats["Class"] = ""  # Label to be filled manually or by classifier
            all_features.append(feats)

    if not all_features:
        print("[!] No features extracted.")
        return

    # Write CSV
    fieldnames = ["File name"] + FEATURE_COLUMNS + ["Class"]
    with open(output_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_features)

    print(f"\n[✓] Features saved to: {output_csv}  ({len(all_features)} files)")


# ─────────────────────────────────────────────
# 5. CLI ENTRY POINT
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PDF Feature Extractor — FYP PDF Malware Detection"
    )
    parser.add_argument("pdf", nargs="?", help="Single PDF file to analyse")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--batch", metavar="FOLDER",
                        help="Batch mode: extract features from all PDFs in folder")
    parser.add_argument("--output", metavar="FILE", default="extracted_features.csv",
                        help="Output CSV path for batch mode (default: extracted_features.csv)")

    args = parser.parse_args()

    if args.batch:
        batch_extract(args.batch, args.output)
    elif args.pdf:
        if not os.path.isfile(args.pdf):
            print(f"[ERROR] File not found: {args.pdf}")
            sys.exit(1)
        features = extract_features(args.pdf)
        if features:
            fmt = "json" if args.json else "table"
            print_features(features, fmt)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

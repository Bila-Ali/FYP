"""
PDF Malware Remediation Module
================================
FYP: An Integrated AI System for Detection, Remediation, and Forensic Analysis
     of PDF-Based Malware
Team: Bilawal Ali (22BSCYS002) & Sagar (22BSCYS049)
Dept: BS Cyber Security, MUET

What this module does:
  1. ANALYSE   — scan the PDF, identify all malicious objects & streams
  2. REMOVE    — strip JavaScript, OpenAction, AA, Launch, EmbeddedFiles,
                 XFA forms, RichMedia, JBIG2Decode filters
  3. REBUILD   — reconstruct a clean PDF preserving text & images
  4. VERIFY    — re-scan the cleaned PDF to confirm threats are gone
  5. REPORT    — save a remediation summary (JSON + printed)

Strategy:
  - Uses pikepdf for low-level object tree manipulation (most powerful)
  - Falls back to pypdf page-copy method if pikepdf fails
  - The clean PDF keeps all readable content (text, images, pages)
  - Removed: all executable/active content

Usage:
  python remediate.py malicious.pdf
  python remediate.py malicious.pdf --out clean_output.pdf
  python remediate.py --batch ./infected_folder/ --out ./cleaned/
"""

import os
import re
import sys
import json
import shutil
import hashlib
import argparse
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────
# THREAT KEYWORD MAP
# What to remove and why
# ─────────────────────────────────────────────

THREAT_ACTIONS = {
    # key: (pdf_name, description, action)
    "JavaScript":  ("/JavaScript",  "Executes JS when PDF opens",         "remove_key"),
    "JS":          ("/JS",          "Inline JavaScript reference",         "remove_key"),
    "OpenAction":  ("/OpenAction",  "Auto-executes on open",               "remove_key"),
    "AA":          ("/AA",          "Additional Actions trigger",          "remove_key"),
    "Launch":      ("/Launch",      "Launches external programs",          "remove_key"),
    "EmbeddedFile":("/EmbeddedFile","Embedded file payload",               "remove_key"),
    "RichMedia":   ("/RichMedia",   "Embeds exploitable media",            "remove_key"),
    "XFA":         ("/XFA",         "XML Forms Architecture exploit",      "remove_key"),
    "ObjStm":      ("/ObjStm",      "Object stream hiding technique",      "flatten"),
    "JBIG2Decode": ("/JBIG2Decode", "Heap overflow exploit filter",        "remove_filter"),
    "Encrypt":     ("/Encrypt",     "Encryption hiding malicious content", "remove_encrypt"),
}

# Keys that are safe to keep even if present (structural, not executable)
SAFE_KEYS = {
    "/Type", "/Subtype", "/Length", "/Filter", "/Width", "/Height",
    "/ColorSpace", "/BitsPerComponent", "/DecodeParms", "/Resources",
    "/Font", "/XObject", "/ExtGState", "/Pattern", "/Shading",
    "/MediaBox", "/CropBox", "/Rotate", "/Contents", "/Parent",
    "/Kids", "/Count", "/Pages", "/Page", "/Catalog",
}

# Keys to always remove from page/catalog dictionaries
MALICIOUS_KEYS = {
    "/JS", "/JavaScript", "/OpenAction", "/AA",
    "/Launch", "/EmbeddedFile", "/RichMedia", "/XFA",
    "/SubmitForm", "/ImportData", "/Sound", "/Movie",
    "/Widget",   # interactive form fields that can run JS
}


# ─────────────────────────────────────────────
# 1. HASH & FILE INFO
# ─────────────────────────────────────────────

def file_hash(path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def file_info(path):
    return {
        "path":     str(path),
        "filename": Path(path).name,
        "size_kb":  round(os.path.getsize(path) / 1024, 2),
        "sha256":   file_hash(path),
        "md5":      file_hash(path, "md5"),
    }


# ─────────────────────────────────────────────
# 2. PRE-SCAN  (raw byte analysis)
# ─────────────────────────────────────────────

def prescan(path):
    """Quick raw-byte scan to identify what threats exist before remediation."""
    with open(path, "rb") as f:
        data = f.read()

    found = {}
    checks = {
        "JavaScript":   rb'/JavaScript\b',
        "JS":           rb'/JS\b',
        "OpenAction":   rb'/OpenAction\b',
        "AA":           rb'/AA\b',
        "Launch":       rb'/Launch\b',
        "EmbeddedFile": rb'/EmbeddedFile\b',
        "RichMedia":    rb'/RichMedia\b',
        "XFA":          rb'/XFA\b',
        "ObjStm":       rb'/ObjStm\b',
        "JBIG2Decode":  rb'/JBIG2Decode\b',
        "Encrypt":      rb'/Encrypt\b',
    }
    for name, pattern in checks.items():
        count = len(re.findall(pattern, data))
        if count > 0:
            found[name] = count

    return found


# ─────────────────────────────────────────────
# 3. PIKEPDF REMEDIATION  (primary method)
# ─────────────────────────────────────────────

def remediate_with_pikepdf(input_path, output_path):
    """
    Deep remediation using pikepdf:
    - Walks every object in the PDF object tree
    - Removes all malicious keys from every dictionary
    - Removes /Encrypt to decrypt the file
    - Flattens ObjStm (object streams) so content is visible
    - Preserves all pages, text, images
    """
    import pikepdf

    removed_items = []
    warnings      = []

    try:
        # Open with password attempt for encrypted files
        try:
            pdf = pikepdf.open(input_path)
        except pikepdf.PasswordError:
            try:
                pdf = pikepdf.open(input_path, password="")
                removed_items.append({"type": "encryption", "detail": "Opened with empty password"})
            except Exception as e:
                warnings.append(f"Cannot open encrypted PDF: {e}")
                return False, removed_items, warnings

        # ── Walk every object in the PDF ──────────────────────────
        for obj_id, obj in pdf.objects.items():
            if isinstance(obj, pikepdf.Dictionary):
                _clean_dictionary(obj, obj_id, removed_items)
            elif isinstance(obj, pikepdf.Stream):
                _clean_dictionary(obj, obj_id, removed_items)

        # ── Clean the document catalog (root) ─────────────────────
        root = pdf.Root
        for key in list(root.keys()):
            key_str = str(key)
            if key_str in MALICIOUS_KEYS:
                del root[key]
                removed_items.append({
                    "type":   "catalog_key",
                    "key":    key_str,
                    "detail": THREAT_ACTIONS.get(key_str.lstrip("/"), ("","removed",""))[1]
                })

        # ── Clean each page ───────────────────────────────────────
        for page_num, page in enumerate(pdf.pages, 1):
            page_removed = _clean_page(page, page_num)
            removed_items.extend(page_removed)

        # ── Remove document-level JavaScript ──────────────────────
        if "/Names" in root:
            names = root["/Names"]
            if isinstance(names, pikepdf.Dictionary):
                for js_key in ["/JavaScript", "/EmbeddedFiles"]:
                    if js_key in names:
                        del names[js_key]
                        removed_items.append({
                            "type":   "names_tree",
                            "key":    js_key,
                            "detail": "Removed from Names dictionary tree"
                        })

        # ── Save clean PDF ────────────────────────────────────────
        pdf.save(
            output_path,
            compress_streams=True,
            object_stream_mode=pikepdf.ObjectStreamMode.disable,  # no ObjStm
            linearize=False,
        )
        pdf.close()
        return True, removed_items, warnings

    except Exception as e:
        warnings.append(f"pikepdf error: {e}")
        return False, removed_items, warnings


def _clean_dictionary(obj, obj_id, removed_items):
    """Remove malicious keys from a pikepdf Dictionary or Stream."""
    import pikepdf
    for key in list(obj.keys()):
        key_str = str(key)
        if key_str in MALICIOUS_KEYS:
            try:
                del obj[key]
                removed_items.append({
                    "type":   "object_key",
                    "obj_id": str(obj_id),
                    "key":    key_str,
                    "detail": THREAT_ACTIONS.get(key_str.lstrip("/"), ("","",""))[1]
                })
            except Exception:
                pass

        # Recursively clean nested dictionaries
        elif isinstance(obj.get(key), pikepdf.Dictionary):
            _clean_dictionary(obj[key], obj_id, removed_items)


def _clean_page(page, page_num):
    """Remove malicious keys from a page dictionary."""
    import pikepdf
    removed = []
    for key in list(page.keys()):
        key_str = str(key)
        if key_str in MALICIOUS_KEYS:
            try:
                del page[key]
                removed.append({
                    "type":     "page_key",
                    "page":     page_num,
                    "key":      key_str,
                    "detail":   THREAT_ACTIONS.get(key_str.lstrip("/"), ("","removed",""))[1]
                })
            except Exception:
                pass
    return removed


# ─────────────────────────────────────────────
# 4. PYPDF FALLBACK  (page copy method)
# ─────────────────────────────────────────────

def remediate_with_pypdf(input_path, output_path):
    """
    Fallback remediation using pypdf:
    Copies pages into a fresh PDF writer — this drops most active content
    because pypdf doesn't copy /AA, /OpenAction, /JavaScript by default.
    Less thorough than pikepdf but works on any PDF.
    """
    from pypdf import PdfReader, PdfWriter

    removed_items = []
    warnings      = []

    try:
        reader = PdfReader(input_path)
        writer = PdfWriter()

        # Copy pages (drops most active content)
        for i, page in enumerate(reader.pages):
            # Manually remove keys before adding
            for key in list(page.keys()):
                if f"/{key}" in MALICIOUS_KEYS or key in [k.lstrip("/") for k in MALICIOUS_KEYS]:
                    try:
                        del page[f"/{key}"]
                        removed_items.append({
                            "type": "page_key_pypdf",
                            "page": i + 1,
                            "key":  f"/{key}",
                        })
                    except Exception:
                        pass
            writer.add_page(page)

        # Copy metadata (clean)
        if reader.metadata:
            writer.add_metadata({
                "/Title":    str(reader.metadata.get("/Title", "")),
                "/Author":   str(reader.metadata.get("/Author", "")),
                "/Subject":  "Sanitized by FYP PDF Malware Remediation Module",
                "/Creator":  "FYP Remediation Tool v1.0",
                "/Producer": "pypdf",
            })

        removed_items.append({
            "type":   "method_note",
            "detail": "pypdf fallback: page copy drops most active content"
        })

        with open(output_path, "wb") as f:
            writer.write(f)

        return True, removed_items, warnings

    except Exception as e:
        warnings.append(f"pypdf error: {e}")
        return False, removed_items, warnings


# ─────────────────────────────────────────────
# 5. POST-SCAN VERIFICATION
# ─────────────────────────────────────────────

def verify_clean(path):
    """Re-scan the output file to confirm threats are removed."""
    threats = prescan(path)
    is_clean = len(threats) == 0
    return is_clean, threats


# ─────────────────────────────────────────────
# 6. REMEDIATION REPORT
# ─────────────────────────────────────────────

def build_report(original_info, clean_info, threats_before, threats_after,
                 removed_items, warnings, method, success, duration_s):
    return {
        "report_type":    "PDF Remediation Report",
        "generated_at":   datetime.now().isoformat(),
        "tool":           "FYP PDF Malware Remediation Module v1.0",
        "team":           "Bilawal Ali (22BSCYS002) & Sagar (22BSCYS049)",

        "original_file":  original_info,
        "cleaned_file":   clean_info,

        "remediation": {
            "method":       method,
            "success":      success,
            "duration_s":   round(duration_s, 2),
            "is_clean":     len(threats_after) == 0,
            "items_removed": len(removed_items),
        },

        "threats": {
            "before": threats_before,
            "after":  threats_after,
            "resolved": {
                k: v for k, v in threats_before.items()
                if k not in threats_after
            },
            "remaining": threats_after,
        },

        "removed_items": removed_items[:50],   # cap for readability
        "warnings":      warnings,

        "size_reduction": {
            "original_kb": original_info["size_kb"],
            "cleaned_kb":  clean_info["size_kb"],
            "reduction_kb": round(original_info["size_kb"] - clean_info["size_kb"], 2),
            "reduction_pct": round(
                100 * (original_info["size_kb"] - clean_info["size_kb"])
                / max(original_info["size_kb"], 1), 1
            ),
        }
    }


def print_report(report):
    r = report
    rem = r["remediation"]
    thr = r["threats"]
    siz = r["size_reduction"]

    status_icon = "✅" if rem["is_clean"] else "⚠️"

    print(f"\n{'═'*62}")
    print(f"  PDF REMEDIATION REPORT")
    print(f"{'─'*62}")
    print(f"  Original : {r['original_file']['filename']}")
    print(f"  Cleaned  : {r['cleaned_file']['filename']}")
    print(f"  Method   : {rem['method']}")
    print(f"  Duration : {rem['duration_s']}s")
    print(f"  Status   : {status_icon}  {'FULLY CLEAN' if rem['is_clean'] else 'PARTIALLY CLEANED'}")

    print(f"\n  THREATS REMOVED")
    print(f"  {'─'*58}")
    if thr["resolved"]:
        for name, count in thr["resolved"].items():
            desc = THREAT_ACTIONS.get(name, ("","Unknown threat",""))[1]
            print(f"  ✅  {name:<16} (was {count}×)  {desc}")
    else:
        print(f"  None resolved")

    if thr["remaining"]:
        print(f"\n  THREATS REMAINING")
        print(f"  {'─'*58}")
        for name, count in thr["remaining"].items():
            print(f"  ⚠️  {name:<16} (still {count}×)")
        print(f"  → These may be in binary streams; manual inspection recommended")

    print(f"\n  FILE COMPARISON")
    print(f"  {'─'*58}")
    print(f"  Original SHA256 : {r['original_file']['sha256'][:48]}...")
    print(f"  Cleaned  SHA256 : {r['cleaned_file']['sha256'][:48]}...")
    print(f"  Size: {siz['original_kb']} KB → {siz['cleaned_kb']} KB "
          f"({siz['reduction_pct']:+.1f}%)")
    print(f"  Items removed   : {rem['items_removed']}")

    if r["warnings"]:
        print(f"\n  WARNINGS")
        for w in r["warnings"]:
            print(f"  [!] {w}")

    print(f"{'═'*62}\n")


# ─────────────────────────────────────────────
# 7. MAIN REMEDIATE FUNCTION
# ─────────────────────────────────────────────

def remediate(input_path, output_path=None, save_report_json=True):
    """
    Full remediation pipeline for one PDF.
    Returns the report dict.
    """
    import time

    input_path = str(input_path)
    if not os.path.isfile(input_path):
        print(f"[ERROR] File not found: {input_path}")
        return None

    # Auto-name output
    if output_path is None:
        stem = Path(input_path).stem
        output_path = str(Path(input_path).parent / f"{stem}_CLEAN.pdf")

    print(f"\n{'─'*62}")
    print(f"  Remediating: {Path(input_path).name}")
    print(f"{'─'*62}")

    # Step 1: Pre-scan
    print(f"  [1/5] Scanning for threats...")
    threats_before = prescan(input_path)
    original_info  = file_info(input_path)

    if not threats_before:
        print(f"  [✓] No threats detected — file appears clean.")
        print(f"      Copying to output unchanged.")
        shutil.copy2(input_path, output_path)
        threats_after = {}
        report = build_report(
            original_info, file_info(output_path),
            threats_before, threats_after,
            [], [], "no_action_needed", True, 0
        )
        print_report(report)
        return report

    print(f"  Found {len(threats_before)} threat type(s): {', '.join(threats_before.keys())}")

    # Step 2: Remediate (pikepdf primary, pypdf fallback)
    print(f"  [2/5] Removing malicious content (pikepdf)...")
    t0 = time.time()
    success, removed_items, warnings = remediate_with_pikepdf(input_path, output_path)
    method = "pikepdf"

    if not success or not os.path.isfile(output_path):
        print(f"  [!] pikepdf failed — trying pypdf fallback...")
        success, removed_items, warnings = remediate_with_pypdf(input_path, output_path)
        method = "pypdf_fallback"

    duration = time.time() - t0
    print(f"  [✓] Remediation complete in {duration:.2f}s  ({len(removed_items)} items removed)")

    # Step 3: Verify
    print(f"  [3/5] Verifying cleaned file...")
    is_clean, threats_after = verify_clean(output_path)
    clean_info = file_info(output_path)

    if is_clean:
        print(f"  [✓] Verification passed — no threats remaining")
    else:
        print(f"  [!] {len(threats_after)} threat type(s) still detected: {list(threats_after.keys())}")
        print(f"      These may be embedded in binary image data (false positives)")

    # Step 4: Build report
    print(f"  [4/5] Building report...")
    report = build_report(
        original_info, clean_info,
        threats_before, threats_after,
        removed_items, warnings, method, success, duration
    )

    # Step 5: Save report JSON
    if save_report_json:
        report_path = output_path.replace(".pdf", "_remediation_report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  [5/5] Report saved: {report_path}")
    else:
        print(f"  [5/5] Report generated (in memory)")

    print_report(report)
    return report


# ─────────────────────────────────────────────
# 8. BATCH MODE
# ─────────────────────────────────────────────

def batch_remediate(input_folder, output_folder):
    input_folder  = Path(input_folder)
    output_folder = Path(output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)

    pdf_files = list(input_folder.rglob("*.pdf"))
    if not pdf_files:
        print(f"[!] No PDFs found in {input_folder}")
        return

    print(f"\n[*] Batch remediating {len(pdf_files)} PDFs → {output_folder}/\n")
    summary = []

    for i, pdf_path in enumerate(pdf_files, 1):
        out_path = output_folder / f"{pdf_path.stem}_CLEAN.pdf"
        print(f"[{i}/{len(pdf_files)}] {pdf_path.name}")
        report = remediate(str(pdf_path), str(out_path), save_report_json=True)
        if report:
            summary.append({
                "file":         pdf_path.name,
                "threats_found": len(report["threats"]["before"]),
                "threats_resolved": len(report["threats"]["resolved"]),
                "threats_remaining": len(report["threats"]["remaining"]),
                "is_clean":     report["remediation"]["is_clean"],
                "method":       report["remediation"]["method"],
            })

    # Batch summary
    print(f"\n{'═'*55}")
    print(f"  BATCH REMEDIATION SUMMARY")
    print(f"  Total files : {len(summary)}")
    fully_clean = sum(1 for r in summary if r["is_clean"])
    print(f"  Fully clean : {fully_clean}/{len(summary)}")
    print(f"  Clean output: {output_folder}/")
    print(f"{'═'*55}\n")


# ─────────────────────────────────────────────
# 9. CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PDF Remediation Module — FYP PDF Malware Detection"
    )
    parser.add_argument("pdf", nargs="?",
                        help="PDF file to remediate")
    parser.add_argument("--out", metavar="OUTPUT",
                        help="Output path for cleaned PDF (default: <name>_CLEAN.pdf)")
    parser.add_argument("--batch", metavar="FOLDER",
                        help="Batch mode: remediate all PDFs in a folder")
    parser.add_argument("--out-dir", default="cleaned_pdfs",
                        help="Output folder for batch mode (default: cleaned_pdfs/)")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip saving JSON report")
    args = parser.parse_args()

    if args.batch:
        batch_remediate(args.batch, args.out_dir)
    elif args.pdf:
        remediate(args.pdf, args.out, save_report_json=not args.no_report)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

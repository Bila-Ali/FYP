#!/usr/bin/env python3
"""
extract_features.py

PDF malware feature-extraction pipeline that reproduces the feature sets
described in:
  "PDF Malware Detection: Toward Machine Learning Modeling With
   Explainability Analysis" (Hossain et al., IEEE Access, 2024)

It orchestrates THREE vendored tools (kept unmodified in tools/, aside from
the pdfinfo.py clone which is the paper's own patched re-implementation):
  - tools/pdfid.py        -> Feature Set F1  (22 features, PDFiD keyword counts)
  - tools/pdfinfo.py      -> Feature Set F2  (patched PyMuPDF-based pdfinfo clone)
  - tools/pdf-parser.py   -> Feature Set F3  (27 features, keyword counts in the
                                               full parsed-object dump)

and then computes the paper's 7 hand-engineered "derived features" from F1.

--------------------------------------------------------------------------
CHANGES vs. the original prototype
--------------------------------------------------------------------------
- Column names and constants now come from pdf_malware.config, the single
  source of truth also used by every downstream script (previously each
  script redefined its own copies of these lists).
- Removed to_model_matrix() / --model-matrix-out: dead code with zero
  callers anywhere in the pipeline; every downstream script builds its own
  model matrix via pdf_malware.preprocessing.preprocess_dataset() instead,
  which is the version that is actually used.
- f2_page_width / f2_page_height / f2_pdf_version_num / f2_mupdf_errors are
  still extracted (useful for EDA) but are explicitly documented as
  engineering extras, NOT part of the paper's 14-feature F2 set -- see
  pdf_malware/config.py for why using raw width/height as ML features would
  double-count the page-size signal already captured by f2_page_size_class.
- print() progress/status output replaced with logging (see
  pdf_malware.logging_utils), written to logs/extraction.log.
- Smart per-class directory backfilling, in-process F3 extraction (avoids
  one interpreter spawn per file), and the leak/duplicate report are kept
  unchanged -- these are reproducibility/performance engineering, not
  methodology, and were already correct.

--------------------------------------------------------------------------
REQUIRED FOLDER LAYOUT
--------------------------------------------------------------------------
<script dir>/tools/pdfid.py
<script dir>/tools/pdfinfo.py
<script dir>/tools/pdf-parser.py

--------------------------------------------------------------------------
REQUIREMENTS
--------------------------------------------------------------------------
pip install --break-system-packages pymupdf pandas

Usage:
    python extract_features.py --benign DIR [DIR ...] --malicious DIR [DIR ...]
                                --out dataset/dataset.csv
                                [--limit-per-dir N] [--strict-per-dir-cap]
                                [--balance-classes]
                                [--workers N] [--leak-report] [--seed N]
                                [--pdfparser-subprocess]
                                [--pdfparser-timeout SEC]
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib.util
import io
import os
import random
import re
import subprocess
import sys
import threading
import traceback
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Optional

import pandas as pd

from pdf_malware.config import DERIVED_ALL, F1_ALL_COLUMNS, F3_NUMERIC, RANDOM_SEED
from pdf_malware.logging_utils import get_logger

logger = get_logger(__name__, "extraction.log")

# --------------------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------------------

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")

PDFID_PATH = os.path.join(TOOLS_DIR, "pdfid.py")
PDFINFO_PATH = os.path.join(TOOLS_DIR, "pdfinfo.py")
PDFPARSER_PATH = os.path.join(TOOLS_DIR, "pdf-parser.py")

PDFPARSER_TIMEOUT_SEC = 60  # guard against malformed/huge PDFs hanging

# --------------------------------------------------------------------------
# Import pdfid.py, pdfinfo.py, and pdf-parser.py as modules. All three run
# in-process (no hyphens block a normal `import` for pdfid.py, and
# importlib.util.spec_from_file_location sidesteps the hyphen in
# pdf-parser.py's filename for the other two). This block runs in every
# worker process too (ProcessPoolExecutor re-imports this module on
# Windows/spawn, and inherits it via fork on Linux/Mac).
# --------------------------------------------------------------------------

sys.path.insert(0, TOOLS_DIR)
import pdfid  # noqa: E402


def _load_module_from_path(name: str, path: str):
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception as e:
        logger.warning("Could not load %s (%s).", path, e)
        return None


pdfinfo_tool = _load_module_from_path("pdfinfo_tool", PDFINFO_PATH)
pdfparser_tool = _load_module_from_path("pdfparser_tool", PDFPARSER_PATH)


# ==========================================================================
# F1 - PDFiD features (22, incl. raw header string)
# ==========================================================================

F1_COLUMNS = F1_ALL_COLUMNS


def extract_f1(filepath: str) -> dict:
    """Run pdfid.py (in-process) and return the 22 F1 features as a dict."""
    xml_doc = pdfid.PDFiD(filepath, False, False, False, True)  # force=True
    o = pdfid.cPDFiD(xml_doc, True)
    return {
        "f1_header_raw": o.header,
        "f1_obj": o.obj.count,
        "f1_endobj": o.endobj.count,
        "f1_stream": o.stream.count,
        "f1_endstream": o.endstream.count,
        "f1_xref": o.xref.count,
        "f1_trailer": o.trailer.count,
        "f1_startxref": o.startxref.count,
        "f1_page": o.page.count,
        "f1_encrypt": o.encrypt.count,
        "f1_objstm": o.objstm.count,
        "f1_js": o.js.count,
        "f1_javascript": o.javascript.count,
        "f1_aa": o.aa.count,
        "f1_openaction": o.openaction.count,
        "f1_acroform": o.acroform.count,
        "f1_jbig2decode": o.jbig2decode.count,
        "f1_richmedia": o.richmedia.count,
        "f1_launch": o.launch.count,
        "f1_embeddedfile": o.embeddedfile.count,
        "f1_xfa": o.xfa.count,
        "f1_colors_gt_2_24": o.colors_gt_2_24.count,
    }


# ==========================================================================
# F2 - pdfinfo.py features
# ==========================================================================

# Paper-faithful 14 features + engineering extras (see pdf_malware.config
# for why the extras are excluded from every ML-facing feature set).
F2_COLUMNS = [
    "f2_custom_metadata", "f2_metadata_stream", "f2_tagged", "f2_userproperties",
    "f2_suspects", "f2_form", "f2_javascript", "f2_pages", "f2_encrypted",
    "f2_page_width", "f2_page_height", "f2_page_size_class", "f2_page_rot",
    "f2_filesize_kb", "f2_optimized", "f2_pdf_version", "f2_pdf_version_num",
    "f2_mupdf_errors",
]

_VALID_FORM_VALUES = {"AcroForm", "XFA", "none"}


def _classify_page_size(width: Optional[float], height: Optional[float]) -> str:
    if width is None or height is None:
        return "miscsize"
    w, h = round(width), round(height)
    long_side, short_side = max(w, h), min(w, h)
    known = {
        (792, 612): "letter",
        (842, 595): "a4",
        (1191, 842): "a3",
        (1008, 612): "legal",
    }
    return known.get((long_side, short_side), "miscsize")


def extract_f2(filepath: str) -> dict:
    if pdfinfo_tool is None:
        raise RuntimeError("pdfinfo.py unavailable (PyMuPDF not installed)")

    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            pdfinfo_tool.analyze_pdf(filepath)
    except Exception:
        pass

    lines = buf.getvalue().splitlines()
    fields = {}
    for line in lines:
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()

    def yn(key: str) -> int:
        return 1 if fields.get(key, "").lower() in ("yes", "true") else 0

    width = height = None
    if "Page size" in fields:
        m = re.match(r"(\d+)\s*x\s*(\d+)", fields["Page size"])
        if m:
            width, height = int(m.group(1)), int(m.group(2))

    filesize_bytes = 0
    if "File size" in fields:
        m = re.match(r"(\d+)", fields["File size"])
        if m:
            filesize_bytes = int(m.group(1))

    form_raw = fields.get("Form", "none")
    form = form_raw if form_raw in _VALID_FORM_VALUES else "none"

    pdf_version_raw = fields.get("PDF version", "unknown")
    pdf_version_num = None
    m = re.match(r"(\d+)\.(\d+)", pdf_version_raw)
    if m:
        pdf_version_num = float(f"{m.group(1)}.{m.group(2)}")

    mupdf_errors = 0
    m = re.match(r"(\d+)", fields.get("MuPDF Errors", "0"))
    if m:
        mupdf_errors = int(m.group(1))

    return {
        "f2_custom_metadata": yn("Custom Metadata"),
        "f2_metadata_stream": yn("Metadata Stream"),
        "f2_tagged": yn("Tagged"),
        "f2_userproperties": yn("UserProperties"),
        "f2_suspects": yn("Suspects"),
        "f2_form": form,
        "f2_javascript": yn("JavaScript"),
        "f2_pages": int(fields.get("Pages", 0) or 0),
        "f2_encrypted": yn("Encrypted"),
        "f2_page_width": width,
        "f2_page_height": height,
        "f2_page_size_class": _classify_page_size(width, height),
        "f2_page_rot": int(fields.get("Page rot", 0) or 0),
        "f2_filesize_kb": round(filesize_bytes / 1024.0, 3),
        "f2_optimized": yn("Optimized"),
        "f2_pdf_version": pdf_version_raw,
        "f2_pdf_version_num": pdf_version_num,
        "f2_mupdf_errors": mupdf_errors,
    }


# ==========================================================================
# F3 - pdf-parser.py features (27)
# ==========================================================================

_F3_KEYWORDS = [
    "/JS", "/JavaScript", "/Size", "startxref", "/Producer", "/ProcSet",
    "/ID", "/S", "/CreationDate", "obj", "xref", "/Font", "/XObject",
    "/ModDate", "/Info", "/XML", "Comment", "/Widget", "Referencing",
    "/FontDescriptor", "/Image", "/Rect", "/Length", "/Action",
]
_F3_KEYWORD_PATTERNS = {kw: re.compile(r"(?<![\w/])" + re.escape(kw) + r"\b") for kw in _F3_KEYWORDS}

F3_COLUMNS = F3_NUMERIC


def _run_pdfparser_subprocess(filepath: str, timeout: float) -> str:
    """Fully isolated fallback path: one new Python process per file. Kept
    as an opt-in (--pdfparser-subprocess) for maximum safety against
    adversarial/hanging PDFs, since a subprocess can be killed outright on
    timeout regardless of platform."""
    try:
        result = subprocess.run(
            [sys.executable, PDFPARSER_PATH, filepath],
            capture_output=True, text=True, timeout=timeout,
            errors="ignore",
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return ""


def _run_pdfparser_inprocess(filepath: str, timeout: float) -> str:
    """Fast default path: call pdf-parser.py's Main() directly in this
    worker process (no interpreter spawn). Runs in a daemon thread so a
    hung/adversarial file can never stall the pipeline: we wait up to
    `timeout` seconds, and if it's not done, we give up on it and move on.
    The abandoned thread is left to run to completion or forever in the
    background (Python threads cannot be forcibly killed) -- a deliberate,
    documented trade-off for a fast default."""
    if pdfparser_tool is None:
        raise RuntimeError("pdf-parser.py failed to load")

    result_holder = {}

    def _worker():
        buf = io.StringIO()
        original_get_arguments = pdfparser_tool.GetArguments
        pdfparser_tool.GetArguments = lambda: [filepath]
        try:
            with contextlib.redirect_stdout(buf):
                try:
                    pdfparser_tool.Main()
                except SystemExit:
                    pass
        except Exception:
            pass
        finally:
            pdfparser_tool.GetArguments = original_get_arguments
        result_holder["output"] = buf.getvalue()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return ""  # gave up waiting - treat F3 as unavailable for this file
    return result_holder.get("output", "")


def extract_f3(filepath: str, use_subprocess: bool = False,
               timeout: float = PDFPARSER_TIMEOUT_SEC) -> dict:
    if use_subprocess or pdfparser_tool is None:
        dump = _run_pdfparser_subprocess(filepath, timeout)
    else:
        dump = _run_pdfparser_inprocess(filepath, timeout)

    row = {}
    for kw in _F3_KEYWORDS:
        col = f"f3_{kw.strip('/').lower()}"
        row[col] = len(_F3_KEYWORD_PATTERNS[kw].findall(dump))

    row["f3_eof"] = dump.count("%EOF")
    row["f3_dict_open"] = dump.count("<<")
    row["f3_dict_close"] = dump.count(">>")
    return row


# ==========================================================================
# Derived features (7; see pdf_malware.config for the leakage note on
# derived_headerlength)
# ==========================================================================

DERIVED_COLUMNS = DERIVED_ALL

_VALID_HEADER_RE = re.compile(r"^%PDF-1\.[0-7]$")
SMALL_CONTENT_THRESHOLD = 14


def sha256_of_file(filepath: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_derived(filename: str, f1: dict) -> dict:
    header = (f1.get("f1_header_raw") or "").strip()
    trigger_counts = [
        f1["f1_js"], f1["f1_javascript"], f1["f1_aa"],
        f1["f1_launch"], f1["f1_openaction"],
    ]
    trigger_hits = sum(1 for c in trigger_counts if c > 0)

    return {
        # NOTE: kept for paper-faithful reproduction and EDA, but excluded
        # from every ML-facing feature set by default -- see
        # pdf_malware.config.LEAKAGE_RISK_FEATURES.
        "derived_headerlength": len(filename),
        "derived_headercorrupt": 0 if _VALID_HEADER_RE.match(header) else 1,
        "derived_smallcontent": 1 if f1["f1_obj"] <= SMALL_CONTENT_THRESHOLD else 0,
        "derived_contentcorrupt": 1 if f1["f1_obj"] != f1["f1_endobj"] else 0,
        "derived_streamcorrupt": 1 if f1["f1_stream"] != f1["f1_endstream"] else 0,
        "derived_malicecontent": 1 if trigger_hits >= 2 else 0,
        "derived_hiddenfile": 1 if f1["f1_embeddedfile"] > 0 else 0,
    }


# ==========================================================================
# Driver (per-file)
# ==========================================================================

def process_file(filepath: str, label: str, use_subprocess_parser: bool = False,
                  pdfparser_timeout: float = PDFPARSER_TIMEOUT_SEC) -> dict:
    filename = os.path.basename(filepath)
    row = {"filename": filename, "filepath": filepath, "label": label}

    try:
        row["sha256"] = sha256_of_file(filepath)
    except Exception:
        logger.error("[HASH FAILED] %s\n%s", filename, traceback.format_exc())
        row["sha256"] = ""

    try:
        f1 = extract_f1(filepath)
    except Exception:
        logger.error("[F1 FAILED] %s\n%s", filename, traceback.format_exc())
        f1 = {c: 0 for c in F1_COLUMNS}
        f1["f1_header_raw"] = ""
    row.update(f1)

    try:
        row.update(extract_f2(filepath))
    except Exception:
        logger.error("[F2 FAILED] %s\n%s", filename, traceback.format_exc())
        f2_defaults = {c: 0 for c in F2_COLUMNS}
        f2_defaults["f2_form"] = "none"
        f2_defaults["f2_pdf_version"] = "unknown"
        f2_defaults["f2_page_size_class"] = "miscsize"
        row.update(f2_defaults)

    try:
        row.update(extract_f3(filepath, use_subprocess_parser, pdfparser_timeout))
    except Exception:
        logger.error("[F3 FAILED] %s\n%s", filename, traceback.format_exc())
        row.update({c: 0 for c in F3_COLUMNS})

    row.update(compute_derived(filename, f1))
    return row


# --------------------------------------------------------------------------
# Dataset collection - smart per-class backfilling (default) or strict
# per-directory cap (--strict-per-dir-cap)
# --------------------------------------------------------------------------

def _list_pdfs(d: str) -> list[str]:
    if not os.path.isdir(d):
        logger.warning("Directory not found, skipping: %s", d)
        return []
    with os.scandir(d) as it:
        return [entry.path for entry in it if entry.is_file() and entry.name.lower().endswith(".pdf")]


def collect_files_strict(dirs, label, limit_per_dir, rng):
    """Cap EACH directory independently. Any shortfall in one directory is
    simply lost (not made up elsewhere)."""
    collected = []
    for d in dirs:
        files = _list_pdfs(d)
        total = len(files)
        if limit_per_dir is not None and total > limit_per_dir:
            files = rng.sample(files, limit_per_dir)
        logger.info("[%s] %s: %d found -> %d selected", label, d, total, len(files))
        collected.extend(files)
    return collected


def collect_files_smart(dirs, label, limit_per_dir, rng):
    """Default: target = limit_per_dir * len(dirs) for this class. Every
    directory is capped at limit_per_dir first; any directory short of that
    cap has its shortfall backfilled from other directories in the same
    class that still have spare capacity."""
    per_dir_files = {d: _list_pdfs(d) for d in dirs}

    if limit_per_dir is None:
        collected = []
        for d in dirs:
            files = per_dir_files[d]
            logger.info("[%s] %s: %d found -> %d selected (no cap)", label, d, len(files), len(files))
            collected.extend(files)
        return collected

    taken = {}
    spare = {}
    for d in dirs:
        files = per_dir_files[d]
        if len(files) > limit_per_dir:
            taken[d] = rng.sample(files, limit_per_dir)
            taken_set = set(taken[d])
            spare[d] = [f for f in files if f not in taken_set]
        else:
            taken[d] = list(files)
            spare[d] = []

    shortfall = sum(max(0, limit_per_dir - len(per_dir_files[d])) for d in dirs)

    if shortfall > 0:
        spare_pool = []
        for d in dirs:
            rng.shuffle(spare[d])
            spare_pool.extend((d, f) for f in spare[d])
        rng.shuffle(spare_pool)

        needed = shortfall
        for d, f in spare_pool:
            if needed <= 0:
                break
            taken[d].append(f)
            needed -= 1

    collected = []
    target_total = limit_per_dir * len(dirs)
    for d in dirs:
        found = len(per_dir_files[d])
        selected = len(taken[d])
        note = ""
        if found < limit_per_dir:
            note = f" (short by {limit_per_dir - found}, backfilled from siblings where possible)"
        elif selected > limit_per_dir:
            note = f" (took {selected - limit_per_dir} extra to backfill sibling shortfall)"
        logger.info("[%s] %s: %d found -> %d selected%s", label, d, found, selected, note)
        collected.extend(taken[d])

    shortage_note = (" (class-wide shortage - not enough files across all dirs to hit target)"
                      if len(collected) < target_total else "")
    logger.info("[%s] target was %d (%d x %d dirs); got %d%s",
                label, target_total, limit_per_dir, len(dirs), len(collected), shortage_note)
    return collected


def balance_classes(benign_files, malicious_files, rng):
    b, m = len(benign_files), len(malicious_files)
    target = min(b, m)
    if b > target:
        benign_files = rng.sample(benign_files, target)
    if m > target:
        malicious_files = rng.sample(malicious_files, target)
    logger.info("--balance-classes: downsampled to %d benign / %d malicious (originally %d / %d)",
                target, target, b, m)
    return benign_files, malicious_files


# --------------------------------------------------------------------------
# Leak report
# --------------------------------------------------------------------------

def write_leak_report(df: pd.DataFrame, out_csv: str) -> None:
    report_path = os.path.splitext(out_csv)[0] + "_leak_report.csv"
    groups = defaultdict(list)
    for _, r in df.iterrows():
        if r["sha256"]:
            groups[r["sha256"]].append((r["filepath"], r["label"]))

    dup_rows = []
    cross_class_hashes = 0
    same_class_dup_hashes = 0
    for h, entries in groups.items():
        if len(entries) < 2:
            continue
        labels = {label for _, label in entries}
        leak_type = "CROSS_CLASS" if len(labels) > 1 else "DUPLICATE"
        if leak_type == "CROSS_CLASS":
            cross_class_hashes += 1
        else:
            same_class_dup_hashes += 1
        for filepath, label in entries:
            dup_rows.append({"sha256": h, "leak_type": leak_type,
                              "filepath": filepath, "label": label,
                              "group_size": len(entries)})

    if dup_rows:
        pd.DataFrame(dup_rows).to_csv(report_path, index=False)

    logger.info("--leak-report: %d hash(es) appear in BOTH classes (cross-class leakage), "
                "%d hash(es) are same-class duplicates.", cross_class_hashes, same_class_dup_hashes)
    if dup_rows:
        logger.info("Details written to %s", report_path)
    else:
        logger.info("No duplicate/leaked files found.")


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="PDF malware feature extraction (F1/F2/F3 + derived).")
    p.add_argument("--benign", nargs="+", required=True, metavar="DIR",
                    help="One or more directories of benign PDFs.")
    p.add_argument("--malicious", nargs="+", required=True, metavar="DIR",
                    help="One or more directories of malicious PDFs.")
    p.add_argument("--out", default="dataset/dataset.csv", help="Output CSV path.")
    p.add_argument("--limit-per-dir", type=int, default=None,
                    help="Per-class target is limit-per-dir x (number of dirs for "
                         "that class). Shortfalls in one dir are backfilled from "
                         "sibling dirs in the same class (see --strict-per-dir-cap "
                         "to disable this).")
    p.add_argument("--strict-per-dir-cap", action="store_true",
                    help="Disable smart backfilling: cap each directory "
                         "independently and never pull shortfall from sibling "
                         "directories.")
    p.add_argument("--balance-classes", action="store_true",
                    help="After collection, downsample the larger class so "
                         "benign and malicious totals match exactly.")
    p.add_argument("--workers", type=int, default=None,
                    help="Parallel worker processes (default: os.cpu_count()).")
    p.add_argument("--leak-report", action="store_true",
                    help="Hash every file (sha256) and report duplicate/cross-class files.")
    p.add_argument("--seed", type=int, default=RANDOM_SEED, help="Random seed for sampling (default: 42).")
    p.add_argument("--pdfparser-subprocess", action="store_true",
                    help="Use one-subprocess-per-file mode for F3 extraction "
                         "instead of the fast in-process default (full OS-level "
                         "isolation per file).")
    p.add_argument("--pdfparser-timeout", type=float, default=PDFPARSER_TIMEOUT_SEC,
                    help=f"Per-file timeout in seconds for F3 extraction "
                         f"(default: {PDFPARSER_TIMEOUT_SEC}).")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    rng = random.Random(args.seed)
    workers = args.workers if args.workers else (os.cpu_count() or 1)

    collect_fn = collect_files_strict if args.strict_per_dir_cap else collect_files_smart

    logger.info("Collecting file lists...")
    benign_files = collect_fn(args.benign, "benign", args.limit_per_dir, rng)
    malicious_files = collect_fn(args.malicious, "malicious", args.limit_per_dir, rng)
    logger.info("Totals before balancing: %d benign, %d malicious", len(benign_files), len(malicious_files))

    if args.balance_classes:
        benign_files, malicious_files = balance_classes(benign_files, malicious_files, rng)

    tasks = [(fp, "benign") for fp in benign_files] + [(fp, "malicious") for fp in malicious_files]
    logger.info("Processing %d files total with %d worker(s) (%s F3 extraction)...",
                len(tasks), workers, "subprocess" if args.pdfparser_subprocess else "in-process")

    rows = []
    if workers <= 1:
        for i, (fp, label) in enumerate(tasks, 1):
            rows.append(process_file(fp, label, args.pdfparser_subprocess, args.pdfparser_timeout))
            if i % 500 == 0:
                logger.info("...%d/%d", i, len(tasks))
    else:
        with ProcessPoolExecutor(max_workers=workers) as ex:
            futures = {
                ex.submit(process_file, fp, label, args.pdfparser_subprocess, args.pdfparser_timeout): fp
                for fp, label in tasks
            }
            for i, fut in enumerate(as_completed(futures), 1):
                try:
                    rows.append(fut.result())
                except Exception:
                    logger.error("[WORKER FAILED] %s\n%s", futures[fut], traceback.format_exc())
                if i % 500 == 0:
                    logger.info("...%d/%d", i, len(tasks))

    df = pd.DataFrame(rows)

    if args.leak_report:
        write_leak_report(df, args.out)

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    df_out = df.drop(columns=["filepath"])
    df_out.to_csv(args.out, index=False)
    logger.info("Done. Wrote %d rows x %d columns to %s", len(df_out), len(df_out.columns), args.out)
    logger.info("Class balance in output: %d benign, %d malicious",
                (df_out["label"] == "benign").sum(), (df_out["label"] == "malicious").sum())


if __name__ == "__main__":
    main()

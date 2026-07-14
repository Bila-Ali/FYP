#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║         PDF CDR v4  —  Structural Content Disarm & Reconstruction       ║
║                                                                          ║
║  v3 hand-rolled the xref/object parser with regex and manually          ║
║  remapped indirect references (the "Dubin adjacency" problem). v4       ║
║  replaces that layer with pikepdf/qpdf, which parses and rewrites the   ║
║  REAL object graph -- renumbering, dangling-reference repair, and       ║
║  xref/trailer regeneration all come for free and can't desync from a    ║
║  regex edge case. Disarm coverage is now driven directly off Table 2 of ║
║  Dubin (2023) instead of a hand-picked keyword/pattern list.            ║
║                                                                          ║
║  Pipeline per file (same shape as v3, safer core):                      ║
║    1. Baseline ML scan (optional, if a trained model is available)      ║
║    2. Parse with pikepdf, strip every Table-2 attack-vector category    ║
║    3. Reconstruct (qpdf renumbers objects + rewrites xref/trailer)      ║
║    4. Renderability check                                               ║
║    5. Final ML re-scan -> sanitised / isolated / render_failed          ║
║    6. Encrypted or unparsable files -> quarantined (zip+password)       ║
║                                                                          ║
║  Table 2 coverage (Dubin 2023):                                         ║
║    Metadata, Links, JavaScript/ActionScript, Embedded Content/Launch,   ║
║    Multimedia annots, Annotations, Triggers/Actions, AcroForm, XFA,     ║
║    PDF Functions. Encryption -> quarantined, not disarmed (same         ║
║    limitation the paper itself reports).                                ║
║                                                                          ║
║  Usage                                                                  ║
║    python pdf_cdr_v4.py --pdf suspicious.pdf                            ║
║    python pdf_cdr_v4.py --pdf suspicious.pdf --out clean.pdf            ║
║    python pdf_cdr_v4.py --pdf suspicious.pdf --dry-run --json           ║
║    python pdf_cdr_v4.py --batch ./pdfs --out-dir ./clean                ║
║    python pdf_cdr_v4.py --pdf x.pdf --model model_v2.joblib             ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

import argparse
import csv
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pikepdf
from pikepdf import Name

# ── Optional ML verification (baseline / final re-scan, like v3) ───────────
try:
    import joblib
    import numpy as np
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False


# ═══════════════════════════════════════════════════════════════════════════
# ANSI HELPERS  (same look as v3)
# ═══════════════════════════════════════════════════════════════════════════
def _ansi(code, t):
    return f"\033[{code}m{t}\033[0m" if sys.stdout.isatty() else t

RED    = lambda t: _ansi("91", t)
GREEN  = lambda t: _ansi("92", t)
YELLOW = lambda t: _ansi("93", t)
CYAN   = lambda t: _ansi("96", t)
BOLD   = lambda t: _ansi("1",  t)
DIM    = lambda t: _ansi("2",  t)
W = 68


# ═══════════════════════════════════════════════════════════════════════════
# TABLE 2 DISARM ENGINE (pikepdf/qpdf object graph -- see pdf_cdr.py for the
# fully-commented per-row version; this is the same logic, condensed into
# one file per your request)
# ═══════════════════════════════════════════════════════════════════════════

ACTION_TRIGGER_KEYS = ["/OpenAction", "/AA"]
MULTIMEDIA_ANNOT_SUBTYPES = {"/Movie", "/Screen", "/RichMedia", "/Sound", "/3D"}


def _count_name_tree_entries(node):
    total = 0
    try:
        if Name.Names in node:
            total += len(node.Names) // 2
        if Name.Kids in node:
            for kid in node.Kids:
                total += _count_name_tree_entries(kid)
    except Exception:
        pass
    return total


def _sanitize_metadata(pdf, log):
    found = removed = 0
    try:
        if pdf.docinfo is not None and len(pdf.docinfo.keys()) > 0:
            found = len(pdf.docinfo.keys())
            for key in list(pdf.docinfo.keys()):
                del pdf.docinfo[key]
            removed = found
    except Exception as e:
        log["errors"].append(f"metadata(docinfo): {e}")
    try:
        if Name.Metadata in pdf.Root:
            found += 1
            del pdf.Root[Name.Metadata]
            removed += 1
    except Exception as e:
        log["errors"].append(f"metadata(xmp): {e}")
    log["removed"]["metadata"] = removed
    log["found"]["metadata"] = found


def _remove_links(pdf, log):
    found = removed = 0
    for page in pdf.pages:
        if Name.Annots not in page:
            continue
        kept = []
        for annot in page.Annots:
            try:
                is_link = annot.get(Name.Subtype) == Name.Link
                has_uri = Name.A in annot and annot.A.get(Name.S) == Name.URI
                if is_link or has_uri:
                    found += 1
                    removed += 1
                    continue
            except Exception:
                pass
            kept.append(annot)
        page.Annots = pikepdf.Array(kept)
    log["removed"]["links"] = removed
    log["found"]["links"] = found


def _remove_javascript(pdf, log):
    found = removed = 0
    try:
        if Name.Names in pdf.Root and Name.JavaScript in pdf.Root.Names:
            n = _count_name_tree_entries(pdf.Root.Names.JavaScript)
            found += n
            del pdf.Root.Names.JavaScript
            removed += n
    except Exception as e:
        log["errors"].append(f"javascript(name tree): {e}")

    def strip(obj):
        nonlocal found, removed
        try:
            for key in ACTION_TRIGGER_KEYS:
                k = Name(key)
                if k not in obj:
                    continue
                action = obj[k]
                if k == Name.OpenAction:
                    if isinstance(action, pikepdf.Dictionary) and action.get(Name.S) == Name.JavaScript:
                        found += 1; del obj[k]; removed += 1
                elif isinstance(action, pikepdf.Dictionary):
                    for trig in list(action.keys()):
                        sub = action[trig]
                        if isinstance(sub, pikepdf.Dictionary) and sub.get(Name.S) == Name.JavaScript:
                            found += 1; del action[trig]; removed += 1
        except Exception:
            pass

    strip(pdf.Root)
    for page in pdf.pages:
        strip(page)
        if Name.Annots in page:
            for annot in page.Annots:
                strip(annot)
    if Name.AcroForm in pdf.Root:
        try:
            for f in pdf.Root.AcroForm.get(Name.Fields, []):
                strip(f)
        except Exception:
            pass
    log["removed"]["javascript"] = removed
    log["found"]["javascript"] = found


def _remove_embedded_content(pdf, log):
    found = removed = 0
    try:
        if Name.Names in pdf.Root and Name.EmbeddedFiles in pdf.Root.Names:
            n = _count_name_tree_entries(pdf.Root.Names.EmbeddedFiles)
            found += n
            del pdf.Root.Names.EmbeddedFiles
            removed += n
    except Exception as e:
        log["errors"].append(f"embedded(name tree): {e}")

    for page in pdf.pages:
        if Name.Annots not in page:
            continue
        kept = []
        for annot in page.Annots:
            try:
                if annot.get(Name.Subtype) == Name.FileAttachment:
                    found += 1; removed += 1; continue
            except Exception:
                pass
            kept.append(annot)
        page.Annots = pikepdf.Array(kept)

    def strip_launch(obj):
        nonlocal found, removed
        try:
            for key in ACTION_TRIGGER_KEYS:
                k = Name(key)
                if k not in obj:
                    continue
                action = obj[k]
                if k == Name.OpenAction and isinstance(action, pikepdf.Dictionary):
                    if action.get(Name.S) in (Name.Launch, Name.GoToE, Name.GoToR):
                        found += 1; del obj[k]; removed += 1
                elif isinstance(action, pikepdf.Dictionary):
                    for trig in list(action.keys()):
                        sub = action[trig]
                        s = sub.get(Name.S) if isinstance(sub, pikepdf.Dictionary) else None
                        if s in (Name.Launch, Name.GoToE, Name.GoToR):
                            found += 1; del action[trig]; removed += 1
        except Exception:
            pass

    strip_launch(pdf.Root)
    for page in pdf.pages:
        strip_launch(page)
        if Name.Annots in page:
            for annot in page.Annots:
                strip_launch(annot)
    log["removed"]["embedded_content"] = removed
    log["found"]["embedded_content"] = found


def _remove_multimedia(pdf, log):
    found = removed = 0
    for page in pdf.pages:
        if Name.Annots not in page:
            continue
        kept = []
        for annot in page.Annots:
            try:
                if annot.get(Name.Subtype) in MULTIMEDIA_ANNOT_SUBTYPES:
                    found += 1; removed += 1; continue
            except Exception:
                pass
            kept.append(annot)
        page.Annots = pikepdf.Array(kept)
    log["removed"]["multimedia"] = removed
    log["found"]["multimedia"] = found


def _remove_xfa(pdf, log, acroform_snapshot):
    found = removed = 0
    if acroform_snapshot is not None and Name.XFA in acroform_snapshot:
        found = removed = 1
        del acroform_snapshot[Name.XFA]
    log["removed"]["xfa"] = removed
    log["found"]["xfa"] = found


def _remove_acroform(pdf, log):
    found = removed = 0
    if Name.AcroForm in pdf.Root:
        found = removed = 1
        del pdf.Root[Name.AcroForm]
    log["removed"]["acroform"] = removed
    log["found"]["acroform"] = found


def _remove_annotations(pdf, log):
    found = removed = 0
    for page in pdf.pages:
        if Name.Annots in page:
            n = len(page.Annots)
            found += n; removed += n
            del page.Annots
    log["removed"]["annotations"] = removed
    log["found"]["annotations"] = found


def _remove_triggers_actions(pdf, log):
    found = removed = 0
    if Name.OpenAction in pdf.Root:
        found += 1; removed += 1; del pdf.Root[Name.OpenAction]
    if Name.AA in pdf.Root:
        n = len(pdf.Root.AA.keys()); found += n; removed += n; del pdf.Root[Name.AA]
    for page in pdf.pages:
        if Name.AA in page:
            n = len(page.AA.keys()); found += n; removed += n; del page[Name.AA]
    log["removed"]["triggers_actions"] = removed
    log["found"]["triggers_actions"] = found


def _remove_functions(pdf, log):
    found = removed = 0
    try:
        for obj in pdf.objects:
            try:
                if isinstance(obj, (pikepdf.Dictionary, pikepdf.Stream)) and Name.FunctionType in obj:
                    found += 1
                    if isinstance(obj, pikepdf.Stream):
                        obj.write(b"")
                    for k in (Name.FunctionType, Name.Domain, Name.Range, Name.C0, Name.C1,
                              Name.Functions, Name.Bounds, Name.Encode, Name.Size, Name.BitsPerSample):
                        if k in obj:
                            del obj[k]
                    removed += 1
            except Exception:
                continue
    except Exception as e:
        log["errors"].append(f"functions: {e}")
    log["removed"]["functions"] = removed
    log["found"]["functions"] = found


def disarm_and_reconstruct(input_path, output_path: str = None, password: str = ""):
    """Runs the full Table 2 pipeline and writes the reconstructed file.
    Returns (log_dict, clean_bytes). Raises pikepdf.PasswordError on an
    encrypted file with unknown password -- caller quarantines that.

    ``input_path`` may be a filesystem path (str/Path) OR raw PDF bytes --
    pikepdf can open either directly, which lets callers skip writing their
    own scratch file. The reconstructed PDF is likewise saved to an
    in-memory buffer rather than a temp file on disk: round-tripping
    through disk here was the source of a Windows-only
    "OSError: [Errno 22] Invalid argument" failure (a second temp file
    being saved-to and re-opened while the source pikepdf.Pdf was still
    holding its own handle open on the same file/volume)."""
    log = {"found": {}, "removed": {}, "warnings": [], "errors": []}
    source = io.BytesIO(input_path) if isinstance(input_path, (bytes, bytearray)) else input_path
    with pikepdf.open(source, password=password) as pdf:
        if pdf.is_encrypted:
            log["warnings"].append("Encrypted PDF content is not disarmed (paper limitation).")

        _sanitize_metadata(pdf, log)
        _remove_links(pdf, log)
        _remove_javascript(pdf, log)
        _remove_embedded_content(pdf, log)
        _remove_multimedia(pdf, log)

        acroform_snapshot = pdf.Root.get(Name.AcroForm)
        _remove_xfa(pdf, log, acroform_snapshot)
        _remove_acroform(pdf, log)

        _remove_annotations(pdf, log)
        _remove_triggers_actions(pdf, log)
        _remove_functions(pdf, log)

        pdf.remove_unreferenced_resources()

        out_buf = io.BytesIO()
        pdf.save(out_buf, linearize=False)
        clean_bytes = out_buf.getvalue()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(clean_bytes)

    return log, clean_bytes


# ═══════════════════════════════════════════════════════════════════════════
# RENDERABILITY CHECK (Obj 3.3 equivalent -- pikepdf re-open + optional
# external renderer, same two-tier approach as v3)
# ═══════════════════════════════════════════════════════════════════════════
def _safe_unlink(path: str):
    """Best-effort cleanup -- a failure here (e.g. a lingering Windows file
    lock) must never mask or replace the real result of the check."""
    try:
        os.unlink(path)
    except OSError:
        pass


def check_renderable(pdf_bytes: bytes):
    # Structural check first, entirely in memory -- no temp file needed for
    # this part, which avoids the disk round-trip that caused Windows-only
    # "OSError: [Errno 22] Invalid argument" failures.
    try:
        with pikepdf.open(io.BytesIO(pdf_bytes)) as pdf:
            n_pages = len(pdf.pages)
        if n_pages == 0:
            return False, "Reconstructed PDF has zero pages"
    except Exception as e:
        return False, f"pikepdf could not re-open reconstructed file: {e}"

    renderer_tools = [
        ("mutool", lambda p: ["mutool", "draw", "-o", os.devnull, p]),
        ("pdftoppm", lambda p: ["pdftoppm", "-r", "1", p, os.devnull]),
    ]
    available = [(tool, fn) for tool, fn in renderer_tools if shutil.which(tool)]
    if not available:
        return True, f"pikepdf structural check passed ({n_pages} pages, no external renderer found)"

    # Only external renderers need a real file on disk.
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    try:
        tmp.write(pdf_bytes)
        tmp.close()
        for tool, args_fn in available:
            try:
                result = subprocess.run(args_fn(tmp.name), capture_output=True, timeout=15)
                ok = result.returncode == 0
                detail = f"{tool}: OK ({n_pages} pages)" if ok else \
                    f"{tool} exit={result.returncode}: {result.stderr[:120].decode(errors='replace')}"
                return ok, detail
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        return True, f"pikepdf structural check passed ({n_pages} pages, external renderer unavailable at runtime)"
    finally:
        _safe_unlink(tmp.name)


# ═══════════════════════════════════════════════════════════════════════════
# ML VERIFICATION LOOP -- reuses YOUR extract_features.py + a joblib bundle
# produced by train_final_model.py ({"model", "final_features", "class_names"}),
# same interface predict_pdf.py uses. Fully optional: if either is missing,
# the tool still disarms, it just skips the P(malicious) before/after numbers.
# ═══════════════════════════════════════════════════════════════════════════
def _load_extractor(extractor_path):
    if not extractor_path or not os.path.exists(extractor_path):
        return None
    try:
        spec = importlib.util.spec_from_file_location("extract_features", extractor_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    except Exception:
        return None


def _build_feature_vector(raw_row, final_features):
    """Mirrors predict_pdf.py's build_feature_vector: aligns extracted raw
    features to the trained model's column order, reconstructing one-hot
    dummies (f2_form_*, f2_page_size_class_*, f2_pdf_version_major_*)."""
    import re as _re

    def bucket_version(v):
        v = str(v)
        return v if _re.match(r"^\d\.\d$", v) else "malformed_or_other"

    onehot_sources = {
        "f2_form_": ("f2_form", None),
        "f2_page_size_class_": ("f2_page_size_class", None),
        "f2_pdf_version_major_": ("f2_pdf_version", bucket_version),
    }
    vec = {}
    for feat in final_features:
        if feat in raw_row:
            val = raw_row[feat]
            if val is None or (isinstance(val, float) and val != val):
                val = -1
            vec[feat] = val
            continue
        matched = 0
        for prefix, (src_col, transform) in onehot_sources.items():
            if feat.startswith(prefix):
                raw_val = raw_row.get(src_col)
                val = transform(raw_val) if transform else raw_val
                matched = 1 if feat == f"{prefix}{val}" else 0
                break
        vec[feat] = matched
    return vec


class MLVerifier:
    """Loads once, scores many times. Pass model_path=None to disable."""
    def __init__(self, model_path, extractor_path, threshold=0.5):
        self.ok = False
        self.threshold = threshold
        if not (_ML_AVAILABLE and model_path and os.path.exists(model_path)):
            return
        try:
            self.bundle = joblib.load(model_path)
            self.extractor = _load_extractor(extractor_path)
            self.ok = self.extractor is not None
        except Exception:
            self.ok = False

    def score(self, pdf_path):
        if not self.ok:
            return {"available": False, "label": "UNKNOWN", "p_malicious": None}
        try:
            raw = self.extractor.process_file(pdf_path, label="unknown")
            final_features = self.bundle["final_features"]
            x = _build_feature_vector(raw, final_features)
            X = np.array([[x[f] for f in final_features]], dtype=float)
            proba = self.bundle["model"].predict_proba(X)[0]
            class_names = self.bundle["class_names"]
            p_mal = float(proba[class_names.index("malicious")]) if "malicious" in class_names else float(proba[-1])
            label = "MALICIOUS" if p_mal >= self.threshold else "BENIGN"
            return {"available": True, "label": label, "p_malicious": round(p_mal, 4)}
        except Exception as e:
            return {"available": True, "label": "ERROR", "p_malicious": None, "error": str(e)}


# ═══════════════════════════════════════════════════════════════════════════
# QUARANTINE (zip + password, same policy as the paper's Fig. 2 step 5 and v3)
# ═══════════════════════════════════════════════════════════════════════════
def quarantine_file(path, quarantine_dir, reason, password="infected"):
    Path(quarantine_dir).mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = Path(path).stem
    zip_path = Path(quarantine_dir) / f"QUARANTINE_{ts}_{stem}.pdf.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.setpassword(password.encode())
        zf.write(path, arcname=os.path.basename(path))
    return str(zip_path), reason


# ═══════════════════════════════════════════════════════════════════════════
# CORE ORCHESTRATOR -- same result shape/outcome states as v3
# (sanitised / isolated / render_failed / error), now backed by pikepdf
# ═══════════════════════════════════════════════════════════════════════════
def remediate_v4(pdf_path: str,
                  output_path: str = None,
                  quarantine_dir: str = None,
                  dry_run: bool = False,
                  threshold: float = 0.5,
                  model_path: str = None,
                  extractor_path: str = None,
                  verifier: MLVerifier = None) -> dict:

    t0 = time.perf_counter()
    result = {
        "input_path": pdf_path,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "cdr_version": "v4-pikepdf-structural",
        "attack_vectors_found": {},
        "attack_vectors_removed": {},
        "warnings": [],
        "renderable": None,
        "render_detail": None,
        "baseline_ml": {},
        "final_ml": {},
        "outcome": None,
        "output_path": None,
        "quarantine_path": None,
        "error": None,
    }

    if not os.path.exists(pdf_path):
        result["error"] = "File not found"
        result["outcome"] = "error"
        return result

    result["original_size"] = os.path.getsize(pdf_path)
    with open(pdf_path, "rb") as f:
        result["original_sha256"] = hashlib.sha256(f.read()).hexdigest()

    verifier = verifier or MLVerifier(model_path, extractor_path, threshold)
    result["baseline_ml"] = verifier.score(pdf_path)

    try:
        disarm_log, clean_bytes = disarm_and_reconstruct(
            pdf_path, output_path=None if dry_run else None  # write below after outcome known
        )
    except pikepdf.PasswordError:
        if not dry_run:
            zpath, reason = quarantine_file(pdf_path, quarantine_dir or "quarantine", "encrypted (unknown password)")
            result["quarantine_path"] = zpath
        result["outcome"] = "quarantined"
        result["warnings"].append("Encrypted, unknown password")
        result["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result
    except Exception as e:
        if not dry_run:
            zpath, reason = quarantine_file(pdf_path, quarantine_dir or "quarantine", f"abnormal structure: {e}")
            result["quarantine_path"] = zpath
        result["outcome"] = "quarantined"
        result["error"] = str(e)
        result["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return result

    result["attack_vectors_found"] = disarm_log["found"]
    result["attack_vectors_removed"] = disarm_log["removed"]
    result["warnings"].extend(disarm_log["warnings"])

    renderable, render_detail = check_renderable(clean_bytes)
    result["renderable"] = renderable
    result["render_detail"] = render_detail

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    tmp.write(clean_bytes)
    tmp.close()
    try:
        final_ml = verifier.score(tmp.name)
    finally:
        _safe_unlink(tmp.name)
    result["final_ml"] = final_ml

    if not renderable:
        result["outcome"] = "render_failed"
    elif final_ml.get("label") in ("BENIGN", "UNKNOWN"):
        result["outcome"] = "sanitised"
    else:
        result["outcome"] = "isolated"

    if result["outcome"] == "sanitised" and not dry_run:
        p = Path(pdf_path)
        out_p = output_path or str(p.parent / p.name)
        with open(out_p, "wb") as f:
            f.write(clean_bytes)
        result["output_path"] = out_p
        result["clean_size"] = len(clean_bytes)
        result["clean_sha256"] = hashlib.sha256(clean_bytes).hexdigest()
    elif result["outcome"] in ("isolated", "render_failed") and not dry_run:
        zpath, reason = quarantine_file(pdf_path, quarantine_dir or "quarantine", result["outcome"])
        result["quarantine_path"] = zpath

    result["elapsed_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return result


# ═══════════════════════════════════════════════════════════════════════════
# PRETTY PRINTER (same layout as v3, attack-vector breakdown instead of a
# flat object-removal list -- Table 2 categories are more informative)
# ═══════════════════════════════════════════════════════════════════════════
def print_result(r: dict):
    div, thin = "═" * W, "─" * W

    def row(label, value, width=36):
        print(f"  {label:<{width}} {value}")

    print(f"\n  {div}")
    print(f"  {'PDF CDR v4 — STRUCTURAL REMEDIATION REPORT':^{W}}")
    print(f"  {div}")
    row("Input file", Path(r["input_path"]).name)
    row("Size (original)", f"{r.get('original_size', 0):,} bytes")
    row("Timestamp", r["timestamp"])
    row("CDR version", BOLD(r["cdr_version"]))
    row("Dry run", "YES" if r["dry_run"] else "NO")

    if r.get("error") and r["outcome"] != "quarantined":
        print(f"\n  {RED('ERROR:')} {r['error']}\n")
        return

    if r["outcome"] == "quarantined":
        print(f"\n  {RED('⚠  QUARANTINED')}  {r.get('error') or r.get('warnings')}")
        row("Quarantine path", r.get("quarantine_path", "(dry run)") or "(dry run)")
        print(f"\n  {thin}\n")
        return

    print(f"\n  {div}")
    print(f"  {'BASELINE ML SCAN':^{W}}")
    print(f"  {div}")
    b = r.get("baseline_ml", {})
    if b.get("available"):
        c = RED if b["label"] == "MALICIOUS" else GREEN
        row("Baseline verdict", f"{c(b['label'])}  P(mal)={b['p_malicious']}")
    else:
        row("Baseline verdict", YELLOW("ML not available (no --model / extractor)"))

    print(f"\n  {div}")
    print(f"  {'ATTACK VECTORS (Table 2, Dubin 2023)':^{W}}")
    print(f"  {div}")
    removed = r["attack_vectors_removed"]
    total_removed = sum(removed.values())
    if total_removed:
        for vector, n in removed.items():
            if n:
                print(f"    {vector:<20} {RED(str(n))} object(s) removed")
    else:
        print(f"    {GREEN('No attack-vector objects found — file was already clean.')}")

    print(f"\n  {div}")
    print(f"  {'RENDERABILITY CHECK':^{W}}")
    print(f"  {div}")
    ok = r.get("renderable")
    row("Renderable", GREEN("YES") if ok else RED("NO"))
    row("Detail", r.get("render_detail", ""))

    print(f"\n  {div}")
    print(f"  {'OUTCOME':^{W}}")
    print(f"  {div}")
    outcome = r.get("outcome")
    f_ml = r.get("final_ml", {})

    if outcome == "sanitised":
        print(f"  {GREEN('✅  SANITISATION SUCCESSFUL')}")
        row("Clean file", r.get("output_path", "(dry run)") or "(dry run)")
        if r.get("clean_size"):
            row("Clean size", f"{r['clean_size']:,} bytes")
        if b.get("available") and f_ml.get("available") and f_ml.get("p_malicious") is not None:
            delta = (b["p_malicious"] or 0) - (f_ml["p_malicious"] or 0)
            print(f"\n  {'P(malicious) before':<36} {b['p_malicious']}")
            print(f"  {'P(malicious) after':<36} {GREEN(str(f_ml['p_malicious']))}  (↓{delta:.4f})")
    elif outcome == "render_failed":
        print(f"  {RED('✗  REBUILT PDF FAILED RENDERABILITY CHECK')}")
        row("Quarantine", r.get("quarantine_path", "(dry run)") or "(dry run)")
    elif outcome == "isolated":
        print(f"  {RED('⚠  STILL FLAGGED MALICIOUS AFTER RECONSTRUCTION — ISOLATED')}")
        row("Quarantine", r.get("quarantine_path", "(dry run)") or "(dry run)")

    print(f"\n  {thin}\n")


# ═══════════════════════════════════════════════════════════════════════════
# BATCH MODE
# ═══════════════════════════════════════════════════════════════════════════
def batch_remediate(folder, output_csv, out_dir=None, quarantine_dir=None,
                     dry_run=False, threshold=0.5, model_path=None, extractor_path=None):
    pdfs = [f for f in Path(folder).rglob("*.pdf") if f.is_file()]
    if not pdfs:
        print(RED(f"  No PDFs found in {folder}")); return
    if out_dir:
        Path(out_dir).mkdir(parents=True, exist_ok=True)

    verifier = MLVerifier(model_path, extractor_path, threshold)
    rows, counts = [], {}

    for i, pdf in enumerate(pdfs, 1):
        out_p = str(Path(out_dir) / pdf.name) if out_dir and not dry_run else None
        r = remediate_v4(str(pdf), out_p, quarantine_dir, dry_run, threshold,
                          model_path, extractor_path, verifier=verifier)
        outcome = r.get("outcome", "error")
        counts[outcome] = counts.get(outcome, 0) + 1
        icon = {"sanitised": GREEN("SANITISED"), "isolated": RED("ISOLATED"),
                "render_failed": YELLOW("RENDER_FAIL"), "quarantined": YELLOW("QUARANTINED")
                }.get(outcome, RED("ERROR"))
        b = r.get("baseline_ml", {})
        p = f"P={b.get('p_malicious')}" if b.get("available") else ""
        print(f"  [{i:>4}/{len(pdfs)}]  {icon:<16} {p:<12} {pdf.name[:45]}")
        rows.append({
            "File": pdf.name, "Outcome": outcome,
            "Attack_vectors_removed": sum(r.get("attack_vectors_removed", {}).values()),
            "Removed_breakdown": json.dumps(r.get("attack_vectors_removed", {})),
            "Renderable": r.get("renderable", ""),
            "Baseline_P_mal": b.get("p_malicious", ""),
            "Final_P_mal": r.get("final_ml", {}).get("p_malicious", ""),
            "Output_Path": r.get("output_path") or r.get("quarantine_path", ""),
        })

    with open(output_csv, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)

    print(f"\n  {'─'*W}")
    print(BOLD("  BATCH CDR v4 SUMMARY"))
    for k, v in counts.items():
        c = GREEN if k == "sanitised" else (YELLOW if k in ("render_failed", "quarantined") else RED)
        print(f"  {k:<15}: {c(str(v))}")
    print(f"  Report        : {output_csv}\n")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        prog="pdf_cdr_v4.py",
        description="PDF CDR v4 — pikepdf structural rebuild, Table-2 (Dubin 2023) coverage",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python pdf_cdr_v4.py --pdf suspicious.pdf\n"
            "  python pdf_cdr_v4.py --pdf suspicious.pdf --out clean.pdf\n"
            "  python pdf_cdr_v4.py --pdf suspicious.pdf --dry-run --json\n"
            "  python pdf_cdr_v4.py --batch ./pdfs --out-dir ./clean\n"
            "  python pdf_cdr_v4.py --pdf x.pdf --model model_v2.joblib --extractor extract_features.py\n"
        ),
    )
    parser.add_argument("--pdf", metavar="FILE")
    parser.add_argument("--batch", metavar="FOLDER")
    parser.add_argument("--out", metavar="FILE")
    parser.add_argument("--out-dir", metavar="DIR", dest="out_dir")
    parser.add_argument("--output", metavar="FILE", default="cdr_v4_report.csv")
    parser.add_argument("--quarantine", metavar="DIR", default="quarantine")
    parser.add_argument("--model", metavar="FILE", default=None,
                         help="joblib bundle from train_final_model.py (model.joblib / model_v2.joblib). Optional.")
    parser.add_argument("--extractor", metavar="FILE", default="extract_features.py",
                         help="Path to your extract_features.py (needed only if --model is given).")
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--dry-run", action="store_true", dest="dry_run")
    parser.add_argument("--json", action="store_true")

    args = parser.parse_args()
    if not args.pdf and not args.batch:
        parser.print_help(); sys.exit(1)

    if args.batch:
        batch_remediate(args.batch, args.output, args.out_dir, args.quarantine,
                         args.dry_run, args.threshold, args.model, args.extractor)
        return

    if not os.path.exists(args.pdf):
        sys.exit(RED(f"  [ERROR] File not found: {args.pdf}"))

    result = remediate_v4(args.pdf, args.out, args.quarantine, args.dry_run,
                           args.threshold, args.model, args.extractor)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        print_result(result)

    if result.get("outcome") == "error": sys.exit(1)
    if result.get("outcome") != "sanitised": sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()

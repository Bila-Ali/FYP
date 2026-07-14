#!/usr/bin/env python3
"""
predict_pdf.py

Scores a new PDF file (or a directory of PDFs) as benign/malicious using the
model trained by train_final_model.py.

Reuses extract_features.py's own extract_f1/extract_f2/extract_f3/
compute_derived functions directly (imported, not reimplemented) so feature
extraction for a new file is guaranteed identical to how the training data
was built.

Must be run from the same folder as extract_features.py (and its tools/
subfolder), OR pass --extract-script pointing at it.

Usage:
    python predict_pdf.py --model models/model.joblib --pdf suspicious.pdf
    python predict_pdf.py --model models/model.joblib --pdf-dir incoming/ --out predictions.csv
    python predict_pdf.py --model models/model.joblib --pdf suspicious.pdf --explain
"""

from __future__ import annotations

import argparse
import glob
import importlib.util
import os
import sys

import joblib
import numpy as np
import pandas as pd

from pdf_malware.logging_utils import get_logger
from pdf_malware.preprocessing import bucket_pdf_version

logger = get_logger(__name__, "prediction.log")


def load_extract_features_module(script_path: str):
    spec = importlib.util.spec_from_file_location("extract_features", script_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build_feature_vector(raw_row: dict, final_features: list[str]) -> dict:
    """Aligns a single extracted-feature dict to the model's expected column
    order, reconstructing one-hot dummy columns (e.g. f2_form_AcroForm,
    f2_pdf_version_major_1.7) by name-matching against the raw categorical
    values, mirroring pandas.get_dummies' prefix_value naming exactly as
    used by pdf_malware.preprocessing.preprocess_dataset() at training time.
    """
    onehot_sources = {
        "f2_form_": ("f2_form", None),
        "f2_page_size_class_": ("f2_page_size_class", None),
        "f2_pdf_version_major_": ("f2_pdf_version", bucket_pdf_version),
    }
    vec = {}
    for feat in final_features:
        if feat in raw_row:
            val = raw_row[feat]
            if val is None or (isinstance(val, float) and val != val):  # None or NaN
                val = -1  # matches the -1 sentinel used by preprocess_dataset() at training time
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


def explain_prediction(model, final_features: list[str], x_row: dict, top_n: int = 8) -> str:
    """Lightweight per-instance explanation using the model's global feature
    importances. For a full SHAP decision plot, see explainability.py."""
    importances = model.feature_importances_
    order = np.argsort(importances)[::-1][:top_n]
    lines = []
    for i in order:
        feat = final_features[i]
        val = x_row[feat]
        lines.append(f"    {feat:30s} = {val:<10}  (global importance {importances[i]:.4f})")
    return "\n".join(lines)


def predict_file(pdf_path: str, extract_mod, bundle: dict) -> tuple[dict, dict]:
    row = extract_mod.process_file(pdf_path, label="unknown")
    final_features = bundle["final_features"]
    x_dict = build_feature_vector(row, final_features)
    X = np.array([[x_dict[f] for f in final_features]], dtype=float)

    model = bundle["model"]
    proba = model.predict_proba(X)[0]
    pred_idx = int(np.argmax(proba))
    pred_class = bundle["class_names"][pred_idx]
    confidence = proba[pred_idx]

    return {
        "filename": os.path.basename(pdf_path),
        "prediction": pred_class,
        "confidence": round(float(confidence), 4),
        "p_benign": round(float(proba[bundle["class_names"].index("benign")]), 4)
                    if "benign" in bundle["class_names"] else None,
        "p_malicious": round(float(proba[bundle["class_names"].index("malicious")]), 4)
                       if "malicious" in bundle["class_names"] else None,
    }, x_dict


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True, help="model.joblib from train_final_model.py")
    ap.add_argument("--pdf", help="Path to a single PDF to score")
    ap.add_argument("--pdf-dir", help="Directory of PDFs to score in batch")
    ap.add_argument("--extract-script", default="extract_features.py",
                     help="Path to extract_features.py (default: same directory)")
    ap.add_argument("--out", default="artifacts/predictions.csv", help="CSV path for batch results (--pdf-dir mode)")
    ap.add_argument("--explain", action="store_true",
                     help="Print the top contributing features for each prediction")
    args = ap.parse_args()

    if not args.pdf and not args.pdf_dir:
        sys.exit("ERROR: pass either --pdf FILE or --pdf-dir DIR")

    if not os.path.exists(args.extract_script):
        sys.exit(f"ERROR: {args.extract_script} not found. Run this script from the same "
                  f"folder as extract_features.py, or pass --extract-script /path/to/it.")

    logger.info("Loading model from %s ...", args.model)
    bundle = joblib.load(args.model)
    logger.info("Model expects %d features, classes=%s", len(bundle["final_features"]), bundle["class_names"])

    extract_mod = load_extract_features_module(args.extract_script)

    targets = [args.pdf] if args.pdf else sorted(glob.glob(os.path.join(args.pdf_dir, "*.pdf")))
    if not targets:
        sys.exit("No PDF files found to score.")

    results = []
    for path in targets:
        logger.info("Scoring: %s", path)
        try:
            result, x_dict = predict_file(path, extract_mod, bundle)
        except Exception as e:
            logger.error("FAILED: %s: %s", path, e)
            results.append({"filename": os.path.basename(path), "prediction": "ERROR",
                             "confidence": None, "p_benign": None, "p_malicious": None})
            continue

        flag = "MALICIOUS" if result["prediction"] == "malicious" else "benign"
        logger.info("  %s (confidence: %.1f%%, p_benign=%s, p_malicious=%s)",
                    flag, result["confidence"] * 100, result["p_benign"], result["p_malicious"])
        if args.explain:
            logger.info("  Top contributing features for this file:\n%s",
                        explain_prediction(bundle["model"], bundle["final_features"], x_dict))
        results.append(result)

    if args.pdf_dir:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        pd.DataFrame(results).to_csv(args.out, index=False)
        logger.info("Saved %d predictions to %s", len(results), args.out)
        n_mal = sum(1 for r in results if r["prediction"] == "malicious")
        logger.info("Summary: %d malicious / %d benign (or error)", n_mal, len(results) - n_mal)


if __name__ == "__main__":
    main()

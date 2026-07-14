#!/usr/bin/env python3
"""
pdfinfo.py (patched) - PyMuPDF-based clone of poppler's pdfinfo, used to
extract the paper's F2 feature set.

--------------------------------------------------------------------------
CHANGELOG vs. the original clone
--------------------------------------------------------------------------
1. Tagged
   Was: `hasattr(doc, 'get_xml_metadata')`
   That checks whether the *fitz.Document class* has a method called
   get_xml_metadata - which is always True, for every PDF, regardless of
   its content. So the original always printed "Tagged: True", making
   f2_tagged a constant column with zero information.
   Now: actually reads /MarkInfo /Marked true from the document catalog,
   which is what "Tagged" (tagged-for-accessibility) means.

2. Metadata Stream
   Was: `doc.xref_get_keys(1)` - assumes the XML metadata stream is
   always object #1. Not guaranteed by the spec; wrong on many real PDFs.
   Now: dereferences the catalog's own /Metadata entry.

3. Form
   Was: only checked for the literal "/AcroForm" keyword and printed a
   boolean ("yes"/"none"), so /XFA forms were never distinguished and the
   type information the paper describes (AcroForm vs. XFA vs. none) was
   discarded.
   Now: reports "XFA", "AcroForm", or "none".

4. Suspects
   Was: `javascript or embedded` - a duplicate of two fields already
   printed elsewhere, not an independent signal.
   Now: True if MuPDF had to tolerate/flag structural problems while
   opening the file (see MuPDF Errors below) - a genuine
   "something is structurally wrong with this PDF" signal, closer to
   poppler's own definition of Suspects.

5. Optimized
   Was: hardcoded to "no" for every file (dead feature).
   Now: inferred from the presence of a /Linearized dictionary, which is
   what "Optimized"/fast-web-view actually refers to.

6. MuPDF Errors (new field)
   MuPDF is a C library; it writes diagnostics ("MuPDF error: format
   error: ...") directly to the OS-level stderr file descriptor, bypassing
   sys.stderr entirely. No amount of try/except or
   contextlib.redirect_stderr() in Python catches these. This version
   redirects the real fd for the duration of each file, counts the
   diagnostic lines, exposes the count as `MuPDF Errors`, and restores
   stderr afterwards so your logs stay clean at scale.
"""

import contextlib
import fitz
import os
import re
import sys
import tempfile


# --------------------------------------------------------------------------
# OS-level stderr capture (the only thing that actually sees MuPDF's output)
# --------------------------------------------------------------------------

@contextlib.contextmanager
def _capture_c_stderr():
    """Redirect the OS-level stderr fd (2) to a temp file for the duration
    of the block and yield a callable that returns everything captured so
    far (and clears the buffer). Restores the original fd on exit."""
    stderr_fd = 2
    sys.stderr.flush()
    saved_fd = os.dup(stderr_fd)
    tmp = tempfile.TemporaryFile(mode="w+b")
    os.dup2(tmp.fileno(), stderr_fd)

    def _read():
        tmp.flush()
        tmp.seek(0)
        data = tmp.read()
        tmp.seek(0, os.SEEK_END)
        return data.decode("latin1", errors="ignore")

    try:
        yield _read
    finally:
        os.dup2(saved_fd, stderr_fd)
        os.close(saved_fd)
        tmp.close()


# --------------------------------------------------------------------------
# Fixed feature detectors
# --------------------------------------------------------------------------

def _detect_tagged(doc):
    try:
        catalog_obj = doc.xref_object(doc.pdf_catalog())
    except Exception:
        return False

    m = re.search(r"/MarkInfo\s+(\d+)\s+\d+\s+R", catalog_obj)
    if m:
        try:
            mi_obj = doc.xref_object(int(m.group(1)))
        except Exception:
            return False
        return bool(re.search(r"/Marked\s+true", mi_obj))

    m = re.search(r"/MarkInfo\s*<<(.*?)>>", catalog_obj, re.DOTALL)
    if m:
        return bool(re.search(r"/Marked\s+true", m.group(1)))

    return False


def _detect_metadata_stream(doc):
    try:
        catalog_obj = doc.xref_object(doc.pdf_catalog())
    except Exception:
        return False

    m = re.search(r"/Metadata\s+(\d+)\s+\d+\s+R", catalog_obj)
    if not m:
        return "/Metadata" in catalog_obj  # inline (unusual) case
    try:
        doc.xref_stream(int(m.group(1)))
        return True
    except Exception:
        return True  # entry exists even if the stream can't be decoded


def _detect_form_and_optimized(doc):
    """Single pass over all xrefs: form type (XFA takes precedence, since
    it's the more specific / higher-signal feature) and whether a
    Linearization dict is present anywhere (Optimized)."""
    has_acroform = False
    has_xfa = False
    has_linearized = False

    for xref in range(1, doc.xref_length()):
        try:
            obj = doc.xref_object(xref)
        except Exception:
            continue
        if "/AcroForm" in obj:
            has_acroform = True
        if "/XFA" in obj:
            has_xfa = True
        if "/Linearized" in obj:
            has_linearized = True

    form = "XFA" if has_xfa else ("AcroForm" if has_acroform else "none")
    return form, has_linearized


# --------------------------------------------------------------------------
# Main analysis
# --------------------------------------------------------------------------

def analyze_pdf(pdf_path):
    file_size = os.path.getsize(pdf_path)

    with open(pdf_path, "rb") as f:
        header = f.read(20).decode("latin1", errors="ignore")
    pdf_version = "Unknown"
    if header.startswith("%PDF-"):
        pdf_version = header.split("%PDF-")[1].split()[0]

    with _capture_c_stderr() as read_stderr:
        doc = fitz.open(pdf_path)

        custom_metadata = bool(doc.metadata)

        javascript = False
        embedded = False
        for xref in range(1, doc.xref_length()):
            try:
                obj = doc.xref_object(xref)
                if "/JavaScript" in obj or "/JS" in obj:
                    javascript = True
                if "/EmbeddedFile" in obj:
                    embedded = True
            except Exception:
                pass

        tagged = _detect_tagged(doc)
        metadata_stream = _detect_metadata_stream(doc)
        form, optimized = _detect_form_and_optimized(doc)

        page_count = doc.page_count
        encrypted = doc.is_encrypted

        if page_count > 0:
            page = doc[0]
            rect = page.rect
            page_width, page_height = int(rect.width), int(rect.height)
            page_rot = page.rotation
        else:
            page_width = page_height = page_rot = 0

        doc.close()
        mupdf_log = read_stderr()

    mupdf_error_count = mupdf_log.count("MuPDF error")
    # Real "Suspects" signal: MuPDF had to tolerate/flag structural
    # problems to open the file at all.
    suspects = mupdf_error_count > 0

    print(f"File: {pdf_path}")
    print(f"Custom Metadata: {'yes' if custom_metadata else 'no'}")
    print(f"Metadata Stream: {'yes' if metadata_stream else 'no'}")
    print(f"Tagged: {'yes' if tagged else 'no'}")
    print(f"UserProperties: no")
    print(f"Suspects: {'yes' if suspects else 'no'}")
    print(f"Form: {form}")
    print(f"JavaScript: {'yes' if javascript else 'no'}")
    print(f"Pages: {page_count}")
    print(f"Encrypted: {'yes' if encrypted else 'no'}")
    if page_count > 0:
        print(f"Page size: {page_width} x {page_height} pts")
        print(f"Page rot: {page_rot}")
    print(f"File size: {file_size} bytes")
    print(f"Optimized: {'yes' if optimized else 'no'}")
    print(f"PDF version: {pdf_version}")
    print(f"MuPDF Errors: {mupdf_error_count}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pdfinfo.py <file.pdf>")
        sys.exit(1)
    analyze_pdf(sys.argv[1])

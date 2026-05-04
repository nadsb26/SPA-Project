"""
pipeline.py — Credential Leak Detector: Full Pipeline

Orchestrates all components:
  1. credential_scanner   — regex + keyword matching (V1)
  2. ast_parser           — extract string-literal assignments (structural layer)
  3. dataflow_tracker     — propagate taint, detect sensitive contexts (V2)
  4. llm_explainer        — LLM triage, explanation, and fix suggestions (V3)
  5. report_formatter     — human-readable report

Usage (CLI):
    python pipeline.py path/to/code/           # full pipeline
    python pipeline.py path/to/code/ --no-llm  # skip LLM (V2 mode)
    python pipeline.py path/to/code/ --output report.txt
    python pipeline.py path/to/code/ --json findings.json
"""

import json
import argparse
from pathlib import Path
from typing import List, Optional

from credential_scanner import scan_paths as regex_scan
from ast_parser import scan_paths as ast_scan
from dataflow_tracker import analyze_source, _iter_python_files
from report_formatter import format_report


# ---------------------------------------------------------------------------
# Merging helpers
# ---------------------------------------------------------------------------

def _make_key(finding: dict) -> tuple:
    """Canonical deduplication key: (file, line, value)."""
    return (
        str(Path(finding.get("file", ""))),
        int(finding.get("line", 0)),
        finding.get("value", ""),
    )


def _merge_findings(regex_findings: List[dict], ast_findings: List[dict]) -> List[dict]:
    """
    Merge regex scanner results with AST parser results.

    - Regex findings carry:  file, line, value, label, type
    - AST findings carry:    variable, value, line  (no file — added by caller)

    We enrich regex findings with the variable name from the AST findings when
    they share the same (line, value), and add any AST-only findings that the
    regex pass missed.
    """
    # Index AST findings by (line, value) for fast lookup
    ast_by_line_value: dict = {}
    for af in ast_findings:
        k = (int(af.get("line", 0)), af.get("value", ""))
        ast_by_line_value.setdefault(k, []).append(af)

    seen_keys: set = set()
    merged: List[dict] = []

    for rf in regex_findings:
        k = _make_key(rf)
        if k in seen_keys:
            continue
        seen_keys.add(k)

        # Try to enrich with variable name from AST pass
        ast_matches = ast_by_line_value.get((int(rf.get("line", 0)), rf.get("value", "")), [])
        variable = ast_matches[0]["variable"] if ast_matches else rf.get("variable", "unknown")

        merged.append({**rf, "variable": variable})

    return merged


def _apply_dataflow(merged: List[dict], paths: List[str]) -> List[dict]:
    """
    For each Python file, run dataflow analysis and annotate matching findings
    with risk level and used_in context.

    Findings without a dataflow match are left as-is (risk stays unknown).
    """
    # Build dataflow results per file
    dataflow_map: dict = {}  # file -> {variable -> record}
    for f in _iter_python_files(paths):
        source = f.read_text(encoding="utf-8", errors="replace")
        records = analyze_source(source, filename=str(f))
        dataflow_map[str(f)] = {r["variable"]: r for r in records}

    annotated: List[dict] = []
    for finding in merged:
        file_ = str(Path(finding.get("file", "")))
        variable = finding.get("variable", "")
        df_records = dataflow_map.get(file_, {})

        if variable in df_records:
            rec = df_records[variable]
            finding = {
                **finding,
                "risk": rec.get("risk", finding.get("risk", "unknown")),
                "used_in": rec.get("used_in", finding.get("used_in", "not tracked")),
            }
        else:
            finding = {
                **finding,
                "risk": finding.get("risk", "unknown"),
                "used_in": finding.get("used_in", "not tracked"),
            }
        annotated.append(finding)

    return annotated


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------

def run_pipeline(
    paths: List[str],
    use_llm: bool = True,
    extensions: tuple = (".py", ".java", ".kt", ".xml"),
) -> List[dict]:
    """
    Run the full (or partial) credential detection pipeline.

    Args:
        paths:      List of files or directories to scan.
        use_llm:    If True, run LLM triage (V3). If False, stop after V2.
        extensions: File extensions to scan (passed to regex scanner).

    Returns:
        List of finding dicts, enriched with all available metadata.
    """

    # ── Stage 1: Regex + Keyword scan ─────────────────────────────────────
    print("[pipeline] Stage 1: regex + keyword scan …")
    regex_findings = regex_scan(paths, extensions=extensions)
    print(f"           {len(regex_findings)} candidate(s) found")

    # ── Stage 2a: AST string extraction (enrich with variable names) ───────
    print("[pipeline] Stage 2a: AST string extraction …")
    ast_findings_raw = ast_scan(paths)

    # AST scan doesn't track filenames per result — re-run per file for enrichment
    ast_findings_with_file: List[dict] = []
    for p in paths:
        path = Path(p)
        files = list(path.rglob("*.py")) if path.is_dir() else ([path] if path.suffix == ".py" else [])
        for f in files:
            from ast_parser import extract_assignments
            for af in extract_assignments(f):
                ast_findings_with_file.append({**af, "file": str(f)})

    merged = _merge_findings(regex_findings, ast_findings_with_file)
    print(f"           merged to {len(merged)} unique finding(s)")

    # ── Stage 2b: Dataflow analysis ────────────────────────────────────────
    print("[pipeline] Stage 2b: dataflow tracking …")
    merged = _apply_dataflow(merged, paths)
    high_risk = sum(1 for f in merged if f.get("risk") == "high")
    print(f"           {high_risk} high-risk finding(s) after dataflow")

    if not use_llm:
        return merged

    # ── Stage 3: LLM triage ────────────────────────────────────────────────
    print("[pipeline] Stage 3: LLM triage …")
    try:
        from llm_explainer import explain_findings
        enriched = explain_findings(merged)
        real = sum(1 for f in enriched if f.get("is_real_secret") is True)
        print(f"           LLM confirmed {real} real secret(s)")
        return enriched
    except EnvironmentError as e:
        print(f"[pipeline] Warning — LLM skipped: {e}")
        return merged


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Credential Leak Detector — full pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument(
        "--no-llm", dest="no_llm", action="store_true",
        help="skip LLM stage (faster, no API key required)",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="save human-readable report to this file",
    )
    parser.add_argument(
        "--json", default=None,
        help="also save raw JSON findings to this file",
    )
    parser.add_argument(
        "--extensions", "-e", default=".py,.java,.kt,.xml",
        help="comma-separated file extensions to scan (default: .py,.java,.kt,.xml)",
    )
    args = parser.parse_args()

    exts = tuple(e.strip() for e in args.extensions.split(","))
    findings = run_pipeline(args.paths, use_llm=not args.no_llm, extensions=exts)

    report = format_report(findings)
    print("\n" + report)

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report saved to {args.output}")

    if args.json:
        Path(args.json).write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"JSON findings saved to {args.json}")


if __name__ == "__main__":
    main()

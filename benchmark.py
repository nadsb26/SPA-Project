"""
benchmark.py — Self-Contained Benchmark for Credential Leak Detector

Why this exists
---------------
SecretBench and FPSecretBench (Basak et al., 2023) are the gold-standard
datasets referenced in our proposal, but they are gated: access requires
contacting the authors and signing a data-protection agreement (both datasets
live in Google BigQuery, not public downloads). This script provides a
self-contained substitute that:

  1. Constructs a controlled set of synthetic test files covering all major
     secret types, placeholder strings, and obfuscated/dataflow cases.
  2. Runs the full ablation study (V1 / V2 / V3) over those files.
  3. Produces Precision / Recall / F1 for each pipeline version.
  4. Prints a table comparing the three versions.

SecretBench compatibility
-------------------------
If you do obtain access to SecretBench, export a slice of it as a CSV with
columns [file, line, value, is_secret] and run:

    python benchmark.py --external path/to/secretbench_slice.csv --format csv

The same evaluator logic handles both synthetic and external ground truth.

Usage
-----
    python benchmark.py                     # run synthetic benchmark
    python benchmark.py --v2-only           # skip LLM stage
    python benchmark.py --external gt.json  # use external ground truth JSON
    python benchmark.py --external gt.csv --format csv
"""

import json
import tempfile
import argparse
from pathlib import Path
from typing import List, Tuple

from evaluator import compute_metrics, load_ground_truth_json, load_ground_truth_csv, _print_summary
from credential_scanner import scan_paths as regex_scan
from pipeline import run_pipeline


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic test cases
# Each entry: (filename, source_code, ground_truth_list)
# ground_truth_list: [{line, value, is_secret}]
# ─────────────────────────────────────────────────────────────────────────────

SYNTHETIC_CASES: List[Tuple[str, str, List[dict]]] = [

    # ── TRUE POSITIVES: real-looking secrets ─────────────────────────────────

    ("tp_aws.py", """\
import boto3
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
client = boto3.client("s3")
""", [
        {"line": 2, "value": "AKIAIOSFODNN7EXAMPLE", "is_secret": True},
        {"line": 3, "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "is_secret": True},
    ]),

    ("tp_google.py", """\
import requests
api_key = "AIzaabcdefghijklmnopqrstuvwxyzABCDEFGHI"
resp = requests.get("https://maps.googleapis.com/maps/api/geocode/json",
                    params={"key": api_key})
""", [
        {"line": 2, "value": "AIzaabcdefghijklmnopqrstuvwxyzABCDEFGHI", "is_secret": True},
    ]),

    ("tp_db_password.py", """\
import psycopg2
db_password = "Sup3rS3cr3tP@ssword"
conn = psycopg2.connect(host="db.example.com", user="admin", password=db_password)
""", [
        {"line": 2, "value": "Sup3rS3cr3tP@ssword", "is_secret": True},
    ]),

    ("tp_jwt.py", """\
# authentication helper
SECRET_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
""", [
        {"line": 2, "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "is_secret": True},
    ]),

    ("tp_stripe.py", """\
STRIPE_SECRET = "sk_live_FAKE_EXAMPLE_NOT_REAL_00"
""", [
        {"line": 1, "value": "sk_live_FAKE_EXAMPLE_NOT_REAL_00", "is_secret": True},
    ]),

    ("tp_db_url.py", """\
DATABASE_URL = "postgres://admin:Sup3rS3cr3t@db.internal:5432/prod"
""", [
        {"line": 1, "value": "postgres://admin:Sup3rS3cr3t@db.internal:5432/prod", "is_secret": True},
    ]),

    # ── TRUE POSITIVES: obfuscated / dataflow ────────────────────────────────

    ("tp_dataflow_http.py", """\
import requests
raw_key = "realApiKey12345678"
auth_header = raw_key
requests.get("https://api.example.com/data",
             headers={"Authorization": "Bearer " + auth_header})
""", [
        {"line": 2, "value": "realApiKey12345678", "is_secret": True},
    ]),

    ("tp_dataflow_db.py", """\
import psycopg2
pw = "dbPassword9876"
conn = psycopg2.connect(host="localhost", user="root", password=pw)
""", [
        {"line": 2, "value": "dbPassword9876", "is_secret": True},
    ]),

    # ── FALSE POSITIVES: placeholders that should be filtered ────────────────

    ("fp_placeholders.py", """\
# Example configuration — replace before deploying
api_key = "your_api_key_here"
password = "changeme"
token = "<token>"
secret = "xxxx"
""", [
        {"line": 2, "value": "your_api_key_here", "is_secret": False},
        {"line": 3, "value": "changeme", "is_secret": False},
        {"line": 4, "value": "<token>", "is_secret": False},
        {"line": 5, "value": "xxxx", "is_secret": False},
    ]),

    ("fp_test_values.py", """\
# Unit test fixtures
TEST_API_KEY = "test_api_key"
MOCK_TOKEN = "mock_token_for_testing"
FAKE_SECRET = "fake_secret_value"
""", [
        {"line": 2, "value": "test_api_key", "is_secret": False},
        {"line": 3, "value": "mock_token_for_testing", "is_secret": False},
        {"line": 4, "value": "fake_secret_value", "is_secret": False},
    ]),

    ("fp_non_sensitive.py", """\
# Non-credential string assignments that should not trigger
app_name = "MyApplication"
version = "1.0.0"
log_level = "DEBUG"
db_host = "localhost"
""", [
        {"line": 2, "value": "MyApplication", "is_secret": False},
        {"line": 3, "value": "1.0.0", "is_secret": False},
        {"line": 4, "value": "DEBUG", "is_secret": False},
        {"line": 5, "value": "localhost", "is_secret": False},
    ]),

    # ── EDGE CASES ────────────────────────────────────────────────────────────

    ("edge_comment.py", """\
# api_key = "AKIAIOSFODNN7EXAMPLE"   # this is in a comment, should be ignored
real_key = "AKIAIOSFODNN7EXAMPLE"    # this one is real
""", [
        {"line": 2, "value": "AKIAIOSFODNN7EXAMPLE", "is_secret": True},
    ]),

    ("edge_annotated.py", """\
from typing import Optional
token: str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
unused: Optional[str] = None
""", [
        {"line": 2, "value": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", "is_secret": True},
    ]),
]


# ─────────────────────────────────────────────────────────────────────────────
# Benchmark runner
# ─────────────────────────────────────────────────────────────────────────────

def build_synthetic_dataset(tmpdir: Path) -> Tuple[List[str], List[dict]]:
    """
    Write synthetic source files to tmpdir and return
    (list_of_file_paths, ground_truth_records).
    """
    paths: List[str] = []
    ground_truth: List[dict] = []

    for filename, source, gt_entries in SYNTHETIC_CASES:
        fpath = tmpdir / filename
        fpath.write_text(source, encoding="utf-8")
        paths.append(str(fpath))

        for entry in gt_entries:
            ground_truth.append({
                "file": str(fpath),
                "line": entry["line"],
                "value": entry["value"],
                "is_secret": entry["is_secret"],
            })

    return paths, ground_truth


def run_synthetic_benchmark(use_llm: bool = True) -> None:
    print("\n" + "=" * 60)
    print("  CREDENTIAL LEAK DETECTOR — SYNTHETIC BENCHMARK")
    print("=" * 60)
    print(f"  Cases: {len(SYNTHETIC_CASES)} files")
    true_count = sum(e["is_secret"] for _, _, gt in SYNTHETIC_CASES for e in gt)
    false_count = sum(not e["is_secret"] for _, _, gt in SYNTHETIC_CASES for e in gt)
    print(f"  Ground truth: {true_count} true secrets, {false_count} non-secrets")
    print("=" * 60)

    with tempfile.TemporaryDirectory() as tmpdir:
        paths, ground_truth = build_synthetic_dataset(Path(tmpdir))

        results = {}

        # V1: regex + keyword only
        print("\n── V1: Regex + Keyword Scanner ─────────────────────────")
        v1 = regex_scan(paths)
        results["V1"] = compute_metrics(v1, ground_truth)
        print(results["V1"])

        # V2: + AST + dataflow
        print("\n── V2: Regex + AST + Dataflow ──────────────────────────")
        v2 = run_pipeline(paths, use_llm=False)
        results["V2"] = compute_metrics(v2, ground_truth)
        print(results["V2"])

        # V3: full pipeline with LLM
        if use_llm:
            print("\n── V3: Full Pipeline (with LLM) ────────────────────────")
            try:
                v3_all = run_pipeline(paths, use_llm=True)
                v3 = [f for f in v3_all if f.get("is_real_secret") is not False]
                results["V3"] = compute_metrics(v3, ground_truth)
                print(results["V3"])
            except EnvironmentError as e:
                print(f"  Skipped — {e}")

        _print_summary(results)

        # Save ground truth for reference
        out = Path("benchmark_ground_truth.json")
        out.write_text(json.dumps(ground_truth, indent=2), encoding="utf-8")
        print(f"\nGround truth saved to: {out}")


def run_external_benchmark(
    paths: List[str],
    ground_truth: List[dict],
    use_llm: bool = True,
) -> None:
    """Run ablation study against externally-provided ground truth (e.g. SecretBench)."""
    print("\n" + "=" * 60)
    print("  CREDENTIAL LEAK DETECTOR — EXTERNAL BENCHMARK")
    print("=" * 60)
    true_count = sum(1 for g in ground_truth if g.get("is_secret") in (True, "true", "True", 1, "1"))
    print(f"  Ground truth records: {len(ground_truth)} ({true_count} true secrets)")
    print("=" * 60)

    results = {}

    print("\n── V1: Regex + Keyword Scanner ─────────────────────────")
    v1 = regex_scan(paths)
    results["V1"] = compute_metrics(v1, ground_truth)
    print(results["V1"])

    print("\n── V2: Regex + AST + Dataflow ──────────────────────────")
    v2 = run_pipeline(paths, use_llm=False)
    results["V2"] = compute_metrics(v2, ground_truth)
    print(results["V2"])

    if use_llm:
        print("\n── V3: Full Pipeline (with LLM) ────────────────────────")
        try:
            v3_all = run_pipeline(paths, use_llm=True)
            v3 = [f for f in v3_all if f.get("is_real_secret") is not False]
            results["V3"] = compute_metrics(v3, ground_truth)
            print(results["V3"])
        except EnvironmentError as e:
            print(f"  Skipped — {e}")

    _print_summary(results)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run benchmark evaluation (synthetic or external ground truth)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--external", default=None,
                        help="path to external ground truth file (SecretBench CSV or JSON)")
    parser.add_argument("--format", choices=["json", "csv"], default="csv",
                        help="format of the external ground truth file")
    parser.add_argument("--paths", nargs="+", default=None,
                        help="source files/dirs to scan (required with --external)")
    parser.add_argument("--v2-only", action="store_true",
                        help="skip LLM stage (no ANTHROPIC_API_KEY needed)")
    args = parser.parse_args()

    use_llm = not args.v2_only

    if args.external:
        if not args.paths:
            parser.error("--paths is required when using --external")
        gt = (load_ground_truth_json(args.external) if args.format == "json"
              else load_ground_truth_csv(args.external))
        run_external_benchmark(args.paths, gt, use_llm=use_llm)
    else:
        run_synthetic_benchmark(use_llm=use_llm)

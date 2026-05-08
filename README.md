# Credential Leak Detector

A static analysis tool that detects hardcoded credentials in Python (and Android) source code using a three-stage hybrid pipeline: **regex pattern matching -> AST + dataflow analysis -> LLM triage**.

> **Authors:** Nisa Shahid, Nada Kaluderovic, Nada Beltagui, Amy Liao

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Pipeline Stages](#pipeline-stages)
- [Reproducing Benchmark Results](#reproducing-benchmark-results)
- [Evaluation](#evaluation)
- [Running Tests](#running-tests)
- [Example Output](#example-output)

---

## Overview

Modern applications frequently contain sensitive credentials — API keys, tokens, passwords, and cloud secrets — accidentally hardcoded into source code. If exposed through public repositories or shared files, these secrets can lead to database breaches, API abuse, and data theft.

Existing secret-scanning tools rely primarily on regex and keyword checks. While effective for known patterns, they suffer from high false positive rates and miss secrets hidden through variable aliasing, string concatenation, or indirect use.

This tool addresses those gaps by combining:

1. **Regex + keyword matching** — fast, broad first pass
2. **AST parsing + dataflow tracking** — structural context to reduce false positives and catch obfuscated secrets
3. **LLM triage** — semantic reasoning to confirm real secrets, explain risk, and suggest fixes

---

## Architecture

```
Source Files
     │
     ▼
┌─────────────────────────────┐
│  Stage 1: Regex Scanner     │  credential_scanner.py
│  - 14 regex patterns        │  - API keys, tokens, passwords,
│  - Keyword matching         │    DB strings, JWTs, etc.
└────────────┬────────────────┘
             │  candidates
             ▼
┌─────────────────────────────┐
│  Stage 2a: AST Parser       │  ast_parser.py
│  - String literal extract   │  - Enriches with variable names
│  - Handles annotations,     │  - Handles tuple unpacking,
│    tuple RHS, etc.          │    annotated assignments
└────────────┬────────────────┘
             │  variable names + values
             ▼
┌─────────────────────────────┐
│  Stage 2b: Dataflow Tracker │  dataflow_tracker.py
│  - Taint propagation        │  - Tracks aliases (a = b)
│  - Sensitive context detect │  - HTTP auth headers
│  - Risk scoring             │  - DB connection calls
└────────────┬────────────────┘
             │  risk-annotated findings
             ▼
┌─────────────────────────────┐
│  Stage 3: LLM Triage        │  llm_explainer.py
│  - Real vs placeholder      │  - Uses Claude (claude-sonnet-4-6)
│  - Risk explanation         │  - Returns structured JSON
│  - Actionable fix           │  - Graceful fallback on error
└────────────┬────────────────┘
             │  enriched findings
             ▼
┌─────────────────────────────┐
│  Report Formatter           │  report_formatter.py
│  - Sorted by risk level     │  - Redacts secret values
│  - Summary counts           │  - Human-readable output
└─────────────────────────────┘
```

---

## Project Structure

```
credential-leak-detector/
│
├── pipeline.py             # Main entry point — orchestrates all stages
├── credential_scanner.py   # Stage 1: regex + keyword scanner
├── ast_parser.py           # Stage 2a: AST string-literal extractor
├── dataflow_tracker.py     # Stage 2b: taint propagation + risk scoring
├── llm_explainer.py        # Stage 3: LLM triage via Anthropic API
├── report_formatter.py     # Human-readable report generator
├── evaluator.py            # Ablation study + precision/recall metrics
├── benchmark.py            # Self-contained synthetic benchmark (V1/V2/V3)
│
├── test_ast_parser.py      # Unit tests for AST parser
├── test_dataflow_tracker.py # Unit tests for dataflow tracker
├── test_llm_explainer.py   # Unit tests for LLM explainer + formatter
│
├── requirements.txt        # Python dependencies
├── Dockerfile              # Container for reproducible execution
└── README.md
```

---

## Installation

**Requirements:** Python 3.10+

```bash
# Clone the repository
git clone [https://github.com/nadsb26/SPA-Project.git](https://github.com/nadsb26/SPA-Project.git)
cd credential-leak-detector

# Install dependencies
pip install  -r requirements.txt

# (Optional) Set your Anthropic API key for LLM stage
export ANTHROPIC_API_KEY=sk-ant-...
```

No other external dependencies — `ast`, `re`, `json`, `pathlib` are all from the standard library.

---

## Quick Start

```bash
# Scan a single file (full pipeline with LLM)
python pipeline.py my_app.py

# Scan a directory (skip LLM — faster, no API key needed)
python pipeline.py ./src --no-llm

# Save a report and raw JSON
python pipeline.py ./src --output report.txt --json findings.json

# Scan Android files too
python pipeline.py ./android_project --extensions .py,.java,.kt,.xml
```

---

## Usage

### `pipeline.py` — Full Pipeline

```
python pipeline.py [-h] [--no-llm] [--output FILE] [--json FILE] [--extensions EXTS] paths [paths ...]

positional arguments:
  paths                 files or directories to scan

options:
  --no-llm              skip LLM stage (V2 mode — faster, no API key required)
  --output, -o FILE     save human-readable report to file
  --json FILE           save raw JSON findings to file
  --extensions, -e EXTS comma-separated extensions (default: .py,.java,.kt,.xml)
```

### `evaluator.py` — Ablation Study

Run a comparison of all three pipeline versions against a labelled ground truth:

```bash
python evaluator.py ./src --ground-truth ground_truth.json --format json
```

Ground truth JSON format:
```json
[
  {"file": "app.py", "line": 12, "value": "AIzaSy...", "is_secret": true},
  {"file": "test_app.py", "line": 5, "value": "your_api_key_here", "is_secret": false}
]
```

### Real-World Targets

**PyGoat** (intentionally vulnerable Python/Django app):

```bash
git clone https://github.com/adeyosemanputra/pygoat.git

# Quick scan — no API key needed
python pipeline.py pygoat --no-llm

# Full scan with saved report and JSON findings
python pipeline.py pygoat --output pygoat_report.txt --json pygoat_findings.json
```

**InsecureShop** (intentionally vulnerable Android/Kotlin app):

```bash
git clone https://github.com/hax0rgb/InsecureShop.git

# Quick scan — no API key needed
python pipeline.py InsecureShop --extensions .py,.java,.kt,.xml --no-llm

# Full scan with saved report and JSON findings
python pipeline.py InsecureShop --extensions .py,.java,.kt,.xml --output insecureshop_report.txt --json insecureshop_findings.json
```

---

## Pipeline Stages

### Stage 1 — Regex + Keyword Scanner (`credential_scanner.py`)

Scans each file line by line using 14 regex patterns targeting known credential formats:

| Pattern | Example |
|---|---|
| `aws_access_key_id` | `AKIAIOSFODNN7EXAMPLE` |
| `google_api_key` | `AIzaSy...` |
| `github_token` | `ghp_...` |
| `jwt_token` | `eyJ...` |
| `stripe_key` | `sk_live_...` |
| `bearer_token` | `Bearer abc123` |
| `password_assignment` | `password = "hunter2"` |
| `db_connection_string` | `postgres://user:pass@host/db` |
| + 6 more | |

A secondary keyword pass catches sensitive variable names (`token`, `api_key`, `secret`, etc.) not matched by regex.

Known placeholders (`your_api_key_here`, `changeme`, `<token>`, etc.) are filtered automatically.

---

### Stage 2a — AST Parser (`ast_parser.py`)

Uses Python's `ast` module to extract all string-literal assignments:

- Simple assignments: `api_key = "abc123"`
- Annotated assignments: `token: str = "secret"`
- Single-element tuple RHS: `key = ("abc123",)`
- Tuple unpacking targets

Returns structured records: `{variable, value, line}` — enabling the downstream stages to reference findings by variable name rather than just line number.

---

### Stage 2b — Dataflow Tracker (`dataflow_tracker.py`)

Performs lightweight intra-procedural taint analysis:

- **Taint sources**: string-literal assignments
- **Propagation**: direct aliasing (`auth = key`), f-string use, concatenation
- **Sensitive sinks**:
  - HTTP requests with `Authorization` header -> **high risk**
  - HTTP requests with tainted args -> **medium risk**
  - DB connection calls (`psycopg2.connect`, `create_engine`, `MongoClient`, etc.) -> **high risk**

Findings without a sensitive-context match are not reported — this is the primary false-positive reduction mechanism.

---

### Stage 3 — LLM Triage (`llm_explainer.py`)

Sends each finding to Claude (claude-sonnet-4-6) with:
- Variable name, redacted value preview, value length
- Pattern label, file location, dataflow risk level

Returns structured JSON:
```json
{
  "is_real_secret": true,
  "risk_level": "high",
  "explanation": "This Google API key is hardcoded and sent in an HTTP request.",
  "fix": "Move to os.getenv('GOOGLE_API_KEY') and add to .gitignore'd .env file."
}
```

Gracefully falls back (no crash) if the API is unavailable or returns malformed output.

---

## Reproducing Benchmark Results
 
### Option A — Docker (recommended)
 
This is the fastest way to reproduce results in a clean environment. No Python installation or manual dependency management is needed.
 
```bash
# Build the image
docker build -t credential-leak-detector .
 
# Run the synthetic benchmark (V1 + V2, no API key needed)
docker run --rm credential-leak-detector
 
# Run with LLM stage (V3) — requires an Anthropic API key
docker run --rm -e ANTHROPIC_API_KEY=sk-ant-... credential-leak-detector \
  python benchmark.py
 
# Run the full unit test suite inside the container
docker run --rm credential-leak-detector \
  python -m pytest test_ast_parser.py test_dataflow_tracker.py test_llm_explainer.py -v
```

### Option B — Local Python
 
```bash
pip install -r requirements.txt
 
# Reproduce V1 + V2 ablation results (no API key needed)
python benchmark.py --v2-only
 
# Reproduce full V1 / V2 / V3 results (requires ANTHROPIC_API_KEY)
python benchmark.py
```

### What `benchmark.py` does
 
Because the gold-standard datasets (SecretBench and FPSecretBench) require a data-protection agreement to access, `benchmark.py` ships a self-contained synthetic dataset that covers all major secret types, placeholder strings, and obfuscated/dataflow cases. It:
 
1. Constructs 13 controlled test files with known ground truth (11 true secrets, 11 non-secrets)
2. Runs the full V1 / V2 / V3 ablation study over those files
3. Reports Precision / Recall / F1 for each pipeline version
4. Saves ground truth labels to `benchmark_ground_truth.json` for inspection

Expected output (V1 and V2 without LLM):
 
```
============================================================
  CREDENTIAL LEAK DETECTOR — SYNTHETIC BENCHMARK
============================================================
  Cases: 13 files
  Ground truth: 11 true secrets, 11 non-secrets
============================================================
 
── V1: Regex + Keyword Scanner ─────────────────────────
 Precision : 0.889
 Recall    : 0.727
 F1-score  : 0.800
 TP=8  FP=1  FN=3
 
── V2: Regex + AST + Dataflow ──────────────────────────
 Precision : 0.889
 Recall    : 0.727
 F1-score  : 0.800
 TP=8  FP=1  FN=3
```
 
### Using SecretBench (if you have access)
 
If you have obtained access to SecretBench, export a slice as CSV with columns `[file, line, value, is_secret]` and run:
 
```bash
python benchmark.py --external path/to/secretbench_slice.csv --format csv --paths ./your_target_code/
```
 
---

## Evaluation

The `evaluator.py` module runs a **3-way ablation study**:

| Version | Components | Expected Outcome |
|---|---|---|
| V1 | Regex + keyword only | High recall, lower precision |
| V2 | + AST + dataflow | Reduced false positives |
| V3 | + LLM triage | Highest precision, context-aware |

Metrics reported: **Precision**, **Recall**, **F1-score** (matched by file + line + value).

Evaluation datasets: [SecretBench](https://github.com/setu1421/SecretBench) and [FPSecretBench](https://github.com/setu1421/SecretBench).

---

## Running Tests

All 44 unit tests run fully offline (LLM calls are mocked).

```bash
# Run all tests
pytest test_ast_parser.py test_dataflow_tracker.py test_llm_explainer.py -v

# Run a specific module
pytest test_dataflow_tracker.py -v

# Run with coverage
pytest --cov=. test_*.py
```

Tests use `unittest.mock` to avoid real API calls — the LLM tests are fully offline.

---

## Example Output

```
============================================================
  CREDENTIAL LEAK DETECTOR - REPORT
============================================================
 Total findings: 2
 High: 1
 Medium: 1
 Low: 0
 Confirmed real: 1
============================================================

────────────────────────────────────────────────────────────
[HIGH] Finding #1
────────────────────────────────────────────────────────────
 File: app.py:12
 Variable: api_key
 Value preview: 'AIza...123'
 Pattern: google_api_key
 Used in: HTTP request
 Real secret: YES

 Explanation:
 This Google API key is hardcoded and passed directly in an HTTP request,
 making it visible in version control and network logs.

 Fix:
 Move to os.getenv('GOOGLE_API_KEY') and store the value in a
 .gitignore'd .env file or a secrets manager such as AWS Secrets Manager.
```

---

## Limitations

- **Intra-procedural only**: dataflow does not cross function boundaries
- **Python-focused**: regex patterns work on Java/Kotlin/XML, but AST/dataflow are Python-only
- **No entropy analysis**: high-entropy strings without known prefixes may be missed
- **LLM cost**: Stage 3 makes one API call per finding; large codebases may incur cost/latency

---

## References

1. Basak et al., "A Comparative Study of Software Secrets Reporting by Secret Detection Tools," arXiv, 2023.
2. Alocci et al., "Evaluating Large Language Models in Detecting Secrets in Android Apps," arXiv, 2025.
3. Basak et al., "AssetHarvester," ICSE 2025.
4. Saha et al., "Secrets in Source Code: Reducing False Positives Using Machine Learning," COMSNETS 2020.
5. Gitleaks: https://github.com/gitleaks/gitleaks
6. Yelp detect-secrets: https://github.com/Yelp/detect-secrets

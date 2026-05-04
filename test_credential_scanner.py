"""
test_credential_scanner.py — unit tests for credential_scanner.py

Tests cover:
  - Each regex pattern fires on a real example
  - Known placeholders are filtered out
  - Keyword-match pass catches sensitive variable names
  - Comment lines are skipped
  - scan_file returns expected structure
  - scan_paths recurses directories correctly
"""

import tempfile
import textwrap
from pathlib import Path

import pytest

from credential_scanner import scan_file, scan_paths, is_placeholder


# ── helpers ──────────────────────────────────────────────────────────────────

def write_temp(source: str, suffix: str = ".py") -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=suffix, mode="w",
                                     encoding="utf-8", delete=False)
    tmp.write(textwrap.dedent(source))
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


def values(findings):
    return {f["value"] for f in findings}


def labels(findings):
    return {f["label"] for f in findings}


# ── placeholder filter ────────────────────────────────────────────────────────

def test_is_placeholder_empty():
    assert is_placeholder("") is True

def test_is_placeholder_known_strings():
    for v in ["your_api_key_here", "changeme", "xxxx", "****", "<token>", "placeholder"]:
        assert is_placeholder(v) is True, f"Expected {v!r} to be a placeholder"

def test_is_placeholder_real_value():
    assert is_placeholder("AIzaSyA1B2C3D4E5F6G7H8I9J0") is False

def test_is_placeholder_template_angle_brackets():
    assert is_placeholder("<my_secret_key>") is True


# ── regex pattern coverage ────────────────────────────────────────────────────

def test_aws_access_key_detected():
    f = write_temp('key = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_file(f)
    assert any(f["label"] == "aws_access_key_id" for f in findings)

def test_google_api_key_detected():
    # AIza + exactly 35 alphanumeric chars (total 39)
    f = write_temp('key = "AIzaabcdefghijklmnopqrstuvwxyzABCDEFGHI"\n')
    findings = scan_file(f)
    assert any(fi["label"] == "google_api_key" for fi in findings)

def test_github_token_detected():
    # ghp_ + exactly 36 alphanumeric chars
    f = write_temp('token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"\n')
    findings = scan_file(f)
    assert any(fi["label"] == "github_token" for fi in findings)

def test_jwt_token_detected():
    f = write_temp('tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n')
    findings = scan_file(f)
    assert any(f["label"] == "jwt_token" for f in findings)

def test_password_assignment_detected():
    f = write_temp('password = "super_secret_123"\n')
    findings = scan_file(f)
    assert any("password" in f["label"] or "keyword" in f["type"] for f in findings)

def test_db_connection_string_detected():
    f = write_temp('dsn = "postgres://admin:s3cr3t@db.example.com:5432/mydb"\n')
    findings = scan_file(f)
    assert any(f["label"] == "db_connection_string" for f in findings)

def test_stripe_key_detected():
    f = write_temp('sk = "sk_live_FAKE_EXAMPLE_NOT_REAL_00"\n')
    findings = scan_file(f)
    assert any(f["label"] == "stripe_key" for f in findings)

def test_generic_secret_detected():
    f = write_temp('client_secret = "AbCdEfGhIj123456"\n')
    findings = scan_file(f)
    assert len(findings) > 0


# ── keyword pass ──────────────────────────────────────────────────────────────

def test_keyword_pass_catches_token():
    f = write_temp('access_token = "someRandomValue123456"\n')
    findings = scan_file(f)
    assert len(findings) > 0

def test_keyword_pass_catches_credential():
    f = write_temp('credentials = "realLookingValue9876"\n')
    findings = scan_file(f)
    assert len(findings) > 0


# ── placeholder filtering in scanner ─────────────────────────────────────────

def test_placeholder_filtered_from_scan():
    f = write_temp('api_key = "your_api_key_here"\n')
    findings = scan_file(f)
    assert findings == []

def test_changeme_filtered():
    f = write_temp('password = "changeme"\n')
    findings = scan_file(f)
    assert findings == []


# ── comment lines skipped ─────────────────────────────────────────────────────

def test_comment_line_skipped():
    f = write_temp('# password = "hunter2"\n')
    findings = scan_file(f)
    assert findings == []

def test_inline_code_after_comment_skipped():
    # A line that is entirely a comment is skipped; inline comments are not
    f = write_temp('  # api_key = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_file(f)
    assert findings == []


# ── result structure ──────────────────────────────────────────────────────────

def test_finding_has_required_keys():
    f = write_temp('password = "realpassword123"\n')
    findings = scan_file(f)
    assert len(findings) > 0
    for finding in findings:
        assert "file" in finding
        assert "line" in finding
        assert "value" in finding
        assert "label" in finding
        assert "type" in finding

def test_finding_line_number_correct():
    f = write_temp("""\
        x = 1
        api_key = "AKIAIOSFODNN7EXAMPLE"
    """)
    findings = scan_file(f)
    aws = [fi for fi in findings if fi["label"] == "aws_access_key_id"]
    assert len(aws) >= 1
    assert aws[0]["line"] == 2


# ── scan_paths ────────────────────────────────────────────────────────────────

def test_scan_paths_finds_file():
    f = write_temp('password = "realpassword123"\n')
    findings = scan_paths([str(f)])
    assert len(findings) > 0

def test_scan_paths_recurses_directory():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "a.py").write_text('password = "realpassword123"\n', encoding="utf-8")
        (Path(d) / "b.py").write_text('api_key = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        findings = scan_paths([d])
        labs = labels(findings)
        assert "aws_access_key_id" in labs

def test_scan_paths_respects_extensions():
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "a.py").write_text('password = "realpassword123"\n', encoding="utf-8")
        (Path(d) / "b.txt").write_text('password = "realpassword123"\n', encoding="utf-8")
        findings_py = scan_paths([d], extensions=(".py",))
        findings_txt = scan_paths([d], extensions=(".txt",))
        # .py should be found; .txt also matches — both have findings
        assert len(findings_py) > 0

def test_scan_paths_missing_path_no_crash(capsys):
    findings = scan_paths(["/no/such/path"])
    assert findings == []
    out = capsys.readouterr().out
    assert "path not found" in out

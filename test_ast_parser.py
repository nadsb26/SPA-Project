import json
import tempfile
import textwrap
from pathlib import Path

from ast_parser import extract_assignments, scan_paths


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def write_temp(source: str) -> Path:
    """Write source text to a temporary .py file and return its path."""
    tmp = tempfile.NamedTemporaryFile(suffix=".py", mode="w",
                                     encoding="utf-8", delete=False)
    tmp.write(textwrap.dedent(source))
    tmp.flush()
    tmp.close()
    return Path(tmp.name)


def as_dict(results: list) -> dict:
    """Index results by variable name for easy lookup in assertions."""
    return {r["variable"]: r for r in results}


# ---------------------------------------------------------------------------
# basic assignment forms
# ---------------------------------------------------------------------------

def test_simple_string_assignment():
    f = write_temp("""\
        api_key = "123abc"
    """)
    results = extract_assignments(f)
    assert len(results) == 1
    assert results[0]["variable"] == "api_key"
    assert results[0]["value"] == "123abc"
    assert results[0]["line"] == 1


def test_annotated_assignment():
    f = write_temp("""
        token: str = "my-secret-token"
    """)
    results = extract_assignments(f)
    assert len(results) == 1
    assert results[0]["variable"] == "token"
    assert results[0]["value"] == "my-secret-token"


def test_multiple_assignments():
    f = write_temp("""
        api_key = "key-value"
        password = "hunter2"
        db_host = "localhost"
    """)
    d = as_dict(extract_assignments(f))
    assert set(d.keys()) == {"api_key", "password", "db_host"}
    assert d["password"]["value"] == "hunter2"


# ---------------------------------------------------------------------------
# non-string values should be ignored
# ---------------------------------------------------------------------------

def test_integer_assignment_ignored():
    f = write_temp("""
        port = 5432
    """)
    assert extract_assignments(f) == []


def test_none_assignment_ignored():
    f = write_temp("""
        token = None
    """)
    assert extract_assignments(f) == []


def test_list_assignment_ignored():
    f = write_temp("""
        items = ["a", "b"]
    """)
    assert extract_assignments(f) == []


def test_bool_assignment_ignored():
    f = write_temp("""
        debug = True
    """)
    assert extract_assignments(f) == []


# ---------------------------------------------------------------------------
# tuple unpacking on the left-hand side
# ---------------------------------------------------------------------------

def test_tuple_unpack():
    f = write_temp("""
        user, role = "admin", "superuser"
    """)
    # right-hand side is a tuple of two strings — only the *first* target
    # gets the tuple value; but our parser pairs each name with the RHS node.
    # We expect both names to be captured if RHS is a plain string;
    # here RHS is a Tuple (not a Constant), so nothing should be captured.
    results = extract_assignments(f)
    assert results == []


def test_single_element_tuple_rhs():
    f = write_temp("""
        key = ("abc123",)
    """)
    results = extract_assignments(f)
    assert len(results) == 1
    assert results[0]["variable"] == "key"
    assert results[0]["value"] == "abc123"


# ---------------------------------------------------------------------------
# annotated assignment without a value (declaration only)
# ---------------------------------------------------------------------------

def test_annotated_no_value_ignored():
    f = write_temp("""
        secret: str
    """)
    assert extract_assignments(f) == []


# ---------------------------------------------------------------------------
# line numbers
# ---------------------------------------------------------------------------

def test_line_numbers_are_correct():
    f = write_temp("""\
        x = "first"
        y = 42
        z = "third"
    """)
    d = as_dict(extract_assignments(f))
    assert d["x"]["line"] == 1
    assert d["z"]["line"] == 3


# ---------------------------------------------------------------------------
# error handling
# ---------------------------------------------------------------------------

def test_syntax_error_returns_empty(capsys):
    f = write_temp("""
        def broken(:
            pass
    """)
    results = extract_assignments(f)
    assert results == []
    captured = capsys.readouterr()
    assert "syntax error" in captured.out


def test_nonexistent_file_returns_empty(capsys):
    results = extract_assignments("/nonexistent/path/file.py")
    assert results == []
    captured = capsys.readouterr()
    assert "couldn't read" in captured.out


# ---------------------------------------------------------------------------
# scan_paths — directory scanning
# ---------------------------------------------------------------------------

def test_scan_paths_single_file():
    f = write_temp("""
        api_key = "abc-123"
    """)
    results = scan_paths([str(f)])
    assert any(r["variable"] == "api_key" for r in results)


def test_scan_paths_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        (d / "a.py").write_text('secret = "val-a"\n', encoding="utf-8")
        (d / "b.py").write_text('password = "val-b"\n', encoding="utf-8")
        (d / "skip.txt").write_text('token = "ignored"\n', encoding="utf-8")

        results = scan_paths([tmpdir])
        names = {r["variable"] for r in results}

        assert "secret" in names
        assert "password" in names
        # .txt file must be skipped (scan_paths only globs *.py)
        assert not any(r["value"] == "ignored" for r in results)


def test_scan_paths_missing_path(capsys):
    results = scan_paths(["/no/such/path"])
    assert results == []
    captured = capsys.readouterr()
    assert "path not found" in captured.out


# ---------------------------------------------------------------------------
# output structure
# ---------------------------------------------------------------------------

def test_result_keys():
    f = write_temp("""
        my_var = "hello"
    """)
    results = extract_assignments(f)
    assert len(results) == 1
    assert set(results[0].keys()) == {"variable", "value", "line"}


def test_result_is_json_serialisable():
    f = write_temp("""
        token = "abc"
    """)
    results = extract_assignments(f)
    # should not raise
    json.dumps(results)

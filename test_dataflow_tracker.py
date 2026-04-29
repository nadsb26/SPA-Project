import textwrap

from dataflow_tracker import analyze_source


def _by_var(records):
    return {r["variable"]: r for r in records}


def test_requests_authorization_header_high_risk():
    code = textwrap.dedent("""\
        import requests
        key = "123"
        requests.get("http://x", headers={"Authorization": key})
    """)
    records = analyze_source(code, filename="test.py")
    by_var = _by_var(records)

    assert "key" in by_var
    assert by_var["key"]["risk"] == "high"
    assert by_var["key"]["used_in"] == "HTTP request"


def test_requests_authorization_header_propagates_aliases():
    code = textwrap.dedent("""\
        import requests
        key = "123"
        auth = key
        requests.get("http://x", headers={"Authorization": auth})
    """)
    records = analyze_source(code, filename="test.py")
    by_var = _by_var(records)

    assert "key" in by_var
    assert by_var["key"]["risk"] == "high"
    assert by_var["key"]["used_in"] == "HTTP request"


def test_db_connection_credentials_high_risk():
    code = textwrap.dedent("""\
        import psycopg2
        user = "u"
        pwd = "p"
        conn = psycopg2.connect(user=user, password=pwd)
    """)
    records = analyze_source(code, filename="test.py")
    by_var = _by_var(records)

    assert "user" in by_var
    assert "pwd" in by_var
    assert by_var["user"]["risk"] == "high"
    assert by_var["pwd"]["risk"] == "high"
    assert by_var["user"]["used_in"] == "DB connection"
    assert by_var["pwd"]["used_in"] == "DB connection"


def test_non_sensitive_usage_reports_nothing():
    code = textwrap.dedent("""\
        token = "abc"
        print(token)
    """)
    records = analyze_source(code, filename="test.py")
    assert records == []


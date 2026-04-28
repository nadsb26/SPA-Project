import re
import json
import argparse
from pathlib import Path

# regex patterns for common credential formats
# each one is (name, pattern) - name allows us to identify what we matched

PATTERNS = [

    # generic api key variable 
    ("api_key_generic", re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']', re.IGNORECASE)),

    # AWS keys always start with AKIA or ASIA
    ("aws_access_key_id", re.compile(r'\b(A(?:KIA|SIA)[0-9A-Z]{16})\b')),

    ("aws_secret_access_key",
    re.compile(r'(?:aws_secret|secret_access_key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', re.IGNORECASE)),

    # google api keys start with AIza
    ("google_api_key", re.compile(r'\b(AIza[0-9A-Za-z\-_]{35})\b')),

    # github tokens
    ("github_token", re.compile(r'\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b')),

    # slack tokens start with xox
    ("slack_token", re.compile(r'\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b')),

    ("stripe_key", re.compile(r'\b(sk_live_[0-9a-zA-Z]{24,})\b')),

    # JWTs tokens start with eyJ, consist of three base64 parts, separated by dots
    ("jwt_token", re.compile(r'\b(eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)\b')),

    ("bearer_token", re.compile(r'["\']Bearer\s+([A-Za-z0-9\-_.~+/]+=*)["\']', re.IGNORECASE)),

    ("oauth_token", re.compile(r'(?:access_token|oauth_token|auth_token)\s*[=:]\s*["\']([A-Za-z0-9\-_.]{16,})["\']', re.IGNORECASE)),

    # passwords dont have a fixed format, match is done based on variable name
    ("password_assignment", re.compile(r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{6,})["\']', re.IGNORECASE)),

    # db connection strings usually hve credentials embedded in the url
    ("db_connection_string", re.compile(r'((?:postgres|mysql|mongodb|redis|amqp)://[^\s"\'<>]+)', re.IGNORECASE)),

    ("generic_secret", re.compile(r'(?:secret|client_secret|app_secret)\s*[=:]\s*["\']([A-Za-z0-9\-_!@#$%^&*]{8,})["\']', re.IGNORECASE)),

    ("private_key_header", re.compile(r'(-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)')),
]


# variable/parameter names that suggest something sensitive is being stored
SENSITIVE_KEYWORDS = {
    # passwords
    "password", "passwd", "pwd", "pass",
    # keys
    "api_key", "apikey", "api_secret", "app_key", "app_secret",
    "client_key", "client_secret", "consumer_key", "consumer_secret",
    "private_key", "secret_key", "signing_key", "encryption_key",
    # tokens
    "token", "auth_token", "access_token", "refresh_token",
    "oauth_token", "bearer_token", "id_token", "session_token",
    "csrf_token",
    # cloud / infra
    "aws_access_key_id", "aws_secret_access_key", "aws_session_token",
    "azure_client_secret", "gcp_service_account_key",
    # database
    "db_password", "database_password", "db_pass",
    # generic
    "secret", "credential", "credentials", "auth",
}

#  builds one combined pattern from all keywords
keyword_pattern = re.compile(
    r'\b(' + '|'.join(re.escape(k) for k in SENSITIVE_KEYWORDS) + r')'
    r'\s*[=:]\s*["\']([^"\']{4,})["\']',
    re.IGNORECASE,
)


# strings that are clearly not real credentials (placeholders)
PLACEHOLDERS = {
        "", "your_api_key_here", "your-api-key", "xxxx", "****",
        "changeme", "change_me", "replace_me", "todo", "none",
        "null", "undefined", "example", "test", "placeholder",
        "<api_key>", "<token>", "<password>", "<secret>",
        "your_token_here", "insert_key_here",
}

def is_placeholder(value):
    v = value.lower().strip()
    # also skip anything that looks like <some_template_variable>
    if v.startswith("<") and v.endswith(">"):
        return True
    return v in PLACEHOLDERS


def scan_file(filepath):
    findings = []
    path = Path(filepath)

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        print(f"couldn't read {filepath}: {e}")
        return findings
    
    lines = content.splitlines()

    for line_num, line in enumerate(lines, start=1):
        stripped = line.lstrip()

        # skip comment lines
        if stripped.startswith("#") or stripped.startswith("//"):
            continue

        # regex pass - check each pattern against this line 
        for name, pattern in PATTERNS:
            for match in pattern.finditer(line):
                # group(1) captures just the credential value, not the whole match
                if match.lastindex and match.lastindex >= 1:
                    value = match.group(1)
                else:
                    value = match.group(0)
                
                if is_placeholder(value):
                    continue

                findings.append({
                    "file": str(path),
                    "value": value,
                    "line": line_num,
                    "type": "regex_match",
                    "label": name,
                })

        #keyword pass - catch anything with a senstive variable name that regex didn't catch
        for match in keyword_pattern.finditer(line):
            keyword = match.group(1)
            value   = match.group(2)

            if is_placeholder(value):
                continue
            
            # avoid duplicates; don't add if already reported through regex pass
            already_found = any(f["line"] == line_num and f["value"] == value for f in findings)
            if not already_found:
                findings.append({
                    "file":  str(path),
                    "value": value,
                    "line":  line_num,
                    "type":  "keyword_match",
                    "label": f"keyword:{keyword.lower()}",
                })

    return findings

# recursively scan files under each path
def scan_paths(paths, extensions=(".py", ".java", ".kt", ".xml")):
    all_findings = []

    for p in paths:
        p = Path(p)
        if p.is_file():
            all_findings.extend(scan_file(p))
        elif p.is_dir():
            for ext in extensions:
                for f in p.rglob(f"*{ext}"):
                    all_findings.extend(scan_file(f))
        else:
            print(f"path not found: {p}")

    return all_findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="scan source files for hardcoded credentials")
    parser.add_argument("paths", nargs="+", help="files or directories to scan")
    parser.add_argument("--output", "-o", default=None, help="save results to this json file")
    parser.add_argument("--extensions", "-e",default=".py,.java,.kt,.xml", help="file extensionsto scan, comma sepearted")
    args = parser.parse_args()

    exts = tuple(e.strip() for e in args.extensions.split(","))
    findings = scan_paths(args.paths, extensions=exts)
    output = json.dumps(findings, indent=2)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"found {len(findings)} potential credential(s), saved to {args.output}")
    else:
        print(output)

if __name__ == "__main__":
    main()

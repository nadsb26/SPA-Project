import json
 
RISK_LABELS = {"high": "[HIGH]", "medium": "[MEDIUM]", "low": "[LOW]", "unknown": "[UNKNOWN]"}
# controls sort order; high risk findings appear first in the report
RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "unknown": 3}

def redact_secret(value: str) -> str:
    """Show only a small preview instead of printing the full secret."""
    if not value:
        return ""
    value = str(value)
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]
 
 
def format_finding(finding: dict, index: int) -> str:
    # pull risk from LLM result if available, otherwise fall back to dataflow risk
    risk = (finding.get("risk_level") or finding.get("risk") or "unknown").lower()
    icon = RISK_LABELS.get(risk, "[UNKNOWN]")
    variable = finding.get("variable", "unknown")
    value = finding.get("value", "")
    file_ = finding.get("file", "unknown file")
    line = finding.get("line")
    used_in = finding.get("used_in", "not tracked")
    label = finding.get("label", "")
    is_real = finding.get("is_real_secret")
    expl = finding.get("explanation", "No explanation available.")
    fix = finding.get("fix", "Move secret to environment variable.")
 
    loc = f"{file_}:{line}" if line else file_
    real_str = "YES" if is_real is True else ("NO (likely placeholder)" if is_real is False else "unknown")
 
    lines = [
        "─" * 60,
        f"{icon} Finding #{index}",
        "─" * 60,
        f" File: {loc}",
        f" Variable: {variable}",
        f" Value preview: {redact_secret(value)!r}",
        f" Pattern: {label}",
        f" Used in: {used_in}",
        f" Real secret: {real_str}",
        "",
        " Explanation:",
        f" {expl}",
        "",
        " Fix:",
        f" {fix}",
    ]
    return "\n".join(lines)
 
 
def format_report(findings: list[dict]) -> str:
    if not findings:
        return "No credentials detected.\n"
 
    # sort by risk level first, then by file name
    sorted_findings = sorted(
        findings,
        key=lambda f: (
            RISK_ORDER.get((f.get("risk_level") or f.get("risk") or "unknown").lower(), 3),
            f.get("file", ""),
        )
    )
 
    # count how many of each risk level there is
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0, "unknown": 0}
    real_count = 0
    for f in sorted_findings:
        r = (f.get("risk_level") or f.get("risk") or "unknown").lower()
        counts[r] = counts.get(r, 0) + 1
        if f.get("is_real_secret") is True:
            real_count += 1
 
    header = "\n".join([
        "=" * 60,
        "  CREDENTIAL LEAK DETECTOR - REPORT",
        "=" * 60,
        f" Total findings: {len(findings)}",
        f" High: {counts['high']}",
        f" Medium: {counts['medium']}",
        f" Low: {counts['low']}",
        f" Confirmed real: {real_count}",
        "=" * 60,
        "",
    ])
 
    body = "\n\n".join(
        format_finding(f, i + 1) for i, f in enumerate(sorted_findings)
    )
 
    return header + body + "\n"
 
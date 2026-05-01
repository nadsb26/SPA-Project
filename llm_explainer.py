import os
import json
import anthropic
 

# keep one client instance and reuse it across calls
 
_client = None
 
def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY is not set." 
                "Run: export ANTHROPIC_API_KEY=sk-ant-..." 
            )
        _client = anthropic.Anthropic(api_key=api_key)
    return _client

def redact_secret(value: str) -> str:
    # show only a small preview so the report/LLM does not leak the full secret
    if not value:
        return ""
    value = str(value)
    if len(value) <= 8:
        return "***"
    return value[:4] + "..." + value[-4:]
 
# tells the model what role it's playing before we send any finding
 
SYSTEM_PROMPT = (
    "You are a security expert specializing in static analysis of source code. "
    "You are given details about a string value detected in code that may be a hardcoded credential. "
    "Your job is to:\n"
    "  1. Decide whether it is a real secret or a harmless placeholder or test value.\n"
    "  2. Explain the risk clearly for a developer who is not a security expert.\n"
    "  3. Suggest a concrete, actionable fix.\n\n"
    "Always respond with valid JSON only — no markdown fences, no extra text."
)
 
def _build_prompt(finding: dict) -> str:
    variable = finding.get("variable", "unknown")
    value = finding.get("value", "")
    redacted_value = redact_secret(value)
    label = finding.get("label", "unknown pattern")
    file_ = finding.get("file", "unknown file")
    line = finding.get("line", "?")
    used_in = finding.get("used_in", "not tracked")
    prelim = finding.get("risk", "unknown")

    # give the model all the context we have and tell it exactly what shape to respond in
    return (
        f"  Credential detection report:\n"
        f"  Variable name : {variable}\n"
        f"  Detected value preview: {redacted_value}\n"
        f"  Value length: {len(str(value))}\n"
        f"  Pattern label : {label}\n"
        f"  File : {file_}, line {line}\n"
        f"  Used in : {used_in}\n"
        f"  Preliminary risk (dataflow): {prelim}\n\n"
        "Respond with this exact JSON structure:\n"
        "{\n"
        '  "is_real_secret": true or false,\n'
        '  "risk_level": "high" or "medium" or "low",\n'
        '  "explanation": "one or two sentences explaining the risk",\n'
        '  "fix": "concrete suggestion, e.g. use os.getenv() or a secrets manager"\n'
        "}"
    )
 

 
def explain_finding(finding: dict) -> dict:
    # takes one finding from the pipeline and asks Claude to explain it
    # returns a dict with: is_real_secret, risk_level, explanation, fix
    # if the API call fails for any reason, we return a safe fallback instead of crashing
    prompt = _build_prompt(finding)
 
    try:
        message = _get_client().messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = message.content[0].text.strip()
 
        # Strip markdown fences if the model adds them despite instructions
        if raw.startswith("```"):
            parts = raw.split("```")
            raw = parts[1].lstrip("json").strip() if len(parts) > 1 else raw
 
        return json.loads(raw)
 
    except json.JSONDecodeError as e:
        return _fallback(finding, f"JSON parse error: {e}")
    except anthropic.APIError as e:
        return _fallback(finding, f"API error: {e}")
    except Exception as e:
        return _fallback(finding, f"Unexpected error: {e}")
 
def explain_findings(findings: list[dict]) -> list[dict]:
    # runs explain_finding on each item and merges the result back in
    enriched = []
    for finding in findings:
        explanation = explain_finding(finding)
        enriched.append({**finding, **explanation})
    return enriched
 
def _fallback(finding: dict, reason: str) -> dict:
    """Return a safe fallback when the LLM call fails."""
    print(f"[llm_explainer] Warning — using fallback for "
          f"'{finding.get('variable', '?')}': {reason}")
    return {
        "is_real_secret": None,          
        "risk_level": finding.get("risk", "unknown"),
        "explanation": f"LLM explanation unavailable ({reason}).",
        "fix": "Review manually and move secrets to environment variables.",
    }
 
import json
from unittest.mock import patch, MagicMock
 
import pytest
 
from llm_explainer import explain_finding, explain_findings, _build_prompt, _fallback
from report_formatter import format_report, format_finding
 
 

# sample data used across multiple tests
 
SAMPLE_FINDING = {
    "file" : "app.py",
    "line" : 12,
    "variable" : "api_key",
    "value" : "AIzaSyAbc123",
    "label" : "google_api_key",
    "used_in" : "HTTP request",
    "risk" : "high",
}
 
GOOD_LLM_RESPONSE = {
    "is_real_secret": True,
    "risk_level" : "high",
    "explanation" : "This Google API key is hardcoded and sent in an HTTP request.",
    "fix" : "Move to os.getenv('GOOGLE_API_KEY') and add to .env file.",
}
 
PLACEHOLDER_FINDING = {
    "file" : "test_app.py",
    "line" : 5,
    "variable" : "api_key",
    "value" : "your_api_key_here",
    "label" : "api_key_generic",
    "used_in" : "not tracked",
    "risk" : "unknown",
}
 
PLACEHOLDER_LLM_RESPONSE = {
    "is_real_secret" : False,
    "risk_level" : "low",
    "explanation" : "This is a placeholder value, not a real credential.",
    "fix" : "No action needed.",
} 
 
def _mock_client(response_dict: dict):
    # builds a fake Anthropic client that returns the given dict as JSON
    # so our tests never actually call the real API
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=json.dumps(response_dict))]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    return mock_client
 
# prompt builder tests; no API call needed
 
def test_prompt_contains_variable_name():
    prompt = _build_prompt(SAMPLE_FINDING)
    assert "api_key" in prompt
 
def test_prompt_contains_value():
    prompt = _build_prompt(SAMPLE_FINDING)
    assert "AIza" in prompt
 
def test_prompt_contains_used_in():
    prompt = _build_prompt(SAMPLE_FINDING)
    assert "HTTP request" in prompt
 
def test_prompt_contains_file_and_line():
    prompt = _build_prompt(SAMPLE_FINDING)
    assert "app.py" in prompt
    assert "12" in prompt
 
def test_prompt_works_with_minimal_finding():
    # should not raise even if most keys are missing
    prompt = _build_prompt({})
    assert "unknown" in prompt
 
# explain_finding tests; all use mocked API
 
def test_explain_finding_returns_correct_keys():
    with patch("llm_explainer._get_client", return_value=_mock_client(GOOD_LLM_RESPONSE)):
        result = explain_finding(SAMPLE_FINDING)
    assert "is_real_secret" in result
    assert "risk_level" in result
    assert "explanation" in result
    assert "fix" in result
 
def test_explain_finding_high_risk_secret():
    with patch("llm_explainer._get_client", return_value=_mock_client(GOOD_LLM_RESPONSE)):
        result = explain_finding(SAMPLE_FINDING)
    assert result["is_real_secret"] is True
    assert result["risk_level"] == "high"
 
def test_explain_finding_placeholder_identified():
    with patch("llm_explainer._get_client", return_value=_mock_client(PLACEHOLDER_LLM_RESPONSE)):
        result = explain_finding(PLACEHOLDER_FINDING)
    assert result["is_real_secret"] is False
    assert result["risk_level"] == "low"
 
def test_explain_finding_handles_json_error_gracefully():
    # if the LLM returns broken JSON, we should get a fallback dict not a crash
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text="NOT VALID JSON {{")]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
 
    with patch("llm_explainer._get_client", return_value=mock_client):
        result = explain_finding(SAMPLE_FINDING)
 
    assert "is_real_secret" in result
    assert "risk_level" in result
    assert "explanation" in result
    assert "fix" in result
 
def test_explain_finding_strips_markdown_fences():
    # the model sometimes wraps its JSON in ```json ... ``` despite being told not to
    fenced = "```json\n" + json.dumps(GOOD_LLM_RESPONSE) + "\n```"
    mock_message = MagicMock()
    mock_message.content = [MagicMock(text=fenced)]
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
 
    with patch("llm_explainer._get_client", return_value=mock_client):
        result = explain_finding(SAMPLE_FINDING)
 
    assert result["risk_level"] == "high"
 
# explain_findings (batch) tests
 
def test_explain_findings_returns_list():
    with patch("llm_explainer._get_client", return_value=_mock_client(GOOD_LLM_RESPONSE)):
        results = explain_findings([SAMPLE_FINDING, SAMPLE_FINDING])
    assert isinstance(results, list)
    assert len(results) == 2
 
def test_explain_findings_preserves_original_keys():
    # the original finding keys should still be there after LLM enrichment
    with patch("llm_explainer._get_client", return_value=_mock_client(GOOD_LLM_RESPONSE)):
        results = explain_findings([SAMPLE_FINDING])
    result = results[0]
    assert result["file"] == "app.py"
    assert result["line"] == 12
    assert result["variable"] == "api_key"
 
def test_explain_findings_empty_list():
    results = explain_findings([])
    assert results == []
 
# fallback tests
 
def test_fallback_has_all_keys():
    result = _fallback(SAMPLE_FINDING, "test reason")
    assert set(result.keys()) == {"is_real_secret", "risk_level", "explanation", "fix"}
 
def test_fallback_is_real_secret_is_none():
    # None means unknown — we couldn't determine it, not that it isn't a secret
    result = _fallback(SAMPLE_FINDING, "test reason")
    assert result["is_real_secret"] is None
 
# report formatter tests
 
def test_format_report_empty_returns_clean_message():
    report = format_report([])
    assert "No credentials" in report
 
def test_format_report_contains_risk_level():
    enriched = {**SAMPLE_FINDING, **GOOD_LLM_RESPONSE}
    report = format_report([enriched])
    assert "HIGH" in report
 
def test_format_report_contains_file():
    enriched = {**SAMPLE_FINDING, **GOOD_LLM_RESPONSE}
    report = format_report([enriched])
    assert "app.py" in report
 
def test_format_report_contains_fix():
    enriched = {**SAMPLE_FINDING, **GOOD_LLM_RESPONSE}
    report = format_report([enriched])
    assert "os.getenv" in report
 
def test_format_report_sorts_high_risk_first():
    low  = {**PLACEHOLDER_FINDING, **PLACEHOLDER_LLM_RESPONSE}
    high = {**SAMPLE_FINDING, **GOOD_LLM_RESPONSE}
    report = format_report([low, high])
    # HIGH should appear before LOW in the output
    assert report.index("HIGH") < report.index("LOW")
 
 
def test_format_report_summary_counts():
    enriched = {**SAMPLE_FINDING, **GOOD_LLM_RESPONSE}
    report = format_report([enriched])
    assert "Total findings: 1" in report
    assert "Confirmed real: 1" in report
 
def test_format_finding_missing_keys_no_crash():
    # should handle missing keys without throwing an error
    result = format_finding({}, 1)
    assert isinstance(result, str)
 
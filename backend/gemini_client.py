from __future__ import annotations

import json
import os
from typing import Any, Literal

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError

try:
    from google import genai
except ImportError:
    genai = None

load_dotenv()

RISK_LEVELS = ("Safe", "Low Risk", "Medium Risk", "High Risk", "Critical")
CONSEQUENCE_RISKS = ("Safe", "Warning", "Danger", "Critical")

class Consequence(BaseModel):
    model_config = ConfigDict(extra="ignore")
    step: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=500)
    risk: Literal["Safe", "Warning", "Danger", "Critical"]

class ThreatAssessmentItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    status: bool
    details: str = Field(default="", max_length=500)

class ConfidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="ignore")
    level: Literal["Low", "Medium", "High"]
    details: str = Field(default="", max_length=500)

class AIAnalysis(BaseModel):
    model_config = ConfigDict(extra="ignore")
    trust_score: int = Field(ge=0, le=100)
    risk_level: Literal["Safe", "Low Risk", "Medium Risk", "High Risk", "Critical"]
    ghost_summary: str = Field(min_length=1, max_length=2500)
    ghost_summary_en: str = Field(min_length=1, max_length=2500)
    ai_explanation: str = Field(min_length=1, max_length=1500)
    recommendations: list[str] = Field(min_length=2, max_length=4)
    consequences: list[Consequence] = Field(min_length=3, max_length=5)
    threat_assessment: dict[str, Any] = Field(default_factory=dict)

def risk_level_for_score(score: int) -> str:
    if score >= 85:
        return "Safe"
    if score >= 70:
        return "Low Risk"
    if score >= 45:
        return "Medium Risk"
    if score >= 25:
        return "High Risk"
    return "Critical"

def format_age(days: int | None) -> str:
    if days is None:
        return "an unknown amount of time ago"
    if days < 30:
        return f"only {days} day{'s' if days != 1 else ''} ago"
    if days < 365:
        months = days // 30
        return f"{months} month{'s' if months != 1 else ''} ago"
    years, months = divmod(days, 365)
    months //= 30
    return f"{years} year{'s' if years != 1 else ''}" + (f" and {months} month{'s' if months != 1 else ''}" if months else "") + " ago"

def generate_fallback_analysis(data: dict[str, Any]) -> dict[str, Any]:
    domain = str(data.get("domain") or "this website")
    score = max(0, min(100, int(data.get("base_trust_score", 50))))
    patterns = [str(value) for value in data.get("suspicious_patterns", [])][:8]
    https_enabled = bool(data.get("https_enabled"))
    age = data.get("domain_age_days")
    registrar = str(data.get("registrar") or "Unknown")
    crawled = data.get("crawled_page_content") or {}
    has_password = bool(crawled.get("has_password_field"))
    has_card = bool(crawled.get("has_card_field"))
    external_scripts = list(crawled.get("external_scripts") or [])

    risk_level = risk_level_for_score(score)
    age_text = format_age(age)
    registrar_text = f"via {registrar}" if registrar != "Unknown" else "with an unverified registrar"
    https_text = "HTTPS is active" if https_enabled else "HTTPS is not active"
    pattern_text = "No suspicious indicators were found." if not patterns else f"Detected indicators include: {', '.join(patterns[:3])}."
    input_text = "The page requests sensitive input." if has_password or has_card else "No password or payment-card input was detected."

    if risk_level == "Safe":
        explanation = f"{domain} has a strong technical score. {https_text}, the observed indicators are limited, and {input_text.lower()}"
        recs = [
            "Verify the domain name before entering credentials.",
            "Keep your browser and operating system updated.",
            "Use unique passwords and multi-factor authentication where available.",
        ]
    elif risk_level == "Low Risk":
        explanation = f"{domain} has a generally favorable technical score, but some signals deserve attention. {pattern_text}"
        recs = [
            "Double-check the domain spelling before signing in.",
            "Avoid entering highly sensitive information unless the destination is expected.",
            "Use multi-factor authentication on important accounts.",
        ]
    elif risk_level == "Medium Risk":
        explanation = f"{domain} has multiple caution signals. {https_text}. {pattern_text} {input_text}"
        recs = [
            "Avoid entering passwords, payment data, or verification codes.",
            "Confirm the destination through an independently trusted source.",
            "Do not download unexpected files from the page.",
        ]
    elif risk_level == "High Risk":
        explanation = f"{domain} has several indicators associated with potentially deceptive destinations. {pattern_text}"
        recs = [
            "Leave the site and use the organization’s official website instead.",
            "Do not enter credentials, payment information, or verification codes.",
            "Do not download or install files prompted by the page.",
        ]
    else:
        explanation = f"{domain} has critical warning signals. The scan cannot establish that the destination is trustworthy. {pattern_text}"
        recs = [
            "Close the page and do not interact with it further.",
            "Use the organization’s official website or app instead.",
            "Do not enter credentials, payment information, or verification codes.",
        ]

    consequences = [
        {
            "step": f"1. Open {domain}",
            "description": f"The page is requested over {'HTTPS' if https_enabled else 'HTTP without HTTPS'}; the scan does not establish that the destination is trustworthy.",
            "risk": "Safe" if score >= 70 else ("Warning" if score >= 45 else "Danger"),
        },
        {
            "step": "2. Review the page",
            "description": f"GhostNet evaluates domain, connection, page structure, and redirect signals. {pattern_text}",
            "risk": "Safe" if not patterns else ("Warning" if score >= 45 else "Danger"),
        },
        {
            "step": "3. Enter information",
            "description": "Sensitive form fields were detected." if has_password or has_card else "No sensitive form field was detected during the scan.",
            "risk": "Warning" if has_password or has_card else ("Safe" if score >= 70 else "Warning"),
        },
        {
            "step": "4. Possible outcome",
            "description": "A low-trust site could collect information or direct you to another destination; this scan cannot prove what happens after interaction.",
            "risk": "Safe" if score >= 85 else ("Warning" if score >= 45 else "Danger"),
        },
    ]

    if age is None:
        age_summary_hi = "डोमेन की रजिस्ट्रेशन उम्र सत्यापित नहीं हो सकी"
        age_summary_en = "its registration age could not be verified"
    else:
        age_summary_hi = f"डोमेन लगभग {age} दिन पुराना है"
        age_summary_en = f"the domain was registered {age_text}"

    summary_hi = (
        f"मैंने इस वेबसाइट को एक्सप्लोर किया है। {domain} के बारे में {age_summary_hi} और रजिस्ट्रार "
        f"{registrar_text} है। {https_text}। {pattern_text} {input_text} "
        f"अगर आप आगे बढ़ते हैं, तो सावधानी आपके लिए सबसे सुरक्षित विकल्प है।"
    )
    summary_en = (
        f"I explored this website before you. {domain} was registered {age_text} and is associated {registrar_text}. "
        f"{https_text}. {pattern_text} {input_text} "
        f"If you continue, treat the destination according to this risk level and avoid sharing sensitive information when the signals are unfavorable."
    )

    threat_assessment = {
        "is_brand_impersonation": {
            "status": any("brand lookalike" in item.lower() or "typosquatting" in item.lower() for item in patterns),
            "details": "A brand lookalike signal was detected." if patterns and any("brand lookalike" in item.lower() for item in patterns) else "No brand lookalike signal was detected.",
        },
        "resembles_phishing": {
            "status": score < 70 and (has_password or has_card or len(patterns) >= 2),
            "details": "Several signals resemble common phishing patterns." if score < 70 and (has_password or has_card or len(patterns) >= 2) else "The scan did not identify enough signals to classify the page as phishing-like.",
        },
        "is_unusually_new": {
            "status": age is not None and age < 90,
            "details": f"The domain age is {age} days." if age is not None else "Domain age could not be verified.",
        },
        "requests_sensitive_info": {
            "status": has_password or has_card,
            "details": "Password or payment-card fields were detected." if has_password or has_card else "No password or payment-card fields were detected.",
        },
        "multiple_warnings": {
            "status": len(patterns) >= 3,
            "details": f"{len(patterns)} distinct warning signals were retained.",
        },
        "confidence_level": {
            "level": "High" if age is not None and data.get("is_reachable") else "Medium" if data.get("is_reachable") else "Low",
            "details": "Confidence reflects the availability of live connectivity and registration metadata.",
        },
    }

    if external_scripts and has_password:
        consequences[2]["description"] += f" The page also loads third-party scripts from {', '.join(external_scripts[:2])}."

    return AIAnalysis.model_validate(
        {
            "trust_score": score,
            "risk_level": risk_level,
            "ghost_summary": summary_hi,
            "ghost_summary_en": summary_en,
            "ai_explanation": explanation,
            "recommendations": recs,
            "consequences": consequences,
            "threat_assessment": threat_assessment,
        }
    ).model_dump()

def sanitize_ai_result(result: Any, baseline: int) -> dict[str, Any]:
    parsed = AIAnalysis.model_validate(result)
    bounded_score = max(0, min(100, int(parsed.trust_score)))
    lower, upper = max(0, baseline - 10), min(100, baseline + 10)
    parsed.trust_score = min(max(bounded_score, lower), upper)
    parsed.risk_level = risk_level_for_score(parsed.trust_score)
    parsed.ghost_summary = parsed.ghost_summary.strip()
    parsed.ghost_summary_en = parsed.ghost_summary_en.strip()
    parsed.ai_explanation = parsed.ai_explanation.strip()
    parsed.recommendations = [item.strip() for item in parsed.recommendations if item.strip()][:4]
    parsed.consequences = parsed.consequences[:5]
    return parsed.model_dump()

def build_prompt(data: dict[str, Any]) -> str:
    return json.dumps(
        {
            "task": "Explain the provided website security scan to a normal user.",
            "constraints": {
                "do_not_invent_facts": True,
                "do_not_claim_malware_or_data_theft_as_confirmed_without_evidence": True,
                "risk_level_must_match_trust_score": True,
                "recommendations_language": "English",
                "summary_languages": ["Hindi", "English"],
            },
            "scan": {
                "url": data.get("url"),
                "domain": data.get("domain"),
                "https_enabled": data.get("https_enabled"),
                "is_reachable": data.get("is_reachable"),
                "domain_age_days": data.get("domain_age_days"),
                "registrar": data.get("registrar"),
                "suspicious_patterns": data.get("suspicious_patterns", []),
                "base_trust_score": data.get("base_trust_score"),
                "scorecard": data.get("scorecard", {}),
                "crawled_page_content": data.get("crawled_page_content", {}),
            },
            "output": {
                "trust_score": "integer 0-100 close to the baseline",
                "risk_level": list(RISK_LEVELS),
                "ghost_summary": "Hindi Devanagari paragraph starting with 'मैंने इस वेबसाइट को एक्सप्लोर किया है।'",
                "ghost_summary_en": "English paragraph starting with 'I explored this website before you.'",
                "ai_explanation": "concise English explanation",
                "recommendations": "2-4 English safety recommendations",
                "consequences": "3-5 ordered objects with step, description, risk",
                "threat_assessment": "object containing evidence-based security flags",
            },
        },
        ensure_ascii=False,
    )

async def get_ai_explanation(analysis_data: dict[str, Any]) -> dict[str, Any]:
    baseline = max(0, min(100, int(analysis_data.get("base_trust_score", 50))))
    api_key = os.getenv("GEMINI_API_KEY")
    model_name = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
    if not api_key or genai is None:
        return generate_fallback_analysis(analysis_data)

    try:
        async with genai.Client(api_key=api_key).aio as client:
            response = await client.models.generate_content(
                model=model_name,
                contents=build_prompt(analysis_data),
                config={
                    "response_mime_type": "application/json",
                    "response_schema": AIAnalysis.model_json_schema(),
                },
            )
        raw_text = response.text
        if not raw_text:
            raise ValueError("Gemini returned an empty response.")
        result = json.loads(raw_text)
        return sanitize_ai_result(result, baseline)
    except Exception:
        return generate_fallback_analysis(analysis_data)

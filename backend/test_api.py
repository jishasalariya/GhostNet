import asyncio

from analyzer import analyze_url
from gemini_client import generate_fallback_analysis


async def test_analyzer() -> None:
    print("Testing URL analyzer...")
    test_urls = [
        "https://google.com",
        "https://paypal-secure-verify.login-check.xyz",
        "http://http-legacy-unsafe.net",
        "https://paypa1-update.xyz/login",
        "https://secure-login-check.top/banking",
        "https://netflix-account-verification.live/login",
        "https://checkout.cloudplaza.io/cz/f2aohaemf?affId=B27ACA03&c1=4",
        "https://flowcode.com/p/PVWkfzw5y?fc=0",
    ]

    for url in test_urls:
        print(f"\nScanning: {url}")
        result = await analyze_url(url)
        crawled = result.get("crawled_page_content", {})

        print(f"Domain: {result['domain']}")
        print(f"HTTPS Enforced: {result['https_enabled']}")
        print(f"Suspicious URL Signatures: {result['suspicious_patterns']}")
        print(f"Calculated Base Trust Score: {result['base_trust_score']}")
        print(f"Crawled Title: {crawled.get('title')}")
        print(f"Has Password Field: {crawled.get('has_password_field')}")
        print(f"Forms Count: {crawled.get('forms_count')}")
        print(f"Inputs Found: {crawled.get('input_fields')}")
        print(f"Subpages Scanned: {crawled.get('subpages_scanned')}")
        print(f"Scorecard: {result.get('scorecard')}")

        ai_data = generate_fallback_analysis(result)
        print(f"Calculated Risk Level: {ai_data['risk_level']}")
        print(f"Threat Assessment: {ai_data.get('threat_assessment')}")
        print(f"Ghost Summary: {ai_data['ghost_summary']}")
        print(f"Consequence Stepper (Steps Count): {len(ai_data['consequences'])}")


if __name__ == "__main__":
    asyncio.run(test_analyzer())

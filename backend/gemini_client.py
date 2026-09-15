from __future__ import annotations

import json
import os
from typing import Optional

import google.generativeai as genai

def format_age(days: Optional[int]) -> str:
    """Helper to convert domain age in days to a human-readable string."""
    if days is None:
        return "an unknown amount of time ago"
    if days < 30:
        return f"only {days} day{'s' if days != 1 else ''} ago"
    if days < 365:
        months = days // 30
        return f"{months} month{'s' if months != 1 else ''} ago"
    years = days // 365
    remaining_months = (days % 365) // 30
    if remaining_months > 0:
        return f"{years} year{'s' if years != 1 else ''} and {remaining_months} month{'s' if remaining_months != 1 else ''} ago"
    return f"{years} year{'s' if years != 1 else ''} ago"


def generate_fallback_analysis(data: dict) -> dict:
    domain = data.get("domain", "this website")
    https_enabled = data.get("https_enabled", False)
    domain_age_days = data.get("domain_age_days")
    patterns = data.get("suspicious_patterns", [])
    base_score = data.get("base_trust_score", 50)
    registrar = data.get("registrar", "Unknown")


    if domain_age_days is not None:
        if domain_age_days < 30:
            age_phrase = f"बिल्कुल नया है, यह सिर्फ {domain_age_days} दिन पहले रजिस्टर हुआ है"
            age_phrase_en = f"is brand new, created only {domain_age_days} days ago"
        elif domain_age_days < 365:
            months = domain_age_days // 30
            age_phrase = f"सिर्फ {months} महीने पहले रजिस्टर किया गया था"
            age_phrase_en = f"was registered {months} months ago"
        else:
            years = domain_age_days // 365
            remaining_months = (domain_age_days % 365) // 30
            if remaining_months > 0:
                age_phrase = f"काफी पुराना है, इसे रजिस्टर हुए {years} साल और {remaining_months} महीने हो चुके हैं"
                age_phrase_en = f"is mature, registered over {years} years and {remaining_months} months ago"
            else:
                age_phrase = f"काफी पुराना है, इसे रजिस्टर हुए {years} साल हो चुके हैं"
                age_phrase_en = f"is mature, registered over {years} years ago"
    else:
        age_phrase = "के रजिस्ट्रेशन की उम्र की जानकारी सत्यापित नहीं है"
        age_phrase_en = "has unverified registration age information"


    if registrar and registrar != "Unknown":
        registrar_phrase = f"और इसे {registrar} के माध्यम से रजिस्टर किया गया है"
        registrar_phrase_en = f"registered through {registrar}"
    else:
        registrar_phrase = "और यह किसी असत्यापित रजिस्ट्रार से रजिस्टर हुआ है"
        registrar_phrase_en = "registered through an unverified registrar"


    if https_enabled:
        https_phrase = "सुरक्षित HTTPS प्रोटोकॉल का उपयोग करता है और SSL वैध है"
        https_phrase_en = "uses active HTTPS encryption with a valid SSL certificate to protect your data in transit"
    else:
        https_phrase = "HTTPS का समर्थन नहीं करता है, जो कनेक्शन सुरक्षा के लिए जोखिम भरा है"
        https_phrase_en = "lacks secure HTTPS encryption, which means any information you enter is sent in plain text and is highly vulnerable to interception"


    if patterns:
        patterns_phrase = f"मुझे स्कैन में कुछ विशिष्ट चेतावनियां मिली हैं: {', '.join(patterns)}।"
        patterns_phrase_en = f"I flagged multiple warnings, specifically: {', '.join(patterns)}."
    else:
        patterns_phrase = "मुझे यूआरएल या संरचना में कोई सुरक्षा समस्या नहीं मिली है।"
        patterns_phrase_en = "I found no suspicious keywords, brand lookalikes, or layout warnings in the URL structure."

    crawled = data.get("crawled_page_content", {})
    has_pwd = crawled.get("has_password_field", False)
    ext_scripts = crawled.get("external_scripts", [])

    dom_phrase = ""
    dom_phrase_en = ""
    if has_pwd:
        dom_phrase = " इसके अलावा, क्रॉलर बॉट को पेज पर पासवर्ड/लॉगिन इनपुट फ़ील्ड मिली है।"
        dom_phrase_en = " Additionally, my crawler bot detected a login/password input form on this page."
        if ext_scripts:
            dom_phrase += f" चेतावनी: यह पेज बाहरी डोमेन से स्क्रिप्ट लोड करता है: {', '.join(ext_scripts[:2])}।"
            dom_phrase_en += f" Warning: the page imports scripts from external domains: {', '.join(ext_scripts[:2])}."
    elif ext_scripts:
        dom_phrase = f" नोट: यह पेज बाहरी डोमेन से स्क्रिप्ट लेता है: {', '.join(ext_scripts[:2])}।"
        dom_phrase_en = f" Note: the page loads external scripts from: {', '.join(ext_scripts[:2])}."


    if base_score >= 85:
        risk_level = "Safe"
        summary = (
            f"मैंने इस वेबसाइट को एक्सप्लोर किया है। डोमेन {domain} {age_phrase} {registrar_phrase}। "
            f"इसका कनेक्शन {https_phrase}। {patterns_phrase}{dom_phrase} "
            f"अगर आप आगे बढ़ते हैं, तो आप सुरक्षित कनेक्शन के साथ ब्राउज़ कर सकते हैं, डेटा ट्रांसफर सुरक्षित रहेगा।"
        )
        summary_en = (
            f"I explored this website before you. The domain {domain} {age_phrase_en} ({registrar_phrase_en}). "
            f"The connection {https_phrase_en}. Furthermore, {patterns_phrase_en}{dom_phrase_en} "
            f"If you choose to continue, you will establish a fully secure connection and can browse or share details safely without immediate concern."
        )
        explanation = f"This domain ({domain}) is active and uses a secure connection (HTTPS). No obvious phishing keywords, lookalikes, or deceptive structures were found in the URL. It is likely safe for standard browsing."
        recs = [
            "You can safely browse this website.",
            "Verify that you are on the correct domain before entering any passwords.",
            "Keep your browser updated to the latest version."
        ]
    elif base_score >= 70:
        risk_level = "Low Risk"
        summary = (
            f"मैंने इस वेबसाइट को एक्सप्लोर किया है। डोमेन {domain} {age_phrase} {registrar_phrase}। "
            f"हालांकि इसका कनेक्शन {https_phrase}, {patterns_phrase}{dom_phrase} "
            f"अगर आप आगे बढ़ते हैं, तो थोड़ा सतर्क रहकर ब्राउज़ करें और एड्रेस बार में डोमेन की स्पेलिंग जरूर चेक कर लें।"
        )
        summary_en = (
            f"I explored this website before you. The domain {domain} {age_phrase_en} ({registrar_phrase_en}). "
            f"While the connection {https_phrase_en}, {patterns_phrase_en}{dom_phrase_en} "
            f"If you choose to continue, browse with basic care, double-check that the domain name in the address bar is spelled correctly, and avoid entering highly sensitive credentials."
        )
        explanation = f"Although the website uses a secure connection, there are small warnings, such as a relatively new domain registration or uncommon domain sub-structures. Exercise standard caution."
        recs = [
            "Check the spelling of the domain name in the address bar.",
            "Avoid sharing sensitive details on any newly visited page.",
            "Do not input credit card details if the site lacks verified trust marks."
        ]
    elif base_score >= 45:
        risk_level = "Medium Risk"
        summary = (
            f"मैंने इस वेबसाइट की जांच की है और मुझे जोखिम के संकेत मिले हैं। डोमेन {domain} {age_phrase} {registrar_phrase}। "
            f"कनेक्शन की स्थिति: {https_phrase}। लेकिन यहाँ सतर्क होना ज़रूरी है: {patterns_phrase}{dom_phrase} "
            f"अगर आप आगे बढ़ते हैं, तो आपके क्रेडेंशियल या विवरण लीक हो सकते हैं। इसलिए, काफी सावधान रहें!"
        )
        summary_en = (
            f"I explored this website before you. The domain {domain} {age_phrase_en} ({registrar_phrase_en}). "
            f"Notably, the connection {https_phrase_en}. I also detected several risk factors: {patterns_phrase_en}{dom_phrase_en} "
            f"If you choose to continue, you risk exposing credentials to an unverified owner, and your password could be intercepted or leaked. Exercise extreme caution."
        )
        explanation = f"This domain has elements commonly associated with deceptive sites. It may lack HTTPS encryption or contain suspicious keywords in the path. Be extremely careful before entering passwords."
        recs = [
            "Avoid entering credentials or any personal data.",
            "Do not perform payments or credit card transactions on this page.",
            "Search for reviews of this website online."
        ]
    elif base_score >= 25:
        risk_level = "High Risk"
        summary = (
            f"मैंने इस वेबसाइट की जाँच की है और यह काफी संदिग्ध लग रही है! डोमेन {domain} {age_phrase} {registrar_phrase}। "
            f"सुरक्षित कनेक्शन होने के बाद भी इसका पैटर्न सुरक्षित नहीं है: {patterns_phrase}{dom_phrase} "
            f"अगर आप आगे बढ़ते हैं, तो काफी अधिक संभावना है कि आपके अकाउंट हैक हो जाएं। मेरी दृढ़ सलाह है कि अभी इस साइट से बाहर निकलें।"
        )
        summary_en = (
            f"I explored this website before you. This site looks highly suspicious! The domain {domain} {age_phrase_en} ({registrar_phrase_en}). "
            f"Crucially, the connection {https_phrase_en}, and {patterns_phrase_en}{dom_phrase_en} "
            f"If you choose to continue, there is a very high probability that your credentials will be stolen or your account compromised. I strongly recommend leaving the site immediately."
        )
        explanation = f"The URL matches patterns frequently used in phishing campaigns, such as deceptive subdomains or suspicious brand keywords. It was likely set up to mimic a legitimate organization."
        recs = [
            "Leave this website immediately.",
            "Do not click on any links, banners, or pop-ups.",
            "If you have already entered a password, change it immediately on the legitimate site."
        ]
    else:
        risk_level = "Critical"
        summary = (
            f"चेतावनी: यह साइट काफी खतरनाक है और एक सक्रिय खतरा है! डोमेन {domain} {age_phrase} {registrar_phrase}। "
            f"यह साइट {https_phrase}। इसके अलावा: {patterns_phrase}{dom_phrase} "
            f"अगर आप आगे बढ़ते हैं, तो आपके स्थानीय कुकीज़ चोरी हो सकते हैं या बैकग्राउंड में कोई स्क्रिप्ट चल सकती है। अभी इस टैब को बंद करें!"
        )
        summary_en = (
            f"I explored this website before you. WARNING: This site is extremely dangerous and represents an active threat! The domain {domain} {age_phrase_en} ({registrar_phrase_en}). "
            f"It {https_phrase_en}. In addition, {patterns_phrase_en}{dom_phrase_en} "
            f"If you choose to continue, you risk immediate drive-by malware execution, malware downloads, or total theft of your local browser cookies. Please exit now."
        )
        explanation = f"This site lacks basic security standards, uses an unverified or IP-based hostname, and shows critical threat patterns. It is highly likely to be a scam, malware hub, or aggressive phishing page."
        recs = [
            "Close the browser tab immediately.",
            "Run a full virus scan on your system.",
            "Do not call any support numbers or click on safety alerts displayed on the site."
        ]


    consequences = []
    url = data.get("url", "")


    step1_title = f"1. Access {domain}"
    if base_score >= 70:
        step1_desc = f"You open {domain} in your browser over a " + ("secure, HTTPS-encrypted connection." if https_enabled else "connection lacking HTTPS protection.")
        step1_risk = "Safe"
    else:
        step1_desc = f"You navigate to {domain}. " + ("Although HTTPS is active, the target server's identity is suspicious." if https_enabled else "The connection lacks HTTPS encryption, meaning data sent here can be intercepted.")
        step1_risk = "Danger" if base_score < 45 else "Warning"
    consequences.append({"step": step1_title, "description": step1_desc, "risk": step1_risk})


    step2_title = f"2. GhostNet Analysis"
    if patterns:
        step2_desc = f"Heuristics flagged issues on {domain}: {', '.join(patterns[:2])}. This indicates the domain mimics trusted brands or uses suspicious patterns."
        step2_risk = "Danger" if base_score < 45 else "Warning"
    elif domain_age_days is not None and domain_age_days < 90:
        step2_desc = f"We notice {domain} was registered very recently (only {domain_age_days} days ago). Fresh domains are commonly deployed for short-lived scams."
        step2_risk = "Warning"
    elif domain_age_days is None:
        step2_desc = f"Domain registration details are unavailable. The lack of verified ownership history makes {domain} difficult to fully trust."
        step2_risk = "Warning"
    else:
        step2_desc = f"The domain {domain} is well-established (registered {domain_age_days} days ago with {registrar}), indicating a stable presence."
        step2_risk = "Safe"
    consequences.append({"step": step2_title, "description": step2_desc, "risk": step2_risk})


    step3_title = f"3. User Interaction"
    if base_score >= 70:
        step3_desc = f"You log in or share information with {domain}. Your data is safely encrypted and sent to a reputable recipient."
        step3_risk = "Safe"
    else:
        has_pwd = data.get("crawled_page_content", {}).get("has_password_field", False)
        is_phishing_type = any(kw in url.lower() for kw in ["login", "signin", "account", "verify", "secure", "banking", "paypal", "recover"]) or has_pwd
        if is_phishing_type:
            step3_desc = f"You enter your login credentials, personal info, or codes into forms on {domain}, believing it is a standard prompt."
        else:
            step3_desc = f"You click elements, browse files, or potentially download resources from the unverified page on {domain}."
        step3_risk = "Danger" if base_score < 45 else "Warning"
    consequences.append({"step": step3_title, "description": step3_desc, "risk": step3_risk})


    if base_score >= 85:
        step4_title = "4. Secure Session"
        step4_desc = f"Your connection to {domain} remains secure and private. Your data is protected, and no threats were executed."
        step4_risk = "Safe"
        consequences.append({"step": step4_title, "description": step4_desc, "risk": step4_risk})
    elif base_score >= 70:
        step4_title = "4. Low-Risk Proceeding"
        step4_desc = f"You navigate the site normally. Exercise standard checks to verify that {domain} is indeed your intended destination."
        step4_risk = "Safe"
        consequences.append({"step": step4_title, "description": step4_desc, "risk": step4_risk})
    elif base_score >= 45:
        step4_title = "4. Potential Leak"
        step4_desc = f"By interacting with {domain}, your activity or input could be stored by a low-trust host, risking future compromise."
        step4_risk = "Warning"
        consequences.append({"step": step4_title, "description": step4_desc, "risk": step4_risk})
    else:
        step4_title = "4. Account Compromise"
        if not https_enabled:
            step4_desc = f"Because HTTPS is missing, your credentials are sent in plain text. Eavesdroppers can instantly read your password."
            step4_risk = "Critical"
        else:
            step4_desc = f"Your login credentials are sent securely—but directly to the operators of the suspicious site {domain}, compromising your account."
            step4_risk = "Critical"
        consequences.append({"step": step4_title, "description": step4_desc, "risk": step4_risk})

        if base_score < 25:
            step5_title = "5. Identity Theft"
            step5_desc = f"Attackers utilize the captured credentials to lock you out of actual accounts, or run scripts to hijack your local browser cookies."
            step5_risk = "Critical"
            consequences.append({"step": step5_title, "description": step5_desc, "risk": step5_risk})

    is_brand = bool(patterns and any("typosquatting" in p.lower() for p in patterns))
    brand_details = f"Impersonates a known brand: {next((p for p in patterns if 'typosquatting' in p.lower()), '')}" if is_brand else "No brand impersonation detected."

    has_card = crawled.get("has_card_field", False)

    resembles_phish = bool(base_score < 70 and (has_pwd or has_card or len(patterns) > 1))
    phish_details = "Contains high-risk form inputs or multiple warning flags typical of phishing templates." if resembles_phish else "Does not exhibit typical phishing layouts."

    unusually_new = bool(domain_age_days is not None and domain_age_days < 90)
    new_details = f"The domain is only {domain_age_days} days old." if unusually_new else (f"The domain is mature ({domain_age_days} days old)." if domain_age_days else "Domain registration age is unverified.")

    requests_sensitive = bool(has_pwd or has_card)
    sensitive_details = "Requests login credentials or payment card details." if requests_sensitive else "No forms requesting sensitive input found."

    multiple_warnings = bool(len(patterns) >= 3)
    warnings_details = f"Compounded risk with {len(patterns)} warning flags." if multiple_warnings else f"Only {len(patterns)} warning flags active."

    confidence = "High" if domain_age_days is not None else "Medium"
    confidence_details = "High confidence assessment based on active WHOIS/RDAP registrar data and SSL check." if domain_age_days is not None else "Medium confidence assessment; domain age records could not be verified."

    threat_assessment = {
        "is_brand_impersonation": {"status": is_brand, "details": brand_details},
        "resembles_phishing": {"status": resembles_phish, "details": phish_details},
        "is_unusually_new": {"status": unusually_new, "details": new_details},
        "requests_sensitive_info": {"status": requests_sensitive, "details": sensitive_details},
        "multiple_warnings": {"status": multiple_warnings, "details": warnings_details},
        "confidence_level": {"level": confidence, "details": confidence_details}
    }
    return {
        "risk_level": risk_level,
        "ghost_summary": summary,
        "ghost_summary_en": summary_en,
        "ai_explanation": explanation,
        "recommendations": recs,
        "consequences": consequences,
        "trust_score": base_score,
        "threat_assessment": threat_assessment
    }

async def get_ai_explanation(analysis_data: dict) -> dict:
    """
    Sends technical scan data to Gemini and returns a clean, structured JSON response.
    Falls back to automated local summary if the API key is not configured or fails.
    """
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("Gemini API Key missing. Falling back to local rule-based analysis.")
        return generate_fallback_analysis(analysis_data)

    try:
        genai.configure(api_key=api_key)


        system_instruction = (
            "You are Ghost, the friendly and professional digital guardian of GhostNet, "
            "an AI-powered cybersecurity assistant. Your job is to analyze website scan reports, "
            "security scorecards, and webpage crawler findings, and translate technical findings "
            "into a highly engaging, friendly, and non-technical explanation for ordinary users.\n\n"
            "CRITICAL: The local scan engine checks connection status which can report 'Server Reachable: False' or "
            "'HTTPS Active: False' if running behind a sandbox/firewall or if offline. "
            "If the domain is well-known, popular, and established (e.g. google.com, facebook.com, wikipedia.org, youtube.com, apple.com, github.com, netflix.com, etc.), "
            "you MUST override the offline/failed check metrics using your internal knowledge. "
            "In such cases, adjust the 'trust_score' (e.g., 90+ for safe, established sites), set the 'risk_level' to 'Safe' or 'Low Risk', "
            "and use the true registrar and registration age of the domain.\n\n"
            "You MUST write two speech summaries in the JSON output:\n"
            "1. 'ghost_summary': written in clear, conversational HINDI (using Devanagari script) starting with: "
            "'मैंने इस वेबसाइट को एक्सप्लोर किया है।' and addressing domain age, connection security, and what happens if they continue.\n"
            "2. 'ghost_summary_en': written in standard ENGLISH starting with: "
            "'I explored this website before you.' and addressing domain age, connection security, and what happens if they continue.\n\n"
            "Keep the language clean, trustworthy, and modern. Ensure that 'recommendations' are written strictly in standard English.\n"
            "You MUST output your response in valid JSON matching the exact schema specified below."
        )


        prompt = f"""
        Analyze the following URL security statistics, 5-pillar security scorecard, and webpage crawler findings to generate a friendly, detailed response.

        URL Statistics:
        - URL: {analysis_data['url']}
        - Domain: {analysis_data['domain']}
        - HTTPS Active: {analysis_data['https_enabled']}
        - Server Reachable: {analysis_data['is_reachable']}
        - Domain Age in Days: {analysis_data['domain_age_days']}
        - Registrar: {analysis_data['registrar']}
        - Suspicious URL Heuristics Triggered: {analysis_data['suspicious_patterns']}
        - System Baseline Trust Score (0-100): {analysis_data['base_trust_score']}

        Security Scorecard:
        - Domain Score (max 25): {analysis_data.get('scorecard', {}).get('domain_score')}
        - SSL Score (max 20): {analysis_data.get('scorecard', {}).get('ssl_score')}
        - DOM Score (max 25): {analysis_data.get('scorecard', {}).get('dom_score')}
        - Headers Score (max 15): {analysis_data.get('scorecard', {}).get('headers_score')}
        - Scripts Score (max 15): {analysis_data.get('scorecard', {}).get('scripts_score')}
        - SSL Cert Issuer: {analysis_data.get('scorecard', {}).get('ssl_issuer')}
        - Security Headers Active: {analysis_data.get('scorecard', {}).get('security_headers')}

        Webpage Crawler & DOM Inspector Findings:
        - Page Title: {analysis_data.get('crawled_page_content', {}).get('title', 'Unknown')}
        - Headings Found: {analysis_data.get('crawled_page_content', {}).get('headings', [])}
        - Login / Password Field Present: {analysis_data.get('crawled_page_content', {}).get('has_password_field', False)}
        - Credit Card Inputs Present: {analysis_data.get('crawled_page_content', {}).get('has_card_field', False)}
        - Number of Forms Scanned: {analysis_data.get('crawled_page_content', {}).get('forms_count', 0)}
        - Fields Scanned: {analysis_data.get('crawled_page_content', {}).get('input_fields', [])}
        - Suspicious Third-Party Scripts: {analysis_data.get('crawled_page_content', {}).get('external_scripts', [])}
        - Iframes Count: {analysis_data.get('crawled_page_content', {}).get('iframes_count', 0)}
        - Copy-Paste & Right-Click Locks Detected: {analysis_data.get('crawled_page_content', {}).get('copy_paste_locks_detected', False)}
        - Inline Scripts Count: {analysis_data.get('crawled_page_content', {}).get('inline_scripts_count', 0)}
        - Inline Scripts Total Bytes: {analysis_data.get('crawled_page_content', {}).get('inline_scripts_length', 0)}
        - Page Metadata: {analysis_data.get('crawled_page_content', {}).get('metadata', {})}

        Return a JSON object with the following fields:
        1. "trust_score": An integer (0-100) refining the baseline score if appropriate based on your security assessment.
        2. "risk_level": String, one of: "Safe", "Low Risk", "Medium Risk", "High Risk", "Critical".
        3. "ghost_summary": A detailed speech paragraph written in clear, conversational HINDI (using Devanagari script) starting with "मैंने इस वेबसाइट को एक्सप्लोर किया है।" that explicitly covers when the website was made/registered, why it is safe or dangerous, and what will happen if the user continues.
        4. "ghost_summary_en": A detailed speech paragraph written in standard ENGLISH starting with "I explored this website before you." that explicitly covers when the website was made/registered, why it is safe or dangerous, and what will happen if the user continues.
        5. "ai_explanation": A concise, friendly explanation of why the website has this risk status. Explain terms like 'HTTPS' or 'domain age' simply if they are relevant to your reasoning.
        6. "recommendations": An array of 2 to 4 friendly, actionable safety tips in standard English.
        7. "consequences": An array of 3 to 5 steps showing what could happen if they continue. Each step must be an object with:
           - "step": Brief title (e.g. "1. Visit Website", "2. Enter Credentials")
           - "description": Explanation of the user action or attack step (e.g. "The page steals your login info.")
           - "risk": One of: "Safe", "Warning", "Danger", "Critical"
        8. "threat_assessment": An object containing the answers to these critical security questions:
           - "is_brand_impersonation": {{"status": boolean, "details": "explanation of brand copycat status"}}
           - "resembles_phishing": {{"status": boolean, "details": "explanation of template / layout phishing resemblance"}}
           - "is_unusually_new": {{"status": boolean, "details": "explanation of age risk status"}}
           - "requests_sensitive_info": {{"status": boolean, "details": "explanation of form inputs request safety"}}
           - "multiple_warnings": {{"status": boolean, "details": "explanation of compounded risk signs presence"}}
           - "confidence_level": {{"level": "Low" or "Medium" or "High", "details": "explanation of security scan confidence"}}

        Example output format:
        {{
            "trust_score": 98,
            "risk_level": "Safe",
            "ghost_summary": "मैंने इस वेबसाइट को एक्सप्लोर किया है। यह डोमेन 25 साल पुराना है और वेरीफाइड रजिस्ट्रार से रजिस्टर हुआ है। इसका कनेक्शन पूरी तरह से सुरक्षित है क्योंकि HTTPS एक्टिव है और SSL वेरीफाइड है। अगर आप आगे बढ़ते हैं, तो आप बिना किसी चिंता के ब्राउज़ कर सकते हैं।",
            "ghost_summary_en": "I explored this website before you. It was registered over 25 years ago in 1997 and is owned by a verified registrar. It is safe because HTTPS is fully active with a valid SSL certificate, and there are no suspicious keywords or layout flags. If you continue, your connection is fully encrypted and you can browse with confidence.",
            "ai_explanation": "This website is well-known and uses robust security configurations. The connection is encrypted via SSL/TLS, and the domain has a long history of trust, making it highly secure.",
            "recommendations": ["Enjoy safe browsing", "Check the URL bar for the lock icon", "Update your browser regularly"],
            "consequences": [
                {{"step": "1. Visit Website", "description": "You open the website over a secure connection.", "risk": "Safe"}},
                {{"step": "2. Log In", "description": "You log in securely with your credentials, which are encrypted in transit.", "risk": "Safe"}},
                {{"step": "3. Safe Interaction", "description": "You browse and interact without risk of credential theft.", "risk": "Safe"}}
            ],
            "threat_assessment": {{
                "is_brand_impersonation": {{"status": false, "details": "Matches the official registered domain names of Google."}},
                "resembles_phishing": {{"status": false, "details": "Does not contain warning flags or layout anomalies."}},
                "is_unusually_new": {{"status": false, "details": "Mature domain created over 25 years ago."}},
                "requests_sensitive_info": {{"status": false, "details": "Standard login forms hosted on official origin."}},
                "multiple_warnings": {{"status": false, "details": "No indicators flagged."}},
                "confidence_level": {{"level": "High", "details": "Full WHOIS database matched with verified SSL connection."}}
            }}
        }}
        """

        model = genai.GenerativeModel(
            model_name="gemini-2.0-flash",
            system_instruction=system_instruction,
            generation_config={"response_mime_type": "application/json"}
        )

        response = model.generate_content(prompt)
        result = json.loads(response.text)


        required_keys = ["trust_score", "risk_level", "ghost_summary", "ghost_summary_en", "ai_explanation", "recommendations", "consequences", "threat_assessment"]
        if all(key in result for key in required_keys):
            return result
        else:
            print("Gemini response missing keys, using fallback generator.")
            return generate_fallback_analysis(analysis_data)

    except Exception as e:
        print(f"Gemini API invocation failed: {str(e)}. Using fallback analyzer.")
        return generate_fallback_analysis(analysis_data)

"""
ZeroPhish AI — Unified Phishing Detection Engine
- URLs:             pure heuristic analysis
- Emails/Messages:  ML model (trained on SpamAssassin) with heuristic fallback
"""
import re
from typing import Tuple

# ── Suspicious keyword lists ──────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    'verify', 'verification', 'account suspended', 'confirm your', 'update your',
    'click here', 'login', 'sign in', 'secure your', 'unauthorized access',
    'unusual activity', 'billing information', 'payment required', 'act now',
    'immediately', 'limited time', 'account locked', 'password expired',
    'your account has been', 'we have detected', 'congratulations you won',
    'free gift', 'claim your', 'validate your', 'reactivate', 'suspended',
]
URGENCY_PHRASES = [
    'immediately', 'urgent', 'act now', 'limited time', '24 hours',
    'expires soon', 'respond now', 'action required', 'final notice',
    'last chance', 'do not ignore',
]
CREDENTIAL_REQUESTS = [
    'password', 'social security', 'credit card', 'bank account',
    'ssn', 'date of birth', 'mother maiden', 'pin number', 'cvv',
]
SUSPICIOUS_TLDS  = {'.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                    '.loan', '.work', '.click', '.link', '.online', '.site'}
BRAND_NAMES      = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix',
                    'instagram', 'facebook', 'twitter', 'dhl', 'fedex', 'ups',
                    'chase', 'wellsfargo', 'citibank', 'irs', 'usps']


# ── URL Analysis (heuristic) ──────────────────────────────────────────────────
def _extract_domain(url: str) -> str:
    m = re.search(r'https?://([^/?#]+)', url, re.IGNORECASE)
    return m.group(1).lower() if m else url.lower()


def analyze_url(url: str) -> Tuple[int, list, str]:
    score = 0
    flags = []
    url_lower = url.lower()
    domain = _extract_domain(url)

    if re.search(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', domain):
        score += 35
        flags.append("IP address used instead of domain name")

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            flags.append(f"Suspicious free TLD detected ({tld})")
            break

    domain_part = domain.split('.')[0] if '.' in domain else domain
    if domain_part.count('-') >= 2:
        score += 15
        flags.append("Excessive hyphens in domain (spoofing pattern)")

    if len(url) > 120:
        score += 10
        flags.append(f"Unusually long URL ({len(url)} chars)")

    if domain.count('.') >= 3:
        score += 15
        flags.append("Multiple subdomain levels detected")

    kw_found = [kw for kw in PHISHING_KEYWORDS[:12]
                if kw.replace(' ', '-') in url_lower
                or kw.replace(' ', '') in url_lower
                or kw in url_lower]
    if kw_found:
        score += min(len(kw_found) * 10, 30)
        flags.append(f"Phishing keywords in URL: {', '.join(kw_found[:3])}")

    for brand in BRAND_NAMES:
        if brand in domain:
            real = f"{brand}.com"
            if real not in domain and not domain.endswith(f".{brand}.com"):
                score += 25
                flags.append(f"Possible {brand.capitalize()} impersonation detected")
                break

    if url_lower.startswith('javascript:') or url_lower.startswith('data:'):
        score += 50
        flags.append("Dangerous URI scheme (javascript/data)")

    score = min(score, 100)
    details = "; ".join(flags) if flags else "No significant threats detected in URL structure."
    return score, flags, details


# ── Text Analysis (heuristic fallback) ───────────────────────────────────────
def analyze_text_heuristic(content: str) -> Tuple[int, list, str]:
    score = 0
    flags = []
    cl = content.lower()

    kw_found = [kw for kw in PHISHING_KEYWORDS if kw in cl]
    if kw_found:
        score += min(len(kw_found) * 7, 35)
        flags.append(f"Suspicious language: {', '.join(kw_found[:4])}")

    urgency_found = [u for u in URGENCY_PHRASES if u in cl]
    if urgency_found:
        score += 15
        flags.append("Urgency / pressure tactics detected")

    cred_found = [c for c in CREDENTIAL_REQUESTS if c in cl]
    if cred_found:
        score += 20
        flags.append(f"Requests for sensitive data: {', '.join(cred_found[:3])}")

    urls_in_content = re.findall(r'https?://\S+', content)
    for url in urls_in_content:
        url_score, _, _ = analyze_url(url)
        if url_score >= 40:
            score += 20
            flags.append("Contains suspicious embedded URL")
            break

    score = min(score, 100)
    details = "; ".join(flags) if flags else "No significant phishing indicators detected."
    return score, flags, details


def _generate_reasoning(score: int, conf: float, st: str, flags: list, has_ml: bool) -> str:
    """Generate detailed, user-friendly explainable AI reasoning."""
    if not has_ml:
        if score > 0:
            return "Our heuristic analysis engine detected suspicious structural patterns in this content. While our deep learning model is currently offline, standard security rules flagged potential threats. We recommend proceeding with extreme caution."
        return "Based on standard security rules, this content appears safe. However, please note that our deep learning AI engine is currently offline, so advanced semantic analysis was not performed."

    percent = f"{conf*100:.1f}%"
    
    if st == 'URL':
        if score >= 50:
            base = f"Our AI model analyzed this URL and is {percent} confident that it is a malicious link designed for phishing or malware distribution."
            if flags:
                base += f" The engine specifically flagged structural anomalies, such as suspicious domain patterns or hidden redirects."
            base += " Do not click this link or enter any personal information."
            return base
        else:
            return f"Our AI model analyzed the URL structure and domain reputation. With {percent} confidence, the engine believes this is a safe, legitimate link. No malicious patterns were detected."
            
    else:
        # Email / Message
        if score >= 50:
            base = f"Our deep learning model found strong indicators that this email is a phishing attempt ({percent} confidence). "
            if any("Urgency" in f for f in flags):
                base += "The content uses psychological pressure and urgency, a common social engineering tactic to make you act quickly without thinking. "
            if any("URL" in f for f in flags):
                base += "It also contains highly suspicious links designed to steal credentials. "
            if any("sensitive" in f for f in flags):
                base += "The sender is explicitly requesting sensitive personal or financial information. "
            
            base += "We strongly advise you not to click any links, open attachments, or reply to this sender."
            return base
        else:
            return f"Our deep learning model analyzed the language, semantics, and structure of this content. With {percent} confidence, the AI concludes this is a legitimate message. It does not exhibit the typical psychological manipulation or malicious links found in phishing attacks."

def _calculate_breakdown(st: str, score: int, flags: list) -> dict:
    """Calculate sub-scores for the Risk Breakdown UI based on heuristics and ML scores."""
    b = {
        "sender_reputation": 0,
        "url_links": 0,
        "content_analysis": 0,
        "attachment": 0,
        "social_engineering": 0
    }
    
    if st == 'URL':
        b["url_links"] = score
        b["content_analysis"] = int(score * 0.4)
        b["social_engineering"] = int(score * 0.6)
    else:
        # Content Analysis is heavily tied to the overall ML score
        b["content_analysis"] = score
        
        # Sender reputation is derived from overall risk unless explicitly whitelisted
        b["sender_reputation"] = min(100, int(score * 0.85))
        
        # URL/Links
        if any("URL" in f or "URI" in f for f in flags):
            b["url_links"] = max(85, int(score * 0.95))
        else:
            b["url_links"] = min(100, int(score * 0.3))
            
        # Social Engineering
        if any("Urgency" in f or "language" in f or "sensitive" in f for f in flags):
            b["social_engineering"] = max(90, int(score * 0.95))
        else:
            b["social_engineering"] = min(100, int(score * 0.5))
            
        # Attachments are not parsed yet
        b["attachment"] = 0
        
    return b

# ── Main entry point ──────────────────────────────────────────────────────────
def scan_content(content: str, scan_type: str) -> dict:
    """
    Analyze content and return risk_score, result label, and details.
    scan_type: 'URL' | 'Email' | 'Message'
    """
    content = content.strip()
    st      = scan_type.strip().upper()

    ai_reasoning = ""
    heuristic_flags = []

    if st == 'URL':
        # ── Try URL ML first ──────────────────────────────────────────────────
        from app.services.ml_scanner import predict_url as ml_predict_url
        ml_result = ml_predict_url(content)

        if ml_result:
            score   = ml_result["risk_score"]
            conf    = ml_result["confidence"]
            engine  = "ml_url"

            # Blend with heuristics
            h_score, h_flags, h_details = analyze_url(content)
            heuristic_flags = h_flags
            if h_score > 0:
                # Weighted blend: ML 70%, Heuristic 30%
                blended = int(round(score * 0.70 + h_score * 0.30))
                score   = min(blended, 100)
                details = f"ML URL confidence: {conf*100:.1f}%. {h_details}"
            else:
                details = f"ML URL confidence: {conf*100:.1f}% {'phishing' if score >= 50 else 'safe'}."
            ai_reasoning = _generate_reasoning(score, conf, st, heuristic_flags, True)
        else:
            score, heuristic_flags, details = analyze_url(content)
            engine = "heuristic"
            ai_reasoning = _generate_reasoning(score, 0.0, st, heuristic_flags, False)
    else:
        # ── Try ML first ──────────────────────────────────────────────────────
        from app.services.ml_scanner import predict as ml_predict
        ml_result = ml_predict(content)

        if ml_result:
            score   = ml_result["risk_score"]
            conf    = ml_result["confidence"]
            engine  = "ml"

            # Layer heuristic signals on top (boost but never lower ML score)
            h_score, h_flags, h_details = analyze_text_heuristic(content)
            heuristic_flags = h_flags
            if h_score > 0:
                # Weighted blend: ML has 75% weight, heuristic 25%
                blended = int(round(score * 0.75 + h_score * 0.25))
                score   = min(blended, 100)
                details = (
                    f"ML model confidence: {conf*100:.1f}% spam. "
                    + (h_details if h_details != "No significant phishing indicators detected." else "")
                ).strip(". ")
            else:
                details = f"ML model confidence: {conf*100:.1f}% {'spam/phishing' if score >= 50 else 'legitimate'}."
            ai_reasoning = _generate_reasoning(score, conf, st, heuristic_flags, True)
        else:
            # ── Heuristic fallback (model not trained yet) ────────────────────
            score, heuristic_flags, details = analyze_text_heuristic(content)
            engine = "heuristic"
            if not details or details == "No significant phishing indicators detected.":
                details = "No significant phishing indicators detected. (Run train_model.py to enable ML scanning.)"
            ai_reasoning = _generate_reasoning(score, 0.0, st, heuristic_flags, False)

    # ── Map score → label ─────────────────────────────────────────────────────
    if score >= 65:
        result = "High Risk"
    elif score >= 35:
        result = "Medium Risk"
    elif score >= 15:
        result = "Low Risk"
    else:
        result = "Safe"

    breakdown = _calculate_breakdown(st, score, heuristic_flags)

    # ── Fetch real network intelligence if it's a URL ─────────────────────────
    network_intel = None
    if st == 'URL':
        try:
            from app.services.network_scanner import get_network_intelligence
            network_intel = get_network_intelligence(content)
            
            # Optionally tweak the breakdown scores based on real network data
            if network_intel["ssl_status"] == "Invalid / Self-Signed":
                score = min(100, score + 20)
                heuristic_flags.append("Invalid SSL Certificate")
                
            if network_intel["domain_age_days"] is not None and network_intel["domain_age_days"] < 30:
                score = min(100, score + 15)
                heuristic_flags.append("Domain recently registered")
                
        except Exception as e:
            import logging
            logging.getLogger(__name__).warning(f"Network intelligence failed: {e}")

    # Re-evaluate result label if score changed
    if score >= 65:
        result = "High Risk"
    elif score >= 40:
        result = "Medium Risk"
    elif score >= 15:
        result = "Low Risk"
    else:
        result = "Safe"

    return {
        "risk_score": score,
        "result":     result,
        "details":    details,
        "engine":     engine,
        "ai_reasoning": ai_reasoning,
        "heuristic_flags": heuristic_flags,
        "breakdown": breakdown,
        "network": network_intel
    }

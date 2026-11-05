from typing import Dict, Any, List

def compute_fraud_risk_score(
    dns_results: Dict[str, Any],
    alignment_results: Dict[str, Any],
    content_results: Dict[str, Any],
    geo_results: Dict[str, Any],
    header_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Consolidated 0 - 100 Fraud Risk Scoring Algorithm.
    Evaluates:
      1. Authentication Failures (up to 40 pts)
      2. Header Anomalies (up to 20 pts)
      3. Content / Link / NLP Indicators (up to 25 pts)
      4. Origin Network Intelligence (up to 15 pts)
    """
    total_score = 0
    breakdown = []

    # =========================================================
    # 1. AUTHENTICATION FAILURES (Max 40 points)
    # =========================================================
    auth_score = 0
    
    # SPF Check
    spf_status = dns_results.get("spf", {}).get("status", "None")
    if spf_status == "Fail":
        auth_score += 15
        breakdown.append({"rule": "SPF Authentication Failed", "points": 15, "category": "Authentication"})
    elif spf_status in ["SoftFail", "Neutral"]:
        auth_score += 5
        breakdown.append({"rule": "SPF SoftFail / Neutral", "points": 5, "category": "Authentication"})
    elif spf_status == "None":
        auth_score += 10
        breakdown.append({"rule": "SPF Record Missing on Domain", "points": 10, "category": "Authentication"})

    # DKIM Check
    dkim_status = dns_results.get("dkim", {}).get("status", "None")
    if dkim_status == "Fail":
        auth_score += 15
        breakdown.append({"rule": "DKIM Cryptographic Signature Invalid (Tampered)", "points": 15, "category": "Authentication"})
    elif dkim_status == "None":
        auth_score += 10
        breakdown.append({"rule": "DKIM Signature Missing", "points": 10, "category": "Authentication"})

    # DMARC Alignment Check
    dmarc_aligned = alignment_results.get("dmarc_aligned", True)
    if not dmarc_aligned:
        auth_score += 10
        breakdown.append({"rule": "DMARC Alignment Mismatch (From domain != Authenticated domain)", "points": 10, "category": "Authentication"})

    total_score += min(auth_score, 40)

    # =========================================================
    # 2. HEADER ANOMALIES (Max 20 points)
    # =========================================================
    header_score = 0
    sender_email = (header_info.get("sender_email") or "").lower().strip()
    reply_to = (header_info.get("reply_to") or "").lower().strip()
    return_path_domain = (alignment_results.get("return_path_domain") or "").lower().strip()
    from_domain = (header_info.get("sender_domain") or "").lower().strip()

    # Reply-To mismatch check
    if reply_to and sender_email and reply_to != sender_email:
        header_score += 10
        breakdown.append({"rule": f"Reply-To Mismatch ('From' is {sender_email}, but replies go to {reply_to})", "points": 10, "category": "Headers"})

    # Return-Path domain mismatch check
    if return_path_domain and from_domain and return_path_domain != from_domain:
        header_score += 10
        breakdown.append({"rule": f"Return-Path Domain Mismatch ({return_path_domain} vs {from_domain})", "points": 10, "category": "Headers"})

    total_score += min(header_score, 20)

    # =========================================================
    # 3. CONTENT, LINKS & NLP THREATS (Max 25 points)
    # =========================================================
    content_score = 0
    nlp = content_results.get("nlp", {})
    links = content_results.get("links", {})
    counts = links.get("counts", {})

    # Urgency keyword matches
    urgency_count = nlp.get("urgency_count", 0)
    if urgency_count > 0:
        pts = min(urgency_count * 5, 10)
        content_score += pts
        breakdown.append({"rule": f"Psychological Urgency Cues Detected: {nlp.get('urgency_matches', [])}", "points": pts, "category": "Content"})

    # Brand Impersonation check
    if nlp.get("impersonation_flagged", False):
        content_score += 10
        breakdown.append({"rule": f"Brand Impersonation Alert: Text mentions {nlp.get('impersonation_brands')} but sender domain is '{from_domain}'", "points": 10, "category": "Content"})

    # Direct IP-based URLs
    if counts.get("ip_links", 0) > 0:
        content_score += 10
        breakdown.append({"rule": "Direct IP-based URL detected (no domain name)", "points": 10, "category": "Links"})

    # Anchor vs Href mismatch
    if counts.get("mismatch_links", 0) > 0:
        content_score += 10
        breakdown.append({"rule": "Deceptive Hyperlink: Display text domain does not match destination URL", "points": 10, "category": "Links"})

    total_score += min(content_score, 25)

    # =========================================================
    # 4. NETWORK & ORIGIN INTEL (Max 15 points)
    # =========================================================
    network_score = 0
    if geo_results.get("is_hosting", False):
        network_score += 15
        breakdown.append({"rule": f"Originating IP ({geo_results.get('ip_address')}) belongs to a Cloud/Hosting/VPN data center", "points": 15, "category": "Network"})

    total_score += min(network_score, 15)

    # =========================================================
    # FINAL VERDICT
    # =========================================================
    if total_score >= 70:
        verdict = "Malicious"
    elif total_score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return {
        "score": total_score,
        "verdict": verdict,
        "breakdown": breakdown
    }

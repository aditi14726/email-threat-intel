import json
from backend.app.parser import extract_basic_info, parse_received_headers, get_earliest_reliable_ip
from backend.app.dns_auth import verify_spf, verify_dkim, verify_dmarc, verify_alignment
from backend.app.geoip import get_ip_geolocation
from backend.app.classifier import analyze_body_content
from backend.app.scoring import compute_fraud_risk_score

# Complete realistic Phishing Email simulation
PHISHING_EMAIL_SAMPLE = """From: PayPal Security Team <security-alert@pay-pal-security.com>
To: victim.account@gmail.com
Subject: URGENT: Your PayPal account has been restricted!
Date: Wed, 04 Nov 2026 12:00:00 +0000
Message-ID: <threat-campaign-9912@pay-pal-security.com>
Reply-To: recovery-helpdesk@gmail.com
Return-Path: <bounce@attacker-relay.net>
Received: from mx.google.com (mail-in.google.com [142.250.102.27])
	by mail-storage.internal with ESMTPS id g14-v6si2341235
	for <victim.account@gmail.com>; Wed, 04 Nov 2026 12:00:04 +0000
Received: from node-relay.hosting-servers.org (node-relay.hosting-servers.org [198.51.100.2])
	by mx.google.com with ESMTPS id A23F1404B;
	Wed, 04 Nov 2026 12:00:02 +0000
Received: from local-machine (unknown [192.168.1.50])
	by node-relay.hosting-servers.org (Postfix) with ESMTP id 98C3F204D2
	from [185.220.101.5]; Wed, 04 Nov 2026 12:00:01 +0000
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<h2>PayPal Account Security Alert</h2>
<p>Dear Customer,</p>
<p>We detected unauthorized activity on your PayPal account. As a result, your account access has been restricted.</p>
<p><strong>Action required immediately:</strong> You must verify your account within 24 hours to prevent permanent suspension.</p>
<p>Please click below to complete the security verification:</p>
<p><a href="http://185.220.101.5/paypal/login">https://www.paypal.com/security/login</a></p>
<p>Thank you,<br>PayPal Support</p>
</body>
</html>
"""

def main():
    print("=" * 70)
    print("🚀 RUNNING FULL END-TO-END FORENSIC PIPELINE")
    print("=" * 70)

    raw_bytes = PHISHING_EMAIL_SAMPLE.encode('utf-8')

    # [1] Header Extraction
    print("\n[Step 1] Extracting Headers & Domains...")
    header_info = extract_basic_info(PHISHING_EMAIL_SAMPLE)
    print(f"    From         : {header_info['from']}")
    print(f"    Sender Domain: {header_info['sender_domain']}")
    print(f"    Reply-To     : {header_info['reply_to']}")

    # [2] Origin IP Tracing
    print("\n[Step 2] Tracing Received Hop Chain...")
    hops = parse_received_headers(PHISHING_EMAIL_SAMPLE)
    origin_ip = get_earliest_reliable_ip(hops)
    print(f"    Total Hops Found : {len(hops)}")
    print(f"    Origin Public IP : {origin_ip}")

    # [3] IP Geolocation & Threat Intel
    print("\n[Step 3] Resolving Origin IP Geolocation...")
    geo_results = get_ip_geolocation(origin_ip)
    print(f"    Origin Location  : {geo_results['city']}, {geo_results['country']}")
    print(f"    Coordinates      : {geo_results['latitude']}, {geo_results['longitude']}")
    print(f"    Network / ASN    : {geo_results['org']}")

    # [4] DNS & Authentication Verification
    print("\n[Step 4] Checking DNS Authentication (SPF, DKIM, DMARC)...")
    spf_res = verify_spf(header_info['sender_domain'], origin_ip)
    dkim_res = verify_dkim(raw_bytes)
    dmarc_res = verify_dmarc(header_info['sender_domain'])
    alignment_res = verify_alignment(header_info['sender_domain'], header_info['return_path'], raw_bytes)
    
    dns_results = {
        "spf": spf_res,
        "dkim": dkim_res,
        "dmarc": dmarc_res
    }
    print(f"    SPF Status   : {spf_res['status']}")
    print(f"    DKIM Status  : {dkim_res['status']}")
    print(f"    DMARC Policy : {dmarc_res['policy']}")
    print(f"    Alignment    : {'ALIGNED' if alignment_res['dmarc_aligned'] else 'MISMATCH'}")

    # [5] Content, Urgency & Link Analysis
    print("\n[Step 5] Scanning Email Body & Hyperlinks...")
    content_results = analyze_body_content(PHISHING_EMAIL_SAMPLE, header_info['sender_domain'])
    print(f"    Urgency Words Found  : {content_results['nlp']['urgency_matches']}")
    print(f"    Brand Impersonation  : {content_results['nlp']['impersonation_flagged']} ({content_results['nlp']['impersonation_brands']})")
    print(f"    Suspicious Links     : {content_results['links']['counts']['total']} link(s) found")

    # [6] Compute Consolidated Fraud Risk Score
    print("\n" + "=" * 70)
    print("📊 COMPUTING FINAL FRAUD RISK SCORE")
    print("=" * 70)
    final_assessment = compute_fraud_risk_score(
        dns_results=dns_results,
        alignment_results=alignment_res,
        content_results=content_results,
        geo_results=geo_results,
        header_info=header_info
    )

    verdict_emoji = "🚨" if final_assessment['verdict'] == "Malicious" else "⚠️"
    print(f"\n{verdict_emoji} OVERALL VERDICT: {final_assessment['verdict'].upper()}")
    print(f"🎯 FRAUD RISK SCORE: {final_assessment['score']} / 100\n")
    print("📌 FIRED THREAT SIGNALS (Why it was flagged):")
    for item in final_assessment['breakdown']:
        print(f"   [+{item['points']} pts] [{item['category']}] {item['rule']}")

    print("\n" + "=" * 70)
    print("✅ Full Pipeline Executed Successfully!")
    print("=" * 70)

if __name__ == "__main__":
    main()

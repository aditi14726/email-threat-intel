from backend.app.dns_auth import verify_spf, verify_dmarc, verify_alignment, resolve_txt_records

def main():
    print("=" * 65)
    print("🛡️ TESTING MODULE 1: DNS AUTHENTICATION CHECKS (SPF & DMARC)")
    print("=" * 65)

    test_domain = "paypal.com"
    attacker_ip = "185.220.101.5"
    
    # 1. Real DNS query for SPF
    print(f"\n[1] Querying real-world SPF record for: {test_domain}...")
    spf_result = verify_spf(domain=test_domain, sender_ip=attacker_ip)
    print(f"    Status : {spf_result['status']}")
    print(f"    Detail : {spf_result['detail']}")
    print(f"    Record : {spf_result['record']}\n")

    # 2. Real DNS query for DMARC policy
    print(f"[2] Querying real-world DMARC policy for: {test_domain}...")
    dmarc_result = verify_dmarc(domain=test_domain)
    print(f"    Status : {dmarc_result['status']}")
    print(f"    Policy : {dmarc_result['policy'].upper()} (p={dmarc_result['policy']})")
    print(f"    Detail : {dmarc_result['detail']}")
    print(f"    Record : {dmarc_result['record']}\n")

    # 3. Testing Alignment Mismatch (Phishing Simulation)
    print("[3] Testing DMARC Alignment (Phishing Simulation):")
    print("    Visual 'From' Domain       : paypal.com")
    print("    Technical 'Return-Path'    : attacker-servers.net")
    
    alignment = verify_alignment(
        from_domain="paypal.com",
        return_path="bounce@attacker-servers.net",
        raw_eml_bytes=b"From: paypal.com\r\nSubject: Test\r\n\r\nHello"
    )
    
    print(f"    SPF Aligned   : {alignment['spf_aligned']}")
    print(f"    DKIM Aligned  : {alignment['dkim_aligned']}")
    print(f"    DMARC Aligned : {alignment['dmarc_aligned']}")
    
    if not alignment['dmarc_aligned']:
        print("\n🚨 CRITICAL FORENSIC FINDING:")
        print("   Domain alignment FAILED!")
        print("   Attacker is spoofing 'paypal.com', but bounce path belongs to 'attacker-servers.net'.")
        print("   Because PayPal's DMARC policy is 'REJECT', this email would be immediately blocked!")

if __name__ == "__main__":
    main()

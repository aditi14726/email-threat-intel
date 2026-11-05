import json
from backend.app.parser import extract_basic_info, parse_received_headers, get_earliest_reliable_ip

# Realistic raw email with a 3-hop Received chain
SAMPLE_EMAIL = """From: PayPal Security Team <security-alert@paypal.com>
To: victim.user@example.com
Subject: URGENT: Unusual login activity detected!
Date: Mon, 07 Sep 2026 10:30:00 +0000
Message-ID: <unique-msg-id-12345@paypal.com>
Reply-To: support-recovery@gmail.com
Return-Path: <bounce-handler@paypal.com>
Received: from mx.google.com (mail-in.google.com [142.250.102.27])
	by mail-storage.internal with ESMTPS id g14-v6si2341235
	for <victim.user@example.com>; Mon, 07 Sep 2026 10:30:04 +0000
Received: from relay-node.hosting-cloud.net (relay-node.hosting-cloud.net [198.51.100.2])
	by mx.google.com with ESMTPS id A23F1404B;
	Mon, 07 Sep 2026 10:30:02 +0000
Received: from attacker-laptop (unknown [192.168.1.50])
	by relay-node.hosting-cloud.net (Postfix) with ESMTP id 98C3F204D2
	from [185.220.101.5]; Mon, 07 Sep 2026 10:30:01 +0000

Dear Customer,
We detected an unauthorized sign-in to your account.
Please verify your identity immediately: http://185.220.101.5/login
"""

def main():
    print("=" * 65)
    print("🔍 1. TESTING BASIC HEADER PARSER")
    print("=" * 65)
    basic_info = extract_basic_info(SAMPLE_EMAIL)
    print(f"Sender (From)    : {basic_info['from']}")
    print(f"Sender Domain    : {basic_info['sender_domain']}")
    print(f"Reply-To Address : {basic_info['reply_to']}")
    
    if basic_info['sender_email'] != basic_info['reply_to']:
        print("⚠️ ANOMALY: From vs Reply-To domain mismatch!")

    print("\n" + "=" * 65)
    print("🌐 2. TESTING ORIGIN TRACEABILITY (RECEIVED HOPS)")
    print("=" * 65)
    
    hops = parse_received_headers(SAMPLE_EMAIL)
    print(f"Total Hops Detected: {len(hops)}\n")
    
    for hop in hops:
        print(f"📍 Hop {hop['hop']}:")
        print(f"   Public IPs  : {hop['public_ips'] if hop['public_ips'] else 'None'}")
        print(f"   Private IPs : {hop['private_ips'] if hop['private_ips'] else 'None'} (filtered out)")
        print(f"   Raw snippet : {hop['raw'][:80]}...\n")

    origin_ip = get_earliest_reliable_ip(hops)
    print("=" * 65)
    print(f"🎯 EARLIEST RELIABLE SENDER PUBLIC IP: {origin_ip}")
    print("=" * 65)
    print("ℹ️ Note: 192.168.1.50 was safely ignored because it is a private LAN IP.")
    print("   The actual public server where this email entered the internet is: " + str(origin_ip))

if __name__ == "__main__":
    main()


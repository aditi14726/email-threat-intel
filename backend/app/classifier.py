import re
from email.parser import Parser
from typing import Dict, Any, List

# Phishing emails me use hone wale common urgency aur panic patterns
URGENCY_KEYWORDS = [
    r"\baction\s+required\b",
    r"\bimmediate(ly)?\b",
    r"\bverify\s+your\s+account\b",
    r"\bsuspend(ed)?\s+(your\s+)?account\b",
    r"\bsecurity\s+alert\b",
    r"\blogin\s+to\s+verify\b",
    r"\baccount\s+restricted\b",
    r"\bterminate\s+access\b",
    r"\burgent\b",
    r"\bwithin\s+24\s+hours\b",
    r"\bunauthorized\s+activity\b"
]

# Common brands jinko attackers sabse zyada target karte hain
COMMON_BRANDS = [
    "paypal", "netflix", "microsoft", "google", "amazon", "apple", "chase", 
    "bankofamerica", "wellsfargo", "facebook", "instagram", "linkedin", "dhl", "fedex"
]

def extract_email_body(raw_email_content: str) -> Dict[str, str]:
    """
    Email text aur HTML body ko separate nikalta hai.
    """
    parser = Parser()
    msg = parser.parsestr(raw_email_content)
    
    body_text = ""
    body_html = ""
    
    if msg.is_multipart():
        # Agar email multipart hai (images, html, text sab mixed)
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            
            # Attachments ko skip karo
            if "attachment" in content_disposition:
                continue
                
            if content_type == "text/plain":
                try:
                    body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except Exception:
                    pass
            elif content_type == "text/html":
                try:
                    body_html += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except Exception:
                    pass
    else:
        # Simple plain single-part email
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            decoded = payload.decode('utf-8', errors='ignore')
            if content_type == "text/html":
                body_html = decoded
            else:
                body_text = decoded
        else:
            # Fallback agar payload decode nahi hua
            body_text = str(msg.get_payload())
            
    # Agar sirf HTML mila toh simple plain text version bana lete hain
    if body_html and not body_text:
        body_text = strip_html_tags(body_html)
        
    return {
        "text": body_text,
        "html": body_html
    }

def strip_html_tags(html_content: str) -> str:
    """HTML tags (<p>, <a>, etc.) ko remove karke saaf text banata hai."""
    clean = re.sub(r'<[^>]+>', ' ', html_content)
    return re.sub(r'\s+', ' ', clean).strip()

def analyze_links(html_body: str, text_body: str) -> Dict[str, Any]:
    """
    Email ke andar ke saare links ko scan karta hai:
    1. Direct IP links (e.g. http://185.220.101.5/login)
    2. URL shorteners (bit.ly, tinyurl)
    3. Anchor mismatch (Display me paypal.com, par click pe attacker.com)
    """
    # HTML me se saare href links nikalo
    hrefs = re.findall(r'href=["\'](https?://[^"\']+)["\']', html_body, re.IGNORECASE)
    # Plain text me se raw URLs nikalo
    raw_urls = re.findall(r'(https?://[^\s>"\']+)', text_body, re.IGNORECASE)
    
    all_links = list(set(hrefs + raw_urls))
    
    suspicious_links = []
    ip_links_found = 0
    shortened_links_found = 0
    mismatch_links_found = 0
    
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "adf.ly"]
    
    for url in all_links:
        reasons = []
        
        # 1. Check if URL has direct IP instead of domain name
        host_match = re.search(r'https?://([^/:\s]+)', url)
        if host_match:
            host = host_match.group(1)
            # IPv4 address format match
            if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', host):
                ip_links_found += 1
                reasons.append("Direct IP-based URL (No Domain Name)")
                
        # 2. Check if URL shortener was used
        if any(shortener in url.lower() for shortener in shorteners):
            shortened_links_found += 1
            reasons.append("URL shortener used to hide destination")
            
        if reasons:
            suspicious_links.append({
                "url": url,
                "reasons": reasons
            })
            
    # 3. Anchor vs Href mismatch check:
    # <a href="http://evil.com">http://paypal.com</a>
    anchor_pattern = re.compile(r'<a\s+[^>]*href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE)
    for href, anchor_text in anchor_pattern.findall(html_body):
        clean_text = strip_html_tags(anchor_text).strip()
        # Agar anchor text me koi domain/URL dikh raha hai
        if "www." in clean_text or ".com" in clean_text or "http" in clean_text:
            anchor_domain = re.search(r'(?:https?://)?(?:www\.)?([^/:\s]+)', clean_text)
            href_domain = re.search(r'(?:https?://)?(?:www\.)?([^/:\s]+)', href)
            
            if anchor_domain and href_domain:
                a_dom = anchor_domain.group(1).lower()
                h_dom = href_domain.group(1).lower()
                
                # Agar visual domain aur actual link domain alag hain
                if a_dom != h_dom and not h_dom.endswith("." + a_dom) and not a_dom.endswith("." + h_dom):
                    mismatch_links_found += 1
                    suspicious_links.append({
                        "url": href,
                        "reasons": [f"Visual text shows '{a_dom}', but real link opens '{h_dom}'"]
                    })
                    
    return {
        "all_links": all_links,
        "suspicious_links": suspicious_links,
        "counts": {
            "total": len(all_links),
            "ip_links": ip_links_found,
            "shortened_links": shortened_links_found,
            "mismatch_links": mismatch_links_found
        }
    }

def analyze_nlp_signals(text_body: str, from_domain: str) -> Dict[str, Any]:
    """
    Body text me psychological cues dhoondta hai:
    - Urgency keywords
    - Brand impersonation (Text me PayPal likha hai par domain kuch aur hai)
    """
    text_lower = text_body.lower()
    
    # 1. Match Urgency keywords
    matched_urgency = []
    for pattern in URGENCY_KEYWORDS:
        if re.search(pattern, text_lower):
            clean_word = pattern.replace(r"\b", "").replace(r"\s+", " ").replace("(ly)?", "").replace("(your\\s+)?", "")
            matched_urgency.append(clean_word.strip())
            
    # 2. Check Brand Impersonation
    impersonation_flagged = False
    brands_found = []
    
    for brand in COMMON_BRANDS:
        if brand in text_lower:
            # Agar text me brand hai lekin sender domain me woh brand nahi hai
            if from_domain and brand not in from_domain.lower():
                brands_found.append(brand)
                impersonation_flagged = True
                
    return {
        "urgency_matches": matched_urgency,
        "urgency_count": len(matched_urgency),
        "impersonation_flagged": impersonation_flagged,
        "impersonation_brands": brands_found
    }

def analyze_body_content(raw_email_content: str, sender_domain: str) -> Dict[str, Any]:
    """
    Main function jo text nikal kar links aur urgency analyze karta hai.
    """
    bodies = extract_email_body(raw_email_content)
    links_data = analyze_links(bodies["html"], bodies["text"])
    nlp_data = analyze_nlp_signals(bodies["text"], sender_domain)
    
    return {
        "links": links_data,
        "nlp": nlp_data
    }

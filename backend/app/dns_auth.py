import dns.resolver
import dkim
import logging
import ipaddress
import re
from typing import Dict, Any, Optional, List
from .parser import extract_email_address

logger = logging.getLogger(__name__)

def resolve_txt_records(domain: str) -> List[str]:
    """
    Queries Public DNS for TXT records of the specified domain using dnspython.
    TXT records store SPF, DMARC, and domain verification strings.
    """
    if not domain:
        return []
    try:
        # Resolver queries public DNS (uses system configured DNS or fallback)
        answers = dns.resolver.resolve(domain, 'TXT')
        records = []
        for rdata in answers:
            # DNS TXT records can be split into multiple chunks; join them into a single string
            record_str = "".join([part.decode('utf-8') for part in rdata.strings])
            records.append(record_str)
        return records
    except Exception as e:
        logger.warning(f"DNS lookup failed for TXT records on {domain}: {e}")
        return []


def verify_spf(domain: str, sender_ip: Optional[str]) -> Dict[str, Any]:
    """
    Verifies SPF (Sender Policy Framework):
    1. Fetches TXT record starting with 'v=spf1' for the sender domain.
    2. Checks if the originating public IP is explicitly authorized.
    """
    records = resolve_txt_records(domain)
    spf_record = None
    for r in records:
        if r.startswith("v=spf1"):
            spf_record = r
            break

    # If no SPF record published by the domain owner
    if not spf_record:
        return {
            "status": "None",
            "record": None,
            "detail": f"No SPF record published by {domain}."
        }

    if not sender_ip:
        return {
            "status": "Neutral",
            "record": spf_record,
            "detail": "SPF record found, but no public originating IP was detected to test."
        }

    try:
        sender_ip_obj = ipaddress.ip_address(sender_ip)
    except ValueError:
        sender_ip_obj = None

    ip_found = False
    
    # Parse terms in SPF record: e.g. "v=spf1 ip4:185.220.101.0/24 include:_spf.google.com ~all"
    terms = spf_record.split()
    for term in terms:
        if term.startswith("ip4:") or term.startswith("ip6:"):
            network_str = term.split(":", 1)[1]
            try:
                if "/" in network_str:
                    net = ipaddress.ip_network(network_str, strict=False)
                    if sender_ip_obj and sender_ip_obj in net:
                        ip_found = True
                        break
                else:
                    if sender_ip == network_str:
                        ip_found = True
                        break
            except Exception:
                continue

    if ip_found:
        status = "Pass"
        detail = f"Sender IP {sender_ip} is explicitly authorized in {domain}'s SPF record."
    else:
        # Check domain's SPF qualifier at the end:
        # -all = Hard Fail (Reject)
        # ~all = Soft Fail (Mark as spam)
        # ?all = Neutral
        if spf_record.endswith("-all"):
            status = "Fail"
            detail = f"Sender IP {sender_ip} is NOT authorized. Policy specifies Hard Fail (-all)."
        elif spf_record.endswith("~all"):
            status = "SoftFail"
            detail = f"Sender IP {sender_ip} is NOT authorized. Policy specifies Soft Fail (~all)."
        else:
            status = "Neutral"
            detail = f"Sender IP {sender_ip} is not listed in SPF record."

    return {
        "status": status,
        "record": spf_record,
        "detail": detail
    }


def verify_dkim(raw_eml_bytes: bytes) -> Dict[str, Any]:
    """
    Verifies DKIM (DomainKeys Identified Mail) cryptographic signature using dkimpy.
    dkim.verify() parses the DKIM-Signature header, queries DNS for the public key,
    and validates RSA/Ed25519 signature against email body and headers.
    """
    try:
        is_valid = dkim.verify(raw_eml_bytes)
        if is_valid:
            return {
                "status": "Pass",
                "detail": "DKIM cryptographic digital signature verified successfully."
            }
        else:
            if b"DKIM-Signature:" in raw_eml_bytes or b"dkim-signature:" in raw_eml_bytes:
                return {
                    "status": "Fail",
                    "detail": "DKIM signature is present but failed cryptographic validation (possible tampering)."
                }
            else:
                return {
                    "status": "None",
                    "detail": "No DKIM-Signature header found in email."
                }
    except Exception as e:
        logger.warning(f"DKIM verification error: {e}")
        if b"DKIM-Signature:" in raw_eml_bytes or b"dkim-signature:" in raw_eml_bytes:
            return {
                "status": "Fail",
                "detail": f"DKIM verification failed: {str(e)}"
            }
        return {
            "status": "None",
            "detail": "No valid DKIM signature found."
        }


def verify_dmarc(domain: str) -> Dict[str, Any]:
    """
    Checks DMARC TXT record for the domain (at _dmarc.{domain}).
    Identifies published enforcement policy: p=none, p=quarantine, p=reject.
    """
    dmarc_domain = f"_dmarc.{domain}"
    records = resolve_txt_records(dmarc_domain)
    
    dmarc_record = None
    for r in records:
        if r.startswith("v=DMARC1"):
            dmarc_record = r
            break
            
    if not dmarc_record:
        return {
            "status": "None",
            "record": None,
            "policy": "none",
            "detail": f"No DMARC record found at {dmarc_domain}."
        }
        
    policy = "none"
    if "p=reject" in dmarc_record.lower():
        policy = "reject"
    elif "p=quarantine" in dmarc_record.lower():
        policy = "quarantine"
        
    return {
        "status": "Pass",
        "record": dmarc_record,
        "policy": policy,
        "detail": f"DMARC record found. Policy: {policy}."
    }


def verify_alignment(
    from_domain: str, 
    return_path: str, 
    raw_eml_bytes: bytes
) -> Dict[str, Any]:
    """
    Checks DMARC Alignment:
    - SPF Alignment: From domain matches Return-Path domain.
    - DKIM Alignment: From domain matches 'd=' tag in DKIM-Signature header.
    DMARC requires at least one authenticated identifier to align with From domain.
    """
    spf_aligned = False
    dkim_aligned = False
    
    # 1. Check SPF Alignment (From domain vs Return-Path domain)
    return_path_email = extract_email_address(return_path)
    return_path_domain = ""
    if return_path_email and "@" in return_path_email:
        return_path_domain = return_path_email.split("@")[-1].lower().strip()
        
    if from_domain and return_path_domain:
        # Check exact match or relaxed organizational domain match (subdomains)
        if (from_domain == return_path_domain or 
            from_domain.endswith("." + return_path_domain) or 
            return_path_domain.endswith("." + from_domain)):
            spf_aligned = True
            
    # 2. Check DKIM Alignment (From domain vs d= tag domain)
    dkim_domains = []
    try:
        headers_str = raw_eml_bytes.decode('utf-8', errors='ignore')
        # Look for d=domain.com in DKIM-Signature headers
        for match in re.finditer(r'DKIM-Signature:[^;]+;\s*.*?d=([^;\s]+)', headers_str, re.IGNORECASE | re.DOTALL):
            dkim_domains.append(match.group(1).lower().strip())
    except Exception:
        pass
        
    if from_domain:
        for d in dkim_domains:
            if from_domain == d or from_domain.endswith("." + d) or d.endswith("." + from_domain):
                dkim_aligned = True
                break

    # DMARC is considered aligned if either SPF or DKIM aligns with From header
    dmarc_aligned = spf_aligned or dkim_aligned

    return {
        "spf_aligned": spf_aligned,
        "dkim_aligned": dkim_aligned,
        "dmarc_aligned": dmarc_aligned,
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "dkim_domains": dkim_domains
    }

import re
import email
from email.parser import Parser
import ipaddress
from typing import Dict, List, Any, Optional

# IPv4 regex pattern (matches numbers between 0-255 separated by dots)
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# IPv6 regex pattern (matches standard hex groups separated by colons)
IPV6_REGEX = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b')

def extract_email_address(header_value: str) -> Optional[str]:
    """
    Helper function to extract the clean email address from a header value.
    For example:
      'John Doe <john@example.com>' -> 'john@example.com'
      'john@example.com'            -> 'john@example.com'
    """
    if not header_value:
        return None
        
    # Search for an email address inside angle brackets < >
    match = re.search(r'<([^>]+)>', header_value)
    if match:
        return match.group(1).strip()
    
    # If no brackets exist, search for a general email pattern in the string
    email_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
    if email_match:
        return email_match.group(0).strip()
    
    return header_value.strip()


def extract_basic_info(raw_email_content: str) -> Dict[str, Any]:
    """
    Parses a raw email text and extracts standard metadata fields:
    From, To, Subject, Date, Message-ID, Reply-To, Return-Path, and Sender Domain.
    """
    # 1. Initialize the built-in email Parser
    parser = Parser()
    
    # 2. Parse the raw email string into a Message object
    msg = parser.parsestr(raw_email_content)
    
    # 3. Retrieve standard headers (using msg.get with fallbacks to empty string)
    from_header = msg.get("From", "")
    to_header = msg.get("To", "")
    subject = msg.get("Subject", "")
    date = msg.get("Date", "")
    message_id = msg.get("Message-ID", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    
    # 4. Clean the 'From' header to get the sender's actual email address
    sender_email = extract_email_address(from_header)
    
    # 5. Extract the sender's domain name from the email (e.g. 'paypal.com')
    sender_domain = ""
    if sender_email and "@" in sender_email:
        sender_domain = sender_email.split("@")[-1].lower().strip()
        
    return {
        "from": from_header,
        "sender_email": sender_email,
        "sender_domain": sender_domain,
        "to": to_header,
        "subject": subject,
        "date": date,
        "message_id": message_id,
        "reply_to": reply_to,
        "return_path": return_path
    }


def is_public_ip(ip_str: str) -> bool:
    """
    Checks if an IP address string is a valid public IP.
    Returns False for private (LAN) ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x),
    loopbacks (127.0.0.1), link-local, multicast, or invalid strings.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        # ip.is_private checks RFC 1918 private address spaces
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
            return False
        return True
    except ValueError:
        # If it's not a valid IP string format, return False
        return False


def parse_received_headers(raw_email_content: str) -> List[Dict[str, Any]]:
    """
    Parses all 'Received' headers to reconstruct the transmission hop path.
    Returns a list of dicts, sorted chronologically from earliest (origin) to latest (destination).
    """
    parser = Parser()
    msg = parser.parsestr(raw_email_content)
    
    # msg.get_all("Received") returns headers in the order they appear in the file.
    # Because each mail server prepends to the TOP, the list starts with the LATEST hop.
    received_headers = msg.get_all("Received") or []
    
    hops = []
    hop_num = 1
    
    # We iterate with reversed() to go from EARLIEST (origin) to LATEST (destination)
    for header in reversed(received_headers):
        ips_found = []
        
        # Search for all IPv4 and IPv6 strings in this specific Received header line
        for ip in IPV4_REGEX.findall(header) + IPV6_REGEX.findall(header):
            ip_clean = ip.strip("[]() ")
            try:
                ipaddress.ip_address(ip_clean)
                if ip_clean not in ips_found:
                    ips_found.append(ip_clean)
            except ValueError:
                continue
        
        # Categorize IPs into public vs private
        public_ips = [ip for ip in ips_found if is_public_ip(ip)]
        private_ips = [ip for ip in ips_found if not is_public_ip(ip)]
        
        hops.append({
            "hop": hop_num,
            "raw": header.replace("\n", " ").replace("\t", " ").strip(),
            "all_ips": ips_found,
            "public_ips": public_ips,
            "private_ips": private_ips
        })
        hop_num += 1
        
    return hops


def get_earliest_reliable_ip(hops: List[Dict[str, Any]]) -> Optional[str]:
    """
    Extracts the earliest reliable public sending IP address from the hop path.
    Scans the hops starting from Hop 1 (earliest) and returns the first public IP encountered.
    """
    for hop in hops:
        if hop["public_ips"]:
            return hop["public_ips"][0]
    return None


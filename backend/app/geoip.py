import requests
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# List of keywords commonly associated with cloud hosting, VPS, data centers, and VPNs
HOSTING_OR_VPN_KEYWORDS = [
    "amazon", "aws", "google cloud", "microsoft", "azure", "digitalocean",
    "linode", "hosting", "ovh", "m247", "data camp", "servers", "leaseweb", 
    "hetzner", "scaleway", "vultr", "oracle cloud", "cloudflare", "fastly", 
    "tor-exit", "protonvpn", "nordvpn", "expressvpn", "private internet access"
]

def check_is_hosting(org_str: Optional[str]) -> bool:
    """
    Checks if the Organization or ASN name matches known cloud/VPS/VPN providers.
    Returns True if suspicious hosting/data-center keyword is found.
    """
    if not org_str:
        return False
    org_lower = org_str.lower()
    for keyword in HOSTING_OR_VPN_KEYWORDS:
        if keyword in org_lower:
            return True
    return False


def get_ip_geolocation(ip: str, token: str = "") -> Dict[str, Any]:
    """
    Resolves geographic location and network intelligence for a given public IP
    using the ipinfo.io public API.
    """
    if not ip or ip == "None":
        return {
            "ip_address": "",
            "country": "Unknown",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "asn": "Unknown",
            "org": "Unknown",
            "is_hosting": False
        }

    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"

    try:
        # Send HTTP GET request to ipinfo API
        response = requests.get(url, timeout=6)
        if response.status_code == 200:
            data = response.json()
            
            # ipinfo gives coordinates as "loc": "latitude,longitude" (e.g. "50.1155,8.6842")
            lat, lon = None, None
            loc_str = data.get("loc", "")
            if loc_str and "," in loc_str:
                try:
                    lat_part, lon_part = loc_str.split(",")
                    lat = float(lat_part.strip())
                    lon = float(lon_part.strip())
                except ValueError:
                    pass

            org_str = data.get("org", "Unknown")
            
            # Extract ASN (Autonomous System Number) - format is typically "AS15169 Google LLC"
            asn_str = "Unknown"
            if org_str and org_str.startswith("AS"):
                asn_str = org_str.split(" ", 1)[0]

            is_hosting = check_is_hosting(org_str)

            return {
                "ip_address": ip,
                "country": data.get("country", "Unknown"),
                "region": data.get("region", "Unknown"),
                "city": data.get("city", "Unknown"),
                "latitude": lat,
                "longitude": lon,
                "asn": asn_str,
                "org": org_str,
                "is_hosting": is_hosting
            }
        else:
            logger.warning(f"ipinfo API returned HTTP {response.status_code}")

    except Exception as e:
        logger.error(f"Failed to resolve IP geolocation for {ip}: {e}")

    # Fallback response if network or API fails
    return {
        "ip_address": ip,
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "latitude": None,
        "longitude": None,
        "asn": "Unknown",
        "org": "Unknown",
        "is_hosting": False
    }

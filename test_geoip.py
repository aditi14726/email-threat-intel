import json
from backend.app.geoip import get_ip_geolocation

def main():
    print("=" * 65)
    print("🌍 TESTING MODULE 2: IP GEOLOCATION & THREAT INTEL")
    print("=" * 65)

    # 1. Attacker IP jo hamare test email se nikla tha
    attacker_ip = "185.220.101.5"
    print(f"\n🔍 [Test 1] Querying Attacker's Origin IP: {attacker_ip}...")
    geo_data = get_ip_geolocation(attacker_ip)
    
    print(f"    Country     : {geo_data['country']}")
    print(f"    Region/City : {geo_data['region']} / {geo_data['city']}")
    print(f"    Coordinates : Latitude {geo_data['latitude']}, Longitude {geo_data['longitude']}")
    print(f"    ISP / Org   : {geo_data['org']}")
    print(f"    ASN         : {geo_data['asn']}")
    print(f"    Is Hosting? : {geo_data['is_hosting']}")
    
    if geo_data['is_hosting']:
        print("    🚨 THREAT FLAG: Yeh IP kisi personal broadband ka nahi hai,")
        print("       balki ek Cloud Server / Data Center / VPN ka hai!")

    # 2. Comparison ke liye ek popular known IP (Google DNS: 8.8.8.8)
    google_ip = "8.8.8.8"
    print(f"\n🔍 [Test 2] Querying Known Clean IP (Google): {google_ip}...")
    google_geo = get_ip_geolocation(google_ip)
    print(f"    Country     : {google_geo['country']}")
    print(f"    City        : {google_geo['city']}")
    print(f"    ISP / Org   : {google_geo['org']}")
    print(f"    Coordinates : {google_geo['latitude']}, {google_geo['longitude']}")

    print("\n" + "=" * 65)
    print("✅ Inhi Coordinates (Lat/Lon) ko hum aage Leaflet.js Map par")
    print("   as a RED PIN point karenge!")
    print("=" * 65)

if __name__ == "__main__":
    main()

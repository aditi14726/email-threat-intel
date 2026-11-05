# AegisMail — Email Threat Detection & Forensic Intelligence Platform

> **Automated email spoofing detection, cryptographic DNS authentication (SPF/DKIM/DMARC), MTA relay hop reconstruction, and origin geolocation intelligence.**

---

## 🛡️ Overview

**AegisMail** is a Digital Forensics & Incident Response (DFIR) platform designed to detect email fraud, business email compromise (BEC), and phishing payloads.

While traditional email filters rely solely on keyword matching, **AegisMail** analyzes the entire RFC 5322 metadata envelope:
- Validates cryptographic domain signatures (**DKIM**) and DNS authorization records (**SPF/DMARC**).
- Detects domain alignment mismatches between visual `From:` headers and technical `Return-Path` / `Reply-To` addresses.
- Reconstructs the multi-server **Mail Transfer Agent (MTA)** relay chain from `Received:` headers to isolate the earliest reliable public sending IP.
- Resolves geographical coordinates, Autonomous System Number (ASN), and hosting/VPN/Tor infrastructure.
- Computes an explainable **0–100 Fraud Risk Score** with full signal attribution.

---

## ⚡ Key Modules

### Module 1: Email Threat Detection & Verification Engine
* **Header Forensics**: Extracts standard RFC 5322 fields (`From`, `To`, `Subject`, `Message-ID`, `Date`, `Reply-To`, `Return-Path`).
* **Cryptographic DNS Authentication**:
  * **SPF (Sender Policy Framework)**: Queries real-time DNS TXT records to verify if the sending IP is explicitly authorized.
  * **DKIM (DomainKeys Identified Mail)**: Validates public-key cryptographic signatures using `dkimpy`.
  * **DMARC & Alignment**: Enforces domain alignment checks (ensuring visual sender domain matches the authenticated SPF/DKIM domains).
* **Semantic & Link Inspection (NLP)**:
  * Detects psychological panic cues (e.g., *"immediate action required"*, *"account suspended within 24 hours"*).
  * Flags brand impersonation (e.g., body claiming PayPal/Microsoft while sender domain is mismatched).
  * Catches deceptive hyperlinks (Anchor text showing legitimate domains while `href` targets direct IP-based web servers).
* **Risk Scoring**: Weighted algorithm generating a 0–100 Fraud Score categorized as **Safe**, **Suspicious**, or **Malicious**.

### Module 2: Origin Traceability & Geolocation Intelligence
* **Relay Hop Re-assembly**: Reverses server-prepended `Received:` headers into chronological order.
* **Public Ingress Isolation**: Filters out RFC 1918 private LAN ranges (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`, `127.0.0.1`) to isolate the true public ingress IP.
* **Network & ISP Telemetry**: Queries `ipinfo.io` to extract physical coordinates (latitude/longitude), city, country, ASN, and organization.
* **Hosting / Tor / VPN Heuristics**: Flags if the sending server is hosted on disposable cloud/VPS subnets (AWS, DigitalOcean, Hetzner, Tor exit nodes).
* **Interactive Mapping**: Renders the attack vector transit path on an **Esri World Dark Canvas** Leaflet.js map.

---

## 💻 Tech Stack

* **Backend**: Python 3.9+, FastAPI (Asynchronous ASGI Web Framework), Uvicorn
* **Security & Network**: `dnspython`, `dkimpy`, `ipaddress`, `requests`
* **Frontend**: HTML5, Tailwind CSS (Dark Mode / Cyberpunk Aesthetic), Leaflet.js, Esri Dark Canvas GIS
* **Standards**: RFC 5322 (Internet Message Format), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)

---

## 🚀 Quickstart & Setup

### 1. Clone & Set Up Virtual Environment
```bash
git clone https://github.com/your-username/email-threat-intel.git
cd email-threat-intel

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate   # On Windows
# source venv/bin/activate  # On Linux / macOS
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the Platform
```bash
uvicorn backend.app.main:app --reload
```
Navigate to **`http://127.0.0.1:8000`** in your browser.

*(For interactive API documentation, visit `http://127.0.0.1:8000/docs`).*

---

## 🧪 Built-in Test Scenarios

The web dashboard comes equipped with 1-click test presets:

1. **GitHub Alert (Safe)**: Valid transactional notification with clean headers, passing authentication, and legitimate relay hops (**Score: 0/100 • SAFE**).
2. **CEO Wire Fraud (Suspicious)**: Business Email Compromise (BEC) with `Reply-To` mismatch and psychological urgency cues (**Score: 50/100 • SUSPICIOUS**).
3. **Microsoft 365 Credential Harvester (Malicious)**: Phishing attack utilizing deceptive anchor links, direct IP-based URLs, and spoofed headers (**Score: 75/100 • MALICIOUS**).

You can also drag-and-drop raw `.eml` files from the `test_samples/` directory directly into the UI.

---

## ⚖️ Legal & Ethical Notice

This platform operates strictly as a **passive Digital Forensics and Incident Response (DFIR)** tool. It inspects metadata of messages that have already been received. It performs standard public DNS resolution and passive IP geolocation queries identical to standard mail user agents (MUA) and Mail Transfer Agents (MTA). It does not engage in active network intrusion, port scanning, or unauthorized exploitation.

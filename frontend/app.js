// Global Leaflet map variable
let map = null;
let originMarker = null;
let recipientMarker = null;
let routeLine = null;

// 3 Distinct Forensic Test Cases
const TEST_PRESETS = {
    clean: `From: GitHub Notifications <support@github.com>
To: developer@mycompany.com
Subject: [GitHub] A new public SSH key was added to your account
Date: Thu, 05 Nov 2026 14:00:00 +0000
Message-ID: <github-auth-notif-78921@github.com>
Reply-To: support@github.com
Return-Path: <support@github.com>
Received: from mail-storage.internal (localhost [127.0.0.1])
	by mail.company.com with ESMTP id 88B12C
	for <developer@mycompany.com>; Thu, 05 Nov 2026 14:00:03 +0000
Received: from mail-out.github.com (mail-out.github.com [140.82.115.1])
	by mx.google.com with ESMTPS id g14-v6si2341235
	for <developer@mycompany.com>; Thu, 05 Nov 2026 14:00:02 +0000
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Hi developer,</p>
<p>The following SSH key was added to your GitHub account: <code>SHA256:d84f82a9...</code></p>
<p>If you added this key, you can safely ignore this email.</p>
</body>
</html>`,

    bec: `From: CEO Johnathan Smith <ceo@acme-enterprises-global.com>
To: finance-lead@acme-enterprises-global.com
Subject: Quick Request - Urgent Wire Transfer
Date: Thu, 05 Nov 2026 15:30:00 +0000
Message-ID: <bec-exec-compromise-9981@external-relay.net>
Reply-To: johnathan.smith.personal99@gmail.com
Return-Path: <bounce@unauthorized-smtp.org>
Received: from mx.recipient-inbox.com (mx.recipient-inbox.com [10.0.0.1])
	by mail-storage.internal with ESMTP id 99C81D;
	Thu, 05 Nov 2026 15:30:04 +0000
Received: from smtp-spoofer.vps-cloud.de (smtp-spoofer.vps-cloud.de [195.201.20.10])
	by mx.recipient-inbox.com with ESMTPS id A23F1404B;
	Thu, 05 Nov 2026 15:30:02 +0000
Content-Type: text/plain; charset="UTF-8"

Hi finance team,

Are you at your desk right now?

I am currently in an urgent offsite board meeting with investors. We need to process an immediate wire transfer to close a critical acquisition before end of day.

Please do not call my office line. Reply directly to this email right away so I can send beneficiary details.

Regards,
Johnathan Smith
Chief Executive Officer`,

    msft: `From: Microsoft 365 Support <admin-support@microsoft-online-verify.net>
To: employee@victim-corp.com
Subject: ACTION REQUIRED: Your Microsoft Office 365 Password Expires Today!
Date: Thu, 05 Nov 2026 16:15:00 +0000
Message-ID: <msft-harvest-campaign-1102@microsoft-online-verify.net>
Reply-To: security-notice@microsoft-online-verify.net
Return-Path: <bounce@attacker-vps-direct.com>
Received: from mx.target-mail.com (mx.target-mail.com [172.16.0.5])
	by mail-gateway.local with ESMTP id 776A1B;
	Thu, 05 Nov 2026 16:15:05 +0000
Received: from tor-node.exit-host.de (tor-node.exit-host.de [185.220.101.5])
	by mx.target-mail.com with ESMTPS id BC23F90;
	Thu, 05 Nov 2026 16:15:02 +0000
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<h3>Microsoft Office 365 Security Notice</h3>
<p>Your password will expire within 24 hours. Immediate action required.</p>
<p>If you wish to keep your current password, please verify credentials:</p>
<p><a href="http://185.220.101.5/microsoft/login.php">https://login.microsoftonline.com/common/oauth2/authorize</a></p>
</body>
</html>`
};

function loadPreset(type) {
    setIngestMode("paste");
    const textarea = document.getElementById("raw-headers");
    if (TEST_PRESETS[type]) {
        textarea.value = TEST_PRESETS[type];
        textarea.classList.add("ring-2", "ring-indigo-500");
        setTimeout(() => textarea.classList.remove("ring-2", "ring-indigo-500"), 600);
    }
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("btn-analyze").addEventListener("click", performAnalysis);
});

// Toggle between Raw Paste and File Upload Modes
function setIngestMode(mode) {
    const pastePanel = document.getElementById("panel-paste");
    const filePanel = document.getElementById("panel-file");
    const pasteBtn = document.getElementById("toggle-paste");
    const fileBtn = document.getElementById("toggle-file");

    if (mode === "paste") {
        pastePanel.classList.remove("hidden");
        filePanel.classList.add("hidden");
        pasteBtn.className = "py-2 rounded-lg bg-indigo-600 text-white shadow-md shadow-indigo-600/30 transition-all duration-150";
        fileBtn.className = "py-2 rounded-lg text-slate-400 hover:text-slate-200 transition-all duration-150";
    } else {
        pastePanel.classList.add("hidden");
        filePanel.classList.remove("hidden");
        fileBtn.className = "py-2 rounded-lg bg-indigo-600 text-white shadow-md shadow-indigo-600/30 transition-all duration-150";
        pasteBtn.className = "py-2 rounded-lg text-slate-400 hover:text-slate-200 transition-all duration-150";
    }
}

// 1-Click Load Sample Threat into Textarea
function loadSamplePhish() {
    setIngestMode("paste");
    const textarea = document.getElementById("raw-headers");
    textarea.value = SAMPLE_PHISHING_EMAIL;
    textarea.classList.add("ring-2", "ring-indigo-500");
    setTimeout(() => textarea.classList.remove("ring-2", "ring-indigo-500"), 800);
}

// Update file label upon selection
function updateFileName(input) {
    const label = document.getElementById("file-label");
    if (input.files.length > 0) {
        label.textContent = `Selected: ${input.files[0].name} (${(input.files[0].size / 1024).toFixed(1)} KB)`;
        label.classList.add("text-cyan-400", "font-bold");
    }
}

// Perform Analysis API Call
async function performAnalysis() {
    const fileInput = document.getElementById("eml-file");
    const rawTextarea = document.getElementById("raw-headers");
    const btn = document.getElementById("btn-analyze");

    btn.disabled = true;
    btn.innerHTML = `
        <svg class="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
        </svg>
        <span>Running Security Telemetry...</span>
    `;

    try {
        let response;
        if (fileInput.files.length > 0) {
            const formData = new FormData();
            formData.append("file", fileInput.files[0]);
            response = await fetch("/api/analyze/file", { method: "POST", body: formData });
        } else if (rawTextarea.value.trim() !== "") {
            const formData = new FormData();
            formData.append("raw_content", rawTextarea.value);
            response = await fetch("/api/analyze/raw", { method: "POST", body: formData });
        } else {
            alert("Please paste email headers or click 'Load Sample Threat' first!");
            btn.disabled = false;
            btn.innerHTML = `<span>Run Forensic Inspection</span>`;
            return;
        }

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.detail || "Server error occurred during scan.");
        }

        const data = await response.json();
        renderAnalysisResults(data);

    } catch (err) {
        alert("Forensic scan failed: " + err.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
            </svg>
            <span>Run Forensic Inspection</span>
        `;
    }
}

// Render Results on the Redesigned Dashboard
function renderAnalysisResults(data) {
    document.getElementById("results-empty").classList.add("hidden");
    document.getElementById("results-content").classList.remove("hidden");

    // Metadata
    document.getElementById("res-subject").textContent = data.subject || "(No Subject)";
    document.getElementById("res-sender").textContent = data.sender;
    document.getElementById("res-replyto").textContent = data.reply_to || "None declared";
    document.getElementById("res-date").textContent = data.date || "Parsed Timestamp";

    const score = data.risk_score;
    const verdict = data.verdict;
    document.getElementById("res-score").textContent = score;

    // Animate Circular Progress Gauge
    const circle = document.getElementById("gauge-arc");
    const totalCircumference = 2 * Math.PI * 40; // r=40 -> 251.2
    const offset = totalCircumference - (score / 100) * totalCircumference;
    circle.style.strokeDashoffset = offset;

    const verdictBadge = document.getElementById("res-verdict-badge");
    const verdictText = document.getElementById("res-verdict-text");
    const heroGradient = document.getElementById("hero-gradient");

    verdictBadge.textContent = verdict.toUpperCase();

    if (verdict === "Malicious") {
        circle.setAttribute("class", "gauge-circle text-rose-500 drop-shadow-[0_0_10px_rgba(244,63,94,0.7)]");
        verdictBadge.className = "px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-rose-500/10 text-rose-400 border border-rose-500/30";
        heroGradient.className = "absolute top-0 left-0 right-0 h-[2px] bg-rose-500";
        verdictText.textContent = "High Severity Phishing Attack";
    } else if (verdict === "Suspicious") {
        circle.setAttribute("class", "gauge-circle text-amber-500 drop-shadow-[0_0_10px_rgba(245,158,11,0.7)]");
        verdictBadge.className = "px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-amber-500/10 text-amber-400 border border-amber-500/30";
        heroGradient.className = "absolute top-0 left-0 right-0 h-[2px] bg-amber-500";
        verdictText.textContent = "Moderate Anomalies Flagged";
    } else {
        circle.setAttribute("class", "gauge-circle text-emerald-500 drop-shadow-[0_0_10px_rgba(16,185,129,0.7)]");
        verdictBadge.className = "px-2.5 py-0.5 rounded-full text-[10px] font-extrabold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
        heroGradient.className = "absolute top-0 left-0 right-0 h-[2px] bg-emerald-500";
        verdictText.textContent = "Cryptographically Clean";
    }

    // TAB 1: Fired Threat Signals
    const breakdown = data.score_breakdown || [];
    document.getElementById("count-threats").textContent = breakdown.length;
    const signalsList = document.getElementById("res-breakdown-list");

    if (breakdown.length === 0) {
        signalsList.innerHTML = `<div class="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-emerald-400 text-xs font-semibold">✅ No malicious threats or spoofing vectors identified.</div>`;
    } else {
        signalsList.innerHTML = breakdown.map(sig => `
            <div class="flex justify-between items-center bg-[#090d16] border border-slate-800 p-3 rounded-xl hover:border-slate-750 transition duration-150">
                <div class="flex items-center space-x-2.5">
                    <span class="text-[9px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono border border-slate-700">${sig.category}</span>
                    <span class="text-xs text-slate-200 font-medium">${sig.rule}</span>
                </div>
                <span class="text-xs font-black font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 shrink-0">+${sig.points} pts</span>
            </div>
        `).join("");
    }

    // TAB 2: Geolocation & Route
    const geo = data.origin_geo || {};
    document.getElementById("geo-ip").textContent = geo.ip_address || "None";
    document.getElementById("geo-city").textContent = `${geo.city || "Unknown"}, ${geo.region || ""}`;
    document.getElementById("geo-country").textContent = geo.country || "Unknown";
    document.getElementById("geo-coords").textContent = (geo.latitude && geo.longitude) ? `${geo.latitude}, ${geo.longitude}` : "None";
    document.getElementById("geo-org").textContent = geo.org || "Unknown";
    document.getElementById("geo-asn").textContent = geo.asn || "Unknown";
    document.getElementById("geo-location-tag").textContent = `${geo.city || "Origin Node"}, ${geo.country || ""}`;

    const isHosting = document.getElementById("geo-hosting");
    isHosting.textContent = geo.is_hosting ? "YES (Cloud / Tor / VPN)" : "NO (Residential/Clean)";
    isHosting.className = geo.is_hosting 
        ? "px-2 py-0.5 rounded text-[10px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30" 
        : "px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";

    // Visual Relay Hop Stepper Timeline (Clean Indigo/Cyan Style)
    const hops = data.hops || [];
    const stepperBox = document.getElementById("hops-stepper");
    stepperBox.innerHTML = hops.map((h, idx) => {
        const isEarliest = idx === 0;
        const isLatest = idx === hops.length - 1;
        const badgeLabel = isEarliest ? "Origin Server" : (isLatest ? "Destination Mailbox" : `Relay Hop ${h.hop}`);
        const ipText = h.public_ips.length > 0 ? h.public_ips.join(", ") : (h.private_ips.length > 0 ? `${h.private_ips.join(", ")} (Private LAN)` : "Internal Relay");

        return `
            <div class="flex items-start space-x-3 p-3 rounded-xl bg-[#090d16] border border-slate-800">
                <div class="w-6 h-6 rounded-lg ${isEarliest ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' : 'bg-indigo-950/60 text-indigo-400 border border-indigo-500/20'} flex items-center justify-center text-[11px] font-black font-mono shrink-0">
                    ${h.hop}
                </div>
                <div class="flex-grow space-y-0.5 min-w-0">
                    <div class="flex justify-between items-center">
                        <span class="font-mono text-xs font-bold text-slate-200">${ipText}</span>
                        <span class="text-[9px] uppercase font-bold tracking-wider px-2 py-0.5 rounded ${isEarliest ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20' : 'bg-slate-800/80 text-slate-400'}">${badgeLabel}</span>
                    </div>
                    <p class="text-[10px] text-slate-500 truncate font-mono" title="${h.raw}">${h.raw}</p>
                </div>
            </div>
        `;
    }).join("");

    // Initialize Map with High-Contrast Dark Tiles
    initMap(geo);

    // TAB 3: Authentication Badges & Content
    const dns = data.dns || {};
    const alignment = data.alignment || {};
    setBadgeStatus("auth-spf", dns.spf?.status || "None");
    setBadgeStatus("auth-dkim", dns.dkim?.status || "None");
    setBadgeStatus("auth-alignment", alignment.dmarc_aligned ? "Pass" : "Mismatch");
    setBadgeStatus("auth-dmarc", dns.dmarc?.policy ? `Policy: ${dns.dmarc.policy.toUpperCase()}` : "None");

    // Content cues
    const content = data.content_analysis || {};
    const nlp = content.nlp || {};
    const links = content.links || {};

    document.getElementById("content-urgency").textContent = nlp.urgency_matches && nlp.urgency_matches.length > 0 ? nlp.urgency_matches.join(", ") : "No panic cues found";
    document.getElementById("content-impersonation").textContent = nlp.impersonation_flagged ? `Target: ${nlp.impersonation_brands.join(", ")}` : "None detected";

    const linksBox = document.getElementById("content-links");
    if (links.suspicious_links && links.suspicious_links.length > 0) {
        linksBox.innerHTML = links.suspicious_links.map(l => `<div class="p-2 rounded bg-rose-500/10 border border-rose-500/20 text-rose-300">⚠️ ${l.url} <br><span class="text-[10px] text-slate-400">Flag: ${l.reasons.join(", ")}</span></div>`).join("");
    } else {
        linksBox.innerHTML = `<span class="text-emerald-400 font-semibold">✅ All hyperlinks appear clean</span>`;
    }

    // Default to Tab 1
    switchTab("tab-threats");
}

// Leaflet Map Plotter (Esri World Dark Canvas - Clean, High Contrast, World Borders Visible)
function initMap(geo) {
    const lat = geo.latitude;
    const lon = geo.longitude;
    const destLat = 20.5937;
    const destLon = 78.9629;

    if (map === null) {
        map = L.map('map', {
            zoomControl: true,
            scrollWheelZoom: false
        }).setView([35.0, 45.0], 3);

        // High contrast Esri Dark Gray Canvas (Shows continents and borders clearly in dark mode)
        L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{z}/{y}/{x}', {
            attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
            maxZoom: 16
        }).addTo(map);
    } else {
        map.setView([35.0, 45.0], 3);
    }

    if (originMarker) map.removeLayer(originMarker);
    if (recipientMarker) map.removeLayer(recipientMarker);
    if (routeLine) map.removeLayer(routeLine);

    if (lat && lon) {
        // Glowing Crimson Origin Marker (Attacker Node)
        originMarker = L.circleMarker([lat, lon], {
            radius: 8,
            fillColor: "#f43f5e",
            color: "#ffffff",
            weight: 2,
            opacity: 1,
            fillOpacity: 1
        }).addTo(map)
        .bindPopup(`<div style="color:#0f172a; font-size:12px;"><b>🚨 Attacker Origin Node</b><br>IP: ${geo.ip_address}<br>${geo.city || ""}, ${geo.country || ""}</div>`)
        .openPopup();

        // Emerald Recipient Marker (Local Node)
        recipientMarker = L.circleMarker([destLat, destLon], {
            radius: 7,
            fillColor: "#10b981",
            color: "#ffffff",
            weight: 2,
            opacity: 1,
            fillOpacity: 1
        }).addTo(map)
        .bindPopup(`<div style="color:#0f172a; font-size:12px;"><b>📬 Destination Mailbox Node</b><br>Recipient Ingress</div>`);

        // Cyber Cyan Glowing Transit Line
        routeLine = L.polyline([[lat, lon], [destLat, destLon]], {
            color: '#06b6d4',
            weight: 3,
            opacity: 0.9,
            dashArray: '5, 8'
        }).addTo(map);

        setTimeout(() => {
            map.invalidateSize();
            map.fitBounds([[lat, lon], [destLat, destLon]], { padding: [50, 50] });
        }, 200);
    }
}

// Set color badges for security seals
function setBadgeStatus(elementId, status) {
    const badge = document.getElementById(elementId);
    badge.textContent = status;
    
    const s = status.toLowerCase();
    if (s.includes("pass") || s.includes("aligned") || s.includes("true")) {
        badge.className = "px-2.5 py-1 rounded-md text-[11px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30";
    } else if (s.includes("fail") || s.includes("mismatch") || s.includes("reject")) {
        badge.className = "px-2.5 py-1 rounded-md text-[11px] font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30";
    } else if (s.includes("softfail") || s.includes("neutral") || s.includes("quarantine")) {
        badge.className = "px-2.5 py-1 rounded-md text-[11px] font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30";
    } else {
        badge.className = "px-2.5 py-1 rounded-md text-[11px] font-bold bg-slate-800 text-slate-400 border border-slate-700/60";
    }
}

// Tab Switcher Helper (Pure attribute matching, zero event dependency)
function switchTab(tabId) {
    document.querySelectorAll(".tab-pane").forEach(pane => pane.classList.add("hidden"));
    const activePane = document.getElementById(tabId);
    if (activePane) activePane.classList.remove("hidden");

    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.className = "tab-btn flex-1 py-2 rounded-lg text-slate-400 hover:text-slate-200 transition-all duration-150 flex items-center justify-center space-x-1.5";
        if (btn.getAttribute("onclick") && btn.getAttribute("onclick").includes(tabId)) {
            btn.className = "tab-btn flex-1 py-2 rounded-lg bg-indigo-600 text-white shadow-md shadow-indigo-600/30 transition-all duration-150 flex items-center justify-center space-x-1.5";
        }
    });

    if (tabId === "tab-geo" && map !== null) {
        setTimeout(() => map.invalidateSize(), 150);
    }
}

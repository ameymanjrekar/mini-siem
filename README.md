# 🛡️ Mini SIEM Dashboard

A beginner-friendly Security Information and Event Management (SIEM) dashboard built in Python with **Streamlit**, **Pandas**, **Plotly**, and **NetworkX**.

---

## 🚀 Key Features

1. **Multi-Log Ingestion**:
   - Upload multiple `.log`, `.txt`, `.csv`, or `.json` files simultaneously.
   - Click **"⚡ Load Samples"** for instant 1-click exploration of pre-built attack telemetry.

2. **Unified Multi-Log Timeline**:
   - Standardizes Syslog, SSH (`auth.log`), Web server (`access.log`), and firewall events onto one synchronized chronological timeline.
   - Interactive Altair histogram showing event spikes colored by severity.

3. **🌍 Geo-IP Attack Map (`plotly.express.scatter_geo`)**:
   - Global geographical threat attribution map.
   - Accurately plots external attacker IP locations (e.g. Frankfurt, Germany; Tokyo, Japan) and internal corporate LAN traffic.
   - Supports multiple map projections (`natural earth`, `orthographic`, `equirectangular`, `mercator`).
   - Interactive hover cards displaying city, country, associated user accounts, and severity.

4. **🕸️ Visual Entity Relationship Graph (Plotly + NetworkX)**:
   - Tri-partite network graph visually linking **IP Addresses ⟷ User Accounts ⟷ Target Hosts**.
   - Clear SOC node color taxonomy:
     - 🟩 **Hosts (Green Squares)**: Target servers (e.g. `srv-prod-01`, `web-prod-01`).
     - 🔴 **Attacker IPs (Red Circles)**: External threat actors performing recon or attacks.
     - 🔵 **Internal IPs (Blue Circles)**: Corporate LAN endpoints or agents.
     - 🟧 **Targeted/Compromised Users (Orange Triangles)**: Users with High/Critical security activity.
     - 🟪 **Benign Users (Purple Triangles)**: Standard system accounts.
   - **Ego-Network Filter**: Isolate any single entity to view only its direct 1-hop connections.

5. **Entity Correlation & Proximity Pivot**:
   - Click any IP address or Username chip to highlight all linked events occurring within an adjustable time window ($\pm 1$ to $\pm 30$ minutes).
   - Step-by-step chronological attack narrative reconstruction.

6. **Automated Threat Detection Rules**:
   - Automated alerts for SSH brute-force (>3 failures), privilege escalation (`sudo /bin/bash`), SQL injection, and database dump exfiltration.

7. **Interactive Triage Table & Export**:
   - `st.data_editor` to edit investigation tags (`Investigating`, `Suspicious`, `Malicious`, `False Positive`, `Resolved`) and analyst notes.
   - Export annotated findings to CSV.

---

## 🛠️ Installation & Quick Start

```powershell
cd C:\Users\ameym\.gemini\antigravity\scratch\siem-dashboard
pip install -r requirements.txt
streamlit run app.py
```

*Or run with Python directly:*
```powershell
& "C:\Users\ameym\AppData\Local\Programs\Python\Python314\python.exe" -m streamlit run app.py
```

---

## 📂 Included Sample Attack Telemetry

- **`sample_auth.log`**: External SSH brute force from `198.51.100.23`, privilege escalation by `support`, unauthorized shadow file access by `david`, and UFW firewall drop of port scan from `203.0.113.88`.
- **`sample_web.log`**: Web recon, `sqlmap` SQL injection, admin portal brute force, and unauthorized download of `database_dump.tar.gz`.

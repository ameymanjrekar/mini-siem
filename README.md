# 🛡️ Mini SIEM Dashboard

A beginner-friendly Security Information and Event Management (SIEM) dashboard built in Python with **Streamlit** and **Pandas**.

## 🚀 Features
- **Multi-Log Ingestion**: Upload multiple `.log`, `.txt`, `.csv`, or `.json` files simultaneously (or click **"⚡ Load Samples"**).
- **Unified Chronological Timeline**: Merges Syslog, SSH (`auth.log`), Web server (`access.log`), and firewall events onto one synchronized timeline.
- **Entity Correlation & Pivot**: Click any **IP address** or **Username** to highlight and correlate all events occurring within an adjustable time window ($\pm 1$ to $\pm 30$ minutes).
- **Threat Detection Heuristics**: Automated alerts for SSH brute force, privilege escalation (`sudo bash`), SQL injection/exploit probing, and unauthorized shadow file access.
- **Interactive Triage Table**: Edit investigation tags (`Investigating`, `Suspicious`, `Malicious`, `False Positive`, `Resolved`) and add analyst notes directly in the table.
- **Export Findings**: Download annotated incident logs as CSV.

---

## 🛠️ Quick Start

### 1. Requirements
Install Streamlit and Pandas:
```bash
pip install streamlit pandas altair
```

### 2. Launch Dashboard
Run the following command in this directory:
```bash
streamlit run app.py
```
Then open the local URL (usually `http://localhost:8501`) in your browser.

---

## 📂 Included Sample Logs
- **`sample_auth.log`**: External brute force on SSH (`198.51.100.23`), unauthorized sudo shadow file read (`david`), and firewall drops (`203.0.113.88`).
- **`sample_web.log`**: Nginx/Apache access logs showing SQL injection probing, admin login brute force, and sensitive database dump exfiltration.

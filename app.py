"""
Mini SIEM Dashboard
Single-file Streamlit application for security event monitoring, log correlation,
Geo-IP threat mapping, entity relationship graph visualization, and incident response tagging.
"""

import os
import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
import altair as alt
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx

# ---------------------------------------------------------
# Page Configuration & Styling
# ---------------------------------------------------------
st.set_page_config(
    page_title="Mini SIEM Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom sleek UI styling
st.markdown(
    """
    <style>
    .kpi-card {
        background-color: #f8fafc;
        border-radius: 10px;
        padding: 16px 20px;
        border: 1px solid #e2e8f0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        text-align: center;
    }
    .kpi-title {
        font-size: 0.82rem;
        color: #64748b;
        text-transform: uppercase;
        font-weight: 600;
        letter-spacing: 0.05em;
    }
    .kpi-value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #0f172a;
        margin-top: 4px;
    }
    .badge-critical {
        background-color: #fee2e2;
        color: #991b1b;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.82em;
    }
    .badge-high {
        background-color: #ffedd5;
        color: #9a3412;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.82em;
    }
    .badge-warning {
        background-color: #fef3c7;
        color: #92400e;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.82em;
    }
    .badge-info {
        background-color: #e0f2fe;
        color: #0369a1;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: 600;
        font-size: 0.82em;
    }
    .linked-banner {
        background: linear-gradient(135deg, #eff6ff 0%, #e0e7ff 100%);
        border: 1px solid #bfdbfe;
        border-left: 6px solid #3b82f6;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 12px 0 20px 0;
    }
    .threat-card {
        background-color: #fff1f2;
        border: 1px solid #fecdd3;
        border-left: 5px solid #f43f5e;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 10px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------------------------------------
# Regular Expressions & Parsing Helpers
# ---------------------------------------------------------
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Timestamp extractors
ISO_TIME_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})")
SYSLOG_TIME_REGEX = re.compile(r"([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
WEB_BRACKET_TIME_REGEX = re.compile(r"\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]")
WEB_APACHE_TIME_REGEX = re.compile(r"\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)\]")

# Syslog patterns
SYSLOG_HOST_REGEX = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+(?P<host>[a-zA-Z0-9_.-]+)\s+")
SSHD_FAILED = re.compile(r"sshd\[\d+\]:\s+Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
SSHD_ACCEPTED = re.compile(r"sshd\[\d+\]:\s+Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
SSHD_DISCONN = re.compile(r"sshd\[\d+\]:\s+(?:Received disconnect from|Connection closed by)\s+(?P<ip>\S+)")
SUDO_CMD = re.compile(r"sudo\[\d+\]:\s+(?P<user>\S+)\s*:\s*(?:user NOT in sudoers\s*;\s*)?TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<cmd>.*)")
UFW_BLOCK = re.compile(r"\[UFW BLOCK\].*?SRC=(?P<ip>\S+).*?DST=(?P<dst>\S+).*?PROTO=(?P<proto>\S+).*?DPT=(?P<dpt>\d+)")

# Web log pattern (Combined / Common / Nginx / Apache)
WEB_COMBINED = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>\w+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)'
)


def parse_timestamp(raw_text: str) -> Optional[datetime]:
    """Parse various log timestamp formats into a datetime object."""
    m = WEB_BRACKET_TIME_REGEX.search(raw_text)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    m = ISO_TIME_REGEX.search(raw_text)
    if m:
        try:
            t_str = m.group(1).replace("T", " ")
            return datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    m = WEB_APACHE_TIME_REGEX.search(raw_text)
    if m:
        t_str = m.group(1).split()[0]
        try:
            return datetime.strptime(t_str, "%d/%b/%Y:%H:%M:%S")
        except Exception:
            pass

    m = SYSLOG_TIME_REGEX.search(raw_text)
    if m:
        try:
            curr_year = datetime.now().year
            return datetime.strptime(f"{curr_year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        except Exception:
            pass

    return None


def parse_log_line(line: str, filename: str) -> Optional[Dict]:
    """Extract structured fields including host, IP, user, and severity."""
    clean_line = line.strip()
    if not clean_line or clean_line.startswith("#"):
        return None

    timestamp = parse_timestamp(clean_line)
    if not timestamp:
        timestamp = datetime.now()

    # Default values
    ip = "-"
    user = "-"
    severity = "INFO"
    action = "Log Event"
    details = clean_line

    # Host extraction
    host = "srv-prod-01"
    host_match = SYSLOG_HOST_REGEX.search(clean_line)
    if host_match:
        host = host_match.group("host")
    elif "web" in filename.lower() or "nginx" in filename.lower() or "apache" in filename.lower():
        host = "web-prod-01"

    # 1. Check Web Combined Log Format
    web_match = WEB_COMBINED.search(clean_line)
    if web_match:
        ip = web_match.group("ip")
        raw_user = web_match.group("user")
        user = raw_user if raw_user != "-" else "-"
        method = web_match.group("method")
        path = web_match.group("path")
        status = int(web_match.group("status"))

        action = f"HTTP {method}"
        details = f"{method} {path} -> {status}"

        suspicious_keywords = ["' or '", "union select", "../", "wp-config", ".env", "shell.php", "/etc/shadow", "sqlmap"]
        is_suspicious_path = any(kw in path.lower() for kw in suspicious_keywords)

        if is_suspicious_path:
            severity = "CRITICAL"
            action = f"Web Exploit Probe ({method})"
        elif status >= 500:
            severity = "HIGH"
        elif status == 401:
            severity = "WARNING"
            action = "Web Auth Failed"
        elif status == 403:
            severity = "WARNING"
            action = "Web Access Forbidden"
        elif "/backup" in path.lower() and status == 200:
            severity = "HIGH"
            action = "Sensitive Download"
        else:
            severity = "INFO"

        return {
            "timestamp": timestamp,
            "host": host,
            "source_file": filename,
            "ip_address": ip,
            "username": user,
            "severity": severity,
            "action": action,
            "details": details,
            "raw_log": clean_line,
        }

    # 2. Check SSH Failed
    m = SSHD_FAILED.search(clean_line)
    if m:
        return {
            "timestamp": timestamp,
            "host": host,
            "source_file": filename,
            "ip_address": m.group("ip"),
            "username": m.group("user"),
            "severity": "HIGH",
            "action": "SSH Login Failed",
            "details": f"Failed password for user '{m.group('user')}' from {m.group('ip')}:{m.group('port')}",
            "raw_log": clean_line,
        }

    # 3. Check SSH Accepted
    m = SSHD_ACCEPTED.search(clean_line)
    if m:
        return {
            "timestamp": timestamp,
            "host": host,
            "source_file": filename,
            "ip_address": m.group("ip"),
            "username": m.group("user"),
            "severity": "INFO",
            "action": "SSH Login Success",
            "details": f"Accepted authentication for '{m.group('user')}' from {m.group('ip')}:{m.group('port')}",
            "raw_log": clean_line,
        }

    # 4. Check SSH Disconnect
    m = SSHD_DISCONN.search(clean_line)
    if m:
        return {
            "timestamp": timestamp,
            "host": host,
            "source_file": filename,
            "ip_address": m.group("ip"),
            "username": "-",
            "severity": "INFO",
            "action": "SSH Disconnect",
            "details": f"SSH connection closed/disconnected by {m.group('ip')}",
            "raw_log": clean_line,
        }

    # 5. Check Sudo Execution
    m = SUDO_CMD.search(clean_line)
    if m:
        caller = m.group("user")
        target = m.group("target")
        cmd = m.group("cmd")
        is_unauthorized = "user not in sudoers" in clean_line.lower()

        if is_unauthorized:
            sev = "CRITICAL"
            act = "Unauthorized Sudo Attempt"
        elif "bash" in cmd or "sh" in cmd or "/etc/" in cmd:
            sev = "HIGH"
            act = "Privilege Escalation (Shell/Root)"
        else:
            sev = "WARNING"
            act = "Sudo Command Executed"

        return {
            "timestamp": timestamp,
            "host": host,
            "source_file": filename,
            "ip_address": "-",
            "username": caller,
            "severity": sev,
            "action": act,
            "details": f"User '{caller}' executed '{cmd}' as '{target}' (PWD={m.group('pwd')})",
            "raw_log": clean_line,
        }

    # 6. Check Firewall / UFW
    m = UFW_BLOCK.search(clean_line)
    if m:
        return {
            "timestamp": timestamp,
            "host": host,
            "source_file": filename,
            "ip_address": m.group("ip"),
            "username": "-",
            "severity": "WARNING",
            "action": f"Firewall Drop (Port {m.group('dpt')})",
            "details": f"UFW blocked incoming {m.group('proto')} traffic from {m.group('ip')} to port {m.group('dpt')}",
            "raw_log": clean_line,
        }

    # 7. Generic Fallback Parser
    ip_match = IPV4_REGEX.search(clean_line)
    if ip_match:
        ip = ip_match.group(0)

    user_match = re.search(r"(?:user|for user|USER)\s*[:= ]\s*['\"]?(\w+)['\"]?", clean_line, re.IGNORECASE)
    if user_match:
        user = user_match.group(1)

    low = clean_line.lower()
    if any(k in low for k in ["crit", "alert", "emerg", "exploit", "unauthorized"]):
        severity = "CRITICAL"
        action = "Critical Alert"
    elif any(k in low for k in ["error", "fail", "denied", "block", "rejected"]):
        severity = "HIGH"
        action = "Error / Security Failure"
    elif any(k in low for k in ["warn", "timeout", "retry"]):
        severity = "WARNING"
        action = "Warning Event"
    else:
        severity = "INFO"
        action = "System Message"

    return {
        "timestamp": timestamp,
        "host": host,
        "source_file": filename,
        "ip_address": ip,
        "username": user,
        "severity": severity,
        "action": action,
        "details": clean_line[:120],
        "raw_log": clean_line,
    }


def parse_log_files(files_data: List[Tuple[str, str]]) -> pd.DataFrame:
    """Parse multiple log files into a unified pandas DataFrame."""
    records = []
    for filename, content in files_data:
        lines = content.splitlines()
        for line in lines:
            parsed = parse_log_line(line, filename)
            if parsed:
                records.append(parsed)

    if not records:
        return pd.DataFrame(
            columns=["event_id", "timestamp", "host", "source_file", "ip_address", "username", "severity", "action", "details", "tag", "notes", "raw_log"]
        )

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(by="timestamp", ascending=True).reset_index(drop=True)
    df.insert(0, "event_id", [f"EVT-{i+1:04d}" for i in range(len(df))])
    df["tag"] = "Untagged"
    df["notes"] = ""
    return df


# ---------------------------------------------------------
# Geo-IP Resolution Engine
# ---------------------------------------------------------
def lookup_geo_ip(ip: str) -> Optional[Dict[str, Any]]:
    """
    Resolve an IP to geographical coordinates and threat classification.
    Includes built-in mappings for RFC-1918 private LANs, threat telemetry sample IPs,
    and a deterministic regional hub assignment for any arbitrary public IP.
    """
    if not ip or ip == "-":
        return None

    # 1. Private RFC-1918 / Loopback
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16.") or ip.startswith("127."):
        if ip == "10.0.0.15":
            return {
                "ip": ip,
                "city": "Internal Backup Datacenter",
                "country": "Internal LAN",
                "lat": 39.0438,
                "lon": -77.4874,  # Ashburn, VA
                "location_type": "Internal Agent (LAN)",
                "is_internal": True,
            }
        return {
            "ip": ip,
            "city": "Corporate HQ (Internal LAN)",
            "country": "Internal LAN",
            "lat": 37.7749,
            "lon": -122.4194,  # San Francisco, CA
            "location_type": "Internal Host / User (LAN)",
            "is_internal": True,
        }

    # 2. Known Threat Intelligence / Sample External IPs
    KNOWN_EXTERNAL = {
        "198.51.100.23": {
            "city": "Frankfurt",
            "country": "Germany",
            "lat": 50.1109,
            "lon": 8.6821,
            "location_type": "External Threat Actor (Brute Force / Exfiltration)",
            "is_internal": False,
        },
        "203.0.113.88": {
            "city": "Tokyo",
            "country": "Japan",
            "lat": 35.6762,
            "lon": 139.6503,
            "location_type": "External Port Scanner (Reconnaissance)",
            "is_internal": False,
        },
    }

    if ip in KNOWN_EXTERNAL:
        res = dict(KNOWN_EXTERNAL[ip])
        res["ip"] = ip
        return res

    # 3. Deterministic fallback for any other arbitrary uploaded public IP
    GLOBAL_HUBS = [
        ("London", "United Kingdom", 51.5074, -0.1278),
        ("Amsterdam", "Netherlands", 52.3676, 4.9041),
        ("Singapore", "Singapore", 1.3521, 103.8198),
        ("Sydney", "Australia", -33.8688, 151.2093),
        ("São Paulo", "Brazil", -23.5505, -46.6333),
        ("Toronto", "Canada", 43.6532, -79.3832),
        ("Seoul", "South Korea", 37.5665, 126.9780),
        ("Paris", "France", 48.8566, 2.3522),
        ("Mumbai", "India", 19.0760, 72.8777),
        ("Stockholm", "Sweden", 59.3293, 18.0686),
    ]
    ip_parts = [int(p) for p in ip.split(".") if p.isdigit()]
    idx = sum(ip_parts) % len(GLOBAL_HUBS)
    hub = GLOBAL_HUBS[idx]

    return {
        "ip": ip,
        "city": hub[0],
        "country": hub[1],
        "lat": hub[2],
        "lon": hub[3],
        "location_type": "External Public IP",
        "is_internal": False,
    }


def build_geo_ip_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate event telemetry by IP address with Geo-IP coordinates."""
    unique_ips = [ip for ip in df["ip_address"].unique() if ip != "-"]
    rows = []

    for ip in unique_ips:
        geo = lookup_geo_ip(ip)
        if not geo:
            continue

        ip_events = df[df["ip_address"] == ip]
        event_count = len(ip_events)
        users = [u for u in ip_events["username"].unique() if u != "-"]
        users_str = ", ".join(users) if users else "None"

        # Calculate threat classification
        severities = ip_events["severity"].tolist()
        if "CRITICAL" in severities:
            threat = "CRITICAL"
        elif "HIGH" in severities:
            threat = "HIGH"
        elif "WARNING" in severities:
            threat = "WARNING"
        elif geo["is_internal"]:
            threat = "INTERNAL"
        else:
            threat = "INFO"

        rows.append({
            "ip": ip,
            "city": geo["city"],
            "country": geo["country"],
            "lat": geo["lat"],
            "lon": geo["lon"],
            "location_type": geo["location_type"],
            "is_internal": geo["is_internal"],
            "threat_level": threat,
            "event_count": event_count,
            "associated_users": users_str,
            "sample_action": ip_events["action"].iloc[0],
        })

    return pd.DataFrame(rows)


# ---------------------------------------------------------
# Entity Relationship Graph Builder
# ---------------------------------------------------------
def build_entity_graph(df: pd.DataFrame, focus_entity: Optional[str] = None) -> Tuple[go.Figure, Dict[str, Any]]:
    """Build an interactive NetworkX + Plotly relationship graph linking IPs, Usernames, and Hosts."""
    G = nx.Graph()

    for _, row in df.iterrows():
        ip = row["ip_address"]
        user = row["username"]
        host = row.get("host", "srv-prod-01")
        sev = row["severity"]

        # 1. Host Node
        if host and host != "-":
            if not G.has_node(host):
                G.add_node(host, entity_type="Host", events=0, highest_sev="INFO")
            G.nodes[host]["events"] += 1

        # 2. IP Node
        if ip and ip != "-":
            if not G.has_node(ip):
                G.add_node(ip, entity_type="IP", events=0, highest_sev="INFO")
            G.nodes[ip]["events"] += 1
            if sev in ["CRITICAL", "HIGH"]:
                G.nodes[ip]["highest_sev"] = sev

            # Edge IP <-> Host
            if host and host != "-":
                if G.has_edge(ip, host):
                    G[ip][host]["weight"] += 1
                else:
                    G.add_edge(ip, host, weight=1, relation="Traffic / Attack")

        # 3. User Node
        if user and user != "-":
            if not G.has_node(user):
                G.add_node(user, entity_type="User", events=0, highest_sev="INFO")
            G.nodes[user]["events"] += 1
            if sev in ["CRITICAL", "HIGH"]:
                G.nodes[user]["highest_sev"] = sev

            # Edge User <-> Host
            if host and host != "-":
                if G.has_edge(user, host):
                    G[user][host]["weight"] += 1
                else:
                    G.add_edge(user, host, weight=1, relation="Session / Exec")

            # Edge IP <-> User
            if ip and ip != "-":
                if G.has_edge(ip, user):
                    G[ip][user]["weight"] += 1
                else:
                    G.add_edge(ip, user, weight=1, relation="Auth / Identity")

    # If an entity is focused, extract ego network (1-hop neighbors)
    if focus_entity and focus_entity != "All Entities" and focus_entity in G:
        neighbors = list(G.neighbors(focus_entity)) + [focus_entity]
        G = G.subgraph(neighbors).copy()

    stats = {
        "total_nodes": len(G.nodes),
        "total_edges": len(G.edges),
        "hosts": len([n for n, d in G.nodes(data=True) if d.get("entity_type") == "Host"]),
        "ips": len([n for n, d in G.nodes(data=True) if d.get("entity_type") == "IP"]),
        "users": len([n for n, d in G.nodes(data=True) if d.get("entity_type") == "User"]),
    }

    if len(G.nodes) == 0:
        fig = go.Figure()
        fig.update_layout(title="No entity nodes available.")
        return fig, stats

    # Compute spring layout
    pos = nx.spring_layout(G, k=1.1, seed=42, iterations=100)

    # Build Edges trace
    edge_x = []
    edge_y = []
    edge_weights = []

    for u, v, data in G.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        edge_weights.append(data.get("weight", 1))

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1.8, color="#64748b"),
        hoverinfo="none",
        mode="lines",
        showlegend=False,
    )

    # Build Node traces by category
    node_configs = [
        ("Host", "🖥️ Hosts", "#10b981", "square", 30),
        ("IP", "🌐 IP Addresses", "#ef4444", "circle", 24),
        ("User", "👤 User Accounts", "#a855f7", "triangle-up", 22),
    ]

    traces = [edge_trace]

    for n_type, display_name, base_color, symbol, size in node_configs:
        sub_nodes = [n for n, d in G.nodes(data=True) if d.get("entity_type") == n_type]
        if not sub_nodes:
            continue

        x_pts = []
        y_pts = []
        hover_texts = []
        labels = []
        colors = []

        for node_id in sub_nodes:
            x, y = pos[node_id]
            x_pts.append(x)
            y_pts.append(y)
            labels.append(node_id)

            data = G.nodes[node_id]
            degree = G.degree(node_id)
            ev_count = data.get("events", 0)
            h_sev = data.get("highest_sev", "INFO")

            # Dynamic node coloring
            if n_type == "IP":
                if node_id.startswith("192.168.") or node_id.startswith("10.") or node_id.startswith("172."):
                    node_col = "#3b82f6"  # Internal LAN (Blue)
                else:
                    node_col = "#ef4444"  # External Attacker (Red)
            elif n_type == "User":
                if h_sev in ["CRITICAL", "HIGH"]:
                    node_col = "#f97316"  # Compromised / Targeted (Orange)
                else:
                    node_col = "#a855f7"  # Benign User (Purple)
            else:
                node_col = base_color

            colors.append(node_col)

            htext = (
                f"<b>{n_type}: {node_id}</b><br>"
                f"Direct Links: {degree}<br>"
                f"Total Events: {ev_count}<br>"
                f"Highest Severity: {h_sev}"
            )
            hover_texts.append(htext)

        trace = go.Scatter(
            x=x_pts,
            y=y_pts,
            mode="markers+text",
            name=display_name,
            marker=dict(
                symbol=symbol,
                size=size,
                color=colors,
                line=dict(width=2, color="#ffffff"),
            ),
            text=labels,
            textposition="top center",
            textfont=dict(color="#f8fafc", size=11),
            hoverinfo="text",
            hovertext=hover_texts,
        )
        traces.append(trace)

    fig = go.Figure(data=traces)
    fig.update_layout(
        title="🕸️ Entity Relationship Network (IPs ⟷ Users ⟷ Hosts)",
        title_font=dict(size=18, color="#f8fafc"),
        paper_bgcolor="#0b1329",
        plot_bgcolor="#0b1329",
        hovermode="closest",
        margin=dict(b=20, l=20, r=20, t=50),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            font=dict(color="#f8fafc"),
        ),
        height=580,
    )

    return fig, stats


# ---------------------------------------------------------
# Streamlit Application Execution
# ---------------------------------------------------------
def main():
    # Session State Initialization
    if "events_df" not in st.session_state:
        st.session_state.events_df = None

    if "selected_ip" not in st.session_state:
        st.session_state.selected_ip = "All IPs"

    if "selected_user" not in st.session_state:
        st.session_state.selected_user = "All Users"

    if "focal_timestamp" not in st.session_state:
        st.session_state.focal_timestamp = None

    if "time_window_mins" not in st.session_state:
        st.session_state.time_window_mins = 5

    # ---------------------------------------------------------
    # Sidebar: Ingestion & Controls
    # ---------------------------------------------------------
    with st.sidebar:
        st.title("🛡️ SIEM Ingestion")
        st.caption("Upload multiple logs or test with pre-built multi-source attack telemetry.")

        uploaded_files = st.file_uploader(
            "Upload .log or .txt files",
            type=["log", "txt", "csv", "json"],
            accept_multiple_files=True,
            help="Upload multiple log files (e.g. auth.log, nginx access.log, syslog).",
        )

        col_b1, col_b2 = st.columns(2)
        load_samples = col_b1.button("⚡ Load Samples", use_container_width=True)
        clear_data = col_b2.button("🗑️ Reset", use_container_width=True)

        if clear_data:
            st.session_state.events_df = None
            st.session_state.selected_ip = "All IPs"
            st.session_state.selected_user = "All Users"
            st.session_state.focal_timestamp = None
            st.rerun()

        # Handle Sample Logs Button
        if load_samples:
            sample_filenames = ["sample_auth.log", "sample_web.log"]
            loaded = []
            script_dir = os.path.dirname(os.path.abspath(__file__))
            for s_file in sample_filenames:
                possible_paths = [
                    s_file,
                    os.path.join(script_dir, s_file),
                ]
                for p in possible_paths:
                    if os.path.exists(p):
                        with open(p, "r", encoding="utf-8", errors="ignore") as f:
                            loaded.append((s_file, f.read()))
                        break

            if loaded:
                st.session_state.events_df = parse_log_files(loaded)
                st.session_state.selected_ip = "All IPs"
                st.session_state.selected_user = "All Users"
                st.session_state.focal_timestamp = None
                st.success(f"Loaded {len(loaded)} sample log files!")
                st.rerun()
            else:
                st.error("Sample log files not found in the project folder!")

        # Handle File Upload
        if uploaded_files:
            files_data = []
            for uf in uploaded_files:
                text = uf.getvalue().decode("utf-8", errors="ignore")
                files_data.append((uf.name, text))
            new_df = parse_log_files(files_data)
            # Preserve tags/notes if matching logs already exist
            if st.session_state.events_df is not None and not st.session_state.events_df.empty:
                old_map = st.session_state.events_df.set_index("raw_log")[["tag", "notes"]].to_dict("index")
                for idx, row in new_df.iterrows():
                    if row["raw_log"] in old_map:
                        new_df.at[idx, "tag"] = old_map[row["raw_log"]]["tag"]
                        new_df.at[idx, "notes"] = old_map[row["raw_log"]]["notes"]
            st.session_state.events_df = new_df

        st.divider()
        st.subheader("⚙️ Correlation Window")
        time_window = st.slider(
            "Time Proximity (± Minutes)",
            min_value=1,
            max_value=30,
            value=st.session_state.time_window_mins,
            step=1,
            help="When an IP or user is selected, all events within ±N minutes of that activity are highlighted across all logs.",
        )
        st.session_state.time_window_mins = time_window

        st.markdown("---")
        st.markdown(
            """
            **SIEM Features Active:**
            * 📈 **Timeline**: Chronological multi-log histogram.
            * 🌍 **Geo-IP Map**: `scatter_geo` attack origins.
            * 🕸️ **Entity Graph**: Visual IPs ⟷ Users ⟷ Hosts graph.
            * 📋 **Triage Table**: In-table tagging and notes.
            """
        )

    # ---------------------------------------------------------
    # Main Header & Empty State
    # ---------------------------------------------------------
    st.title("🛡️ Mini SIEM & Security Event Correlator")
    st.caption("Unified multi-log timeline, Geo-IP threat mapping, relational graph intelligence, and incident triage.")

    df = st.session_state.events_df

    if df is None or df.empty:
        st.info("👋 **Welcome to your Mini SIEM Dashboard!** Upload log files from the sidebar, or click below to load sample attack data.")
        col_c1, _ = st.columns([1, 2])
        if col_c1.button("⚡ Click to Load Sample Attack Logs Now", type="primary", use_container_width=True):
            sample_filenames = ["sample_auth.log", "sample_web.log"]
            loaded = []
            script_dir = os.path.dirname(os.path.abspath(__file__))
            for s_file in sample_filenames:
                for p in [s_file, os.path.join(script_dir, s_file)]:
                    if os.path.exists(p):
                        with open(p, "r", encoding="utf-8", errors="ignore") as f:
                            loaded.append((s_file, f.read()))
                        break
            if loaded:
                st.session_state.events_df = parse_log_files(loaded)
                st.rerun()

        st.markdown(
            """
            ---
            ### 🔍 Included Threat Telemetry Scenario:
            * **`sample_auth.log`**: External SSH brute force (`198.51.100.23`), unauthorized sudo shadow file read (`david`), and firewall drops (`203.0.113.88`).
            * **`sample_web.log`**: SQL injection probe (`sqlmap`), admin login brute force, and sensitive database dump exfiltration.
            * **Correlated Story**: Switch between the **Timeline**, **Geo-IP Attack Map**, and **Entity Relationship Graph** to see how the attacker moves across systems!
            """
        )
        return

    # ---------------------------------------------------------
    # Global KPI Metrics Banner
    # ---------------------------------------------------------
    total_events = len(df)
    distinct_ips = len([ip for ip in df["ip_address"].unique() if ip != "-"])
    distinct_users = len([u for u in df["username"].unique() if u != "-"])
    distinct_hosts = len([h for h in df["host"].unique() if h != "-"])
    critical_count = len(df[df["severity"].isin(["CRITICAL", "HIGH"])])

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.markdown(f"<div class='kpi-card'><div class='kpi-title'>Total Events</div><div class='kpi-value'>{total_events:,}</div></div>", unsafe_allow_html=True)
    k2.markdown(f"<div class='kpi-card'><div class='kpi-title'>Distinct IPs</div><div class='kpi-value'>{distinct_ips}</div></div>", unsafe_allow_html=True)
    k3.markdown(f"<div class='kpi-card'><div class='kpi-title'>Active Users</div><div class='kpi-value'>{distinct_users}</div></div>", unsafe_allow_html=True)
    k4.markdown(f"<div class='kpi-card'><div class='kpi-title'>Target Hosts</div><div class='kpi-value'>{distinct_hosts}</div></div>", unsafe_allow_html=True)
    k5.markdown(f"<div class='kpi-card'><div class='kpi-title'>High / Critical</div><div class='kpi-value' style='color:#dc2626;'>{critical_count}</div></div>", unsafe_allow_html=True)

    st.write("")

    # ---------------------------------------------------------
    # Tab Navigation
    # ---------------------------------------------------------
    tab_timeline, tab_geomap, tab_graph, tab_table = st.tabs([
        "📈 Overview & Timeline",
        "🌍 Geo-IP Attack Map",
        "🕸️ Entity Relationship Graph",
        "📋 Triage Table & Export",
    ])

    # =========================================================
    # TAB 1: Overview, Automated Detections & Timeline
    # =========================================================
    with tab_timeline:
        st.subheader("🚨 Automated Threat Detection Rules")
        t_col1, t_col2 = st.columns(2)

        with t_col1:
            failed_logins = df[df["action"] == "SSH Login Failed"]
            ip_fail_counts = failed_logins["ip_address"].value_counts()
            brute_ips = ip_fail_counts[ip_fail_counts >= 3].to_dict()

            if brute_ips:
                for b_ip, count in brute_ips.items():
                    st.markdown(
                        f"""
                        <div class='threat-card'>
                            <b>🚨 SSH Brute Force Detected</b><br/>
                            IP <code>{b_ip}</code> generated <b>{count} failed login attempts</b> in rapid succession.
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    if st.button(f"🔍 Pivot & Correlate Attacker `{b_ip}`", key=f"btn_brute_{b_ip}"):
                        st.session_state.selected_ip = b_ip
                        st.session_state.selected_user = "All Users"
                        st.session_state.focal_timestamp = failed_logins[failed_logins["ip_address"] == b_ip]["timestamp"].min()
                        st.rerun()
            else:
                st.success("✅ No SSH Brute Force patterns detected.")

        with t_col2:
            crit_events = df[df["severity"] == "CRITICAL"]
            if not crit_events.empty:
                for _, crit_row in crit_events.iterrows():
                    st.markdown(
                        f"""
                        <div class='threat-card'>
                            <b>⚠️ {crit_row['action']}</b> ({crit_row['source_file']})<br/>
                            <code>{crit_row['details']}</code>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    c_ip = crit_row["ip_address"] if crit_row["ip_address"] != "-" else None
                    c_user = crit_row["username"] if crit_row["username"] != "-" else None
                    label = f"🎯 Investigate {c_ip or c_user or crit_row['event_id']}"
                    if st.button(label, key=f"btn_crit_{crit_row['event_id']}"):
                        if c_ip:
                            st.session_state.selected_ip = c_ip
                        if c_user:
                            st.session_state.selected_user = c_user
                        st.session_state.focal_timestamp = crit_row["timestamp"]
                        st.rerun()
            else:
                st.success("✅ No critical web exploits or unauthorized root executions found.")

        st.divider()

        # Altair Unified Timeline
        st.subheader("📊 Unified Multi-Log Timeline Histogram")
        timeline_df = df.copy()
        timeline_df["minute"] = timeline_df["timestamp"].dt.floor("1min")
        grouped_timeline = (
            timeline_df.groupby(["minute", "severity", "source_file"]).size().reset_index(name="event_count")
        )

        color_scale = alt.Scale(
            domain=["INFO", "WARNING", "HIGH", "CRITICAL"],
            range=["#38bdf8", "#facc15", "#fb923c", "#ef4444"],
        )

        chart = (
            alt.Chart(grouped_timeline)
            .mark_bar(size=14)
            .encode(
                x=alt.X("minute:T", title="Timeline (1-Minute Intervals)", axis=alt.Axis(format="%H:%M:%S")),
                y=alt.Y("event_count:Q", title="Events"),
                color=alt.Color("severity:N", scale=color_scale, title="Severity"),
                tooltip=["minute:T", "source_file:N", "severity:N", "event_count:Q"],
            )
            .properties(height=230)
            .interactive()
        )
        st.altair_chart(chart, use_container_width=True)

        # Entity Click-to-Pivot Quick Chips
        st.subheader("🔗 Quick Pivot by Entity")
        st.caption("Click any IP or username below to isolate and correlate all events occurring within the proximity time window:")

        unique_ips = [ip for ip in df["ip_address"].unique() if ip != "-"]
        unique_users = [u for u in df["username"].unique() if u != "-"]

        chip_cols = st.columns(max(len(unique_ips) + len(unique_users) + 1, 6))
        c_idx = 0

        if chip_cols[c_idx].button("🔄 View All", key="chip_all_t1", use_container_width=True):
            st.session_state.selected_ip = "All IPs"
            st.session_state.selected_user = "All Users"
            st.session_state.focal_timestamp = None
            st.rerun()
        c_idx += 1

        for ip_val in unique_ips:
            if c_idx < len(chip_cols):
                is_active = (st.session_state.selected_ip == ip_val)
                label = f"🌐 {ip_val}" + (" (Active)" if is_active else "")
                if chip_cols[c_idx].button(label, key=f"chip_ip_t1_{ip_val}", use_container_width=True):
                    st.session_state.selected_ip = ip_val
                    st.session_state.selected_user = "All Users"
                    st.session_state.focal_timestamp = df[df["ip_address"] == ip_val]["timestamp"].iloc[0]
                    st.rerun()
                c_idx += 1

        for u_val in unique_users:
            if c_idx < len(chip_cols):
                is_active = (st.session_state.selected_user == u_val)
                label = f"👤 {u_val}" + (" (Active)" if is_active else "")
                if chip_cols[c_idx].button(label, key=f"chip_user_t1_{u_val}", use_container_width=True):
                    st.session_state.selected_user = u_val
                    st.session_state.selected_ip = "All IPs"
                    st.session_state.focal_timestamp = df[df["username"] == u_val]["timestamp"].iloc[0]
                    st.rerun()
                c_idx += 1

        # Correlated Incident Progression Chain
        is_entity_focused = (st.session_state.selected_ip != "All IPs") or (st.session_state.selected_user != "All Users")
        if is_entity_focused:
            entity_matches = pd.Series([False] * len(df), index=df.index)
            if st.session_state.selected_ip != "All IPs":
                entity_matches = entity_matches | (df["ip_address"] == st.session_state.selected_ip)
            if st.session_state.selected_user != "All Users":
                entity_matches = entity_matches | (df["username"] == st.session_state.selected_user)

            target_events = df[entity_matches]
            if not target_events.empty:
                if st.session_state.focal_timestamp is not None:
                    pivot_time = pd.to_datetime(st.session_state.focal_timestamp)
                else:
                    pivot_time = target_events["timestamp"].iloc[0]

                window_delta = timedelta(minutes=st.session_state.time_window_mins)
                t_start = pivot_time - window_delta
                t_end = pivot_time + window_delta

                linked_mask = entity_matches & (df["timestamp"] >= t_start) & (df["timestamp"] <= t_end)
                correlated_events = df[linked_mask].sort_values(by="timestamp")

                entity_desc = []
                if st.session_state.selected_ip != "All IPs":
                    entity_desc.append(f"IP: <b>{st.session_state.selected_ip}</b>")
                if st.session_state.selected_user != "All Users":
                    entity_desc.append(f"User: <b>{st.session_state.selected_user}</b>")

                st.markdown(
                    f"""
                    <div class="linked-banner">
                        <h4 style="margin: 0 0 6px 0;">🎯 Correlated Incident Chain for {' & '.join(entity_desc)}</h4>
                        <span>Time Window: <b>{t_start.strftime('%H:%M:%S')}</b> to <b>{t_end.strftime('%H:%M:%S')}</b> (±{st.session_state.time_window_mins} mins). 
                        Found <b>{len(correlated_events)} linked event(s)</b> across <b>{correlated_events['source_file'].nunique()} log source(s)</b>.</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                with st.expander("🔍 Step-by-Step Chronological Attack Narrative", expanded=True):
                    for _, cev in correlated_events.iterrows():
                        b_cls = f"badge-{cev['severity'].lower()}"
                        t_str = cev["timestamp"].strftime("%H:%M:%S")
                        st.markdown(
                            f"**`{t_str}`** &nbsp;|&nbsp; `{cev['source_file']}` &nbsp;|&nbsp; "
                            f"<span class='{b_cls}'>{cev['severity']}</span> &nbsp;|&nbsp; "
                            f"**{cev['action']}** &nbsp;|&nbsp; `{cev['details']}`",
                            unsafe_allow_html=True,
                        )

    # =========================================================
    # TAB 2: Geo-IP Attack Map (plotly.express.scatter_geo)
    # =========================================================
    with tab_geomap:
        st.subheader("🌍 Geo-IP Attack Origin Map")
        st.caption("Interactive global attack origin visualization built with Plotly `scatter_geo`.")

        geo_df = build_geo_ip_dataframe(df)

        if geo_df.empty:
            st.info("No IP addresses found in the current log telemetry.")
        else:
            # Map Controls
            map_c1, map_c2 = st.columns([3, 1])
            projection_choice = map_c2.selectbox(
                "Map Projection",
                ["natural earth", "equirectangular", "orthographic", "mercator"],
                index=0,
            )

            # Render scatter_geo
            fig_map = px.scatter_geo(
                geo_df,
                lat="lat",
                lon="lon",
                hover_name="ip",
                size="event_count",
                color="threat_level",
                color_discrete_map={
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "WARNING": "#eab308",
                    "INFO": "#06b6d4",
                    "INTERNAL": "#3b82f6",
                },
                hover_data={
                    "city": True,
                    "country": True,
                    "threat_level": True,
                    "event_count": True,
                    "associated_users": True,
                    "sample_action": True,
                    "lat": False,
                    "lon": False,
                },
                projection=projection_choice,
                size_max=32,
            )

            fig_map.update_geos(
                showcountries=True,
                countrycolor="#334155",
                showcoastlines=True,
                coastlinecolor="#475569",
                showland=True,
                landcolor="#1e293b",
                showocean=True,
                oceancolor="#0b1329",
                bgcolor="#0b1329",
            )

            fig_map.update_layout(
                paper_bgcolor="#0b1329",
                plot_bgcolor="#0b1329",
                font=dict(color="#f8fafc"),
                margin=dict(l=0, r=0, t=20, b=10),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.12,
                    xanchor="center",
                    x=0.5,
                    title="Threat Level",
                    font=dict(color="#f8fafc"),
                ),
                height=520,
            )

            st.plotly_chart(fig_map, use_container_width=True)

            # Geo-IP Telemetry Metrics
            ext_ips = geo_df[~geo_df["is_internal"]]
            int_ips = geo_df[geo_df["is_internal"]]
            top_country = ext_ips["country"].value_counts().index[0] if not ext_ips.empty else "None"

            gm1, gm2, gm3, gm4 = st.columns(4)
            gm1.metric("External Threat IPs", len(ext_ips))
            gm2.metric("Internal LAN Endpoints", len(int_ips))
            gm3.metric("Top Threat Country", top_country)
            gm4.metric("Mapped Locations", geo_df["city"].nunique())

            st.markdown("##### 📍 IP Geographic Attribution Table")
            display_geo = geo_df[["ip", "city", "country", "location_type", "threat_level", "event_count", "associated_users"]]

            geo_cols = st.columns([4, 1])
            geo_cols[0].dataframe(display_geo, use_container_width=True, hide_index=True)

            with geo_cols[1]:
                st.markdown("**⚡ 1-Click Pivot**")
                for _, grow in geo_df.iterrows():
                    btn_lbl = f"{grow['ip']}"
                    if st.button(f"🔍 {btn_lbl}", key=f"btn_geo_{grow['ip']}", use_container_width=True):
                        st.session_state.selected_ip = grow["ip"]
                        st.session_state.selected_user = "All Users"
                        st.session_state.focal_timestamp = df[df["ip_address"] == grow["ip"]]["timestamp"].iloc[0]
                        st.rerun()

    # =========================================================
    # TAB 3: Entity Relationship Graph (Plotly + NetworkX)
    # =========================================================
    with tab_graph:
        st.subheader("🕸️ Visual Entity Relationship Graph")
        st.caption("Multi-dimensional correlation graph linking IP Addresses ⟷ User Accounts ⟷ Target Host Systems.")

        # Entity focus filter
        all_graph_entities = ["All Entities"]
        all_graph_entities.extend(sorted([ip for ip in df["ip_address"].unique() if ip != "-"]))
        all_graph_entities.extend(sorted([u for u in df["username"].unique() if u != "-"]))
        all_graph_entities.extend(sorted([h for h in df["host"].unique() if h != "-"]))

        graph_col1, graph_col2 = st.columns([3, 1])
        chosen_focus = graph_col1.selectbox("Ego Network Focus (Isolate 1-Hop Connected Subgraph)", all_graph_entities, index=0)

        fig_graph, g_stats = build_entity_graph(df, focus_entity=chosen_focus)
        st.plotly_chart(fig_graph, use_container_width=True)

        # Graph Metrics
        g1, g2, g3, g4, g5 = st.columns(5)
        g1.metric("Total Nodes", g_stats["total_nodes"])
        g2.metric("Total Link Edges", g_stats["total_edges"])
        g3.metric("Host Systems", g_stats["hosts"])
        g4.metric("IP Endpoints", g_stats["ips"])
        g5.metric("User Identities", g_stats["users"])

        st.markdown(
            """
            **Graph Legend & Interaction Guide:**
            * 🟩 **Hosts (Green Squares)**: Target server assets (e.g. `srv-prod-01`, `web-prod-01`).
            * 🔴 **Attacker IPs (Red Circles)**: External public IP sources performing recon, brute force, or attacks.
            * 🔵 **Internal IPs (Blue Circles)**: Internal corporate endpoints or LAN backup agents.
            * 🟧 **Targeted/Compromised Users (Orange Triangles)**: Users with High/Critical security activity.
            * 🟪 **Standard Users (Purple Triangles)**: Normal system user accounts.
            * **Lines (Edges)**: Interactions between entities. Hover over any node to inspect direct connections and event counts!
            """
        )

    # =========================================================
    # TAB 4: Interactive Triage Table & Export
    # =========================================================
    with tab_table:
        st.subheader("📋 Interactive Log Table & Incident Tagging")
        st.caption(
            "💡 **Analyst Triage:** Directly edit the **'Tag'** dropdown or type into **'Analyst Notes'**. "
            "Modifications are saved immediately in memory and can be exported below."
        )

        # Table Filter Controls
        tf_col1, tf_col2, tf_col3, tf_col4 = st.columns([2, 2, 2, 1])

        avail_ips = ["All IPs"] + sorted([ip for ip in df["ip_address"].unique() if ip != "-"])
        c_ip_idx = avail_ips.index(st.session_state.selected_ip) if st.session_state.selected_ip in avail_ips else 0
        filter_ip = tf_col1.selectbox("Filter by IP", avail_ips, index=c_ip_idx, key="table_sel_ip")

        avail_users = ["All Users"] + sorted([u for u in df["username"].unique() if u != "-"])
        c_user_idx = avail_users.index(st.session_state.selected_user) if st.session_state.selected_user in avail_users else 0
        filter_user = tf_col2.selectbox("Filter by User", avail_users, index=c_user_idx, key="table_sel_user")

        chosen_sevs = tf_col3.multiselect(
            "Filter Severity",
            ["INFO", "WARNING", "HIGH", "CRITICAL"],
            default=["INFO", "WARNING", "HIGH", "CRITICAL"],
            key="table_sel_sev",
        )

        if tf_col4.button("Reset Filters", key="btn_reset_table_filters", use_container_width=True):
            st.session_state.selected_ip = "All IPs"
            st.session_state.selected_user = "All Users"
            st.session_state.focal_timestamp = None
            st.rerun()

        st.session_state.selected_ip = filter_ip
        st.session_state.selected_user = filter_user

        # Filter the DataFrame
        table_df = df.copy()
        if chosen_sevs:
            table_df = table_df[table_df["severity"].isin(chosen_sevs)]
        if filter_ip != "All IPs":
            table_df = table_df[table_df["ip_address"] == filter_ip]
        if filter_user != "All Users":
            table_df = table_df[table_df["username"] == filter_user]

        # Calculate linked mask
        is_piv = (filter_ip != "All IPs") or (filter_user != "All Users")
        correlated_idx = set()
        if is_piv:
            m_entity = pd.Series([False] * len(df), index=df.index)
            if filter_ip != "All IPs":
                m_entity = m_entity | (df["ip_address"] == filter_ip)
            if filter_user != "All Users":
                m_entity = m_entity | (df["username"] == filter_user)
            t_events = df[m_entity]
            if not t_events.empty:
                p_time = pd.to_datetime(st.session_state.focal_timestamp) if st.session_state.focal_timestamp else t_events["timestamp"].iloc[0]
                w_delta = timedelta(minutes=st.session_state.time_window_mins)
                l_mask = m_entity & (df["timestamp"] >= p_time - w_delta) & (df["timestamp"] <= p_time + w_delta)
                correlated_idx = set(df[l_mask].index)

        table_df["is_linked"] = table_df.index.isin(correlated_idx)
        table_df["Status"] = table_df.apply(
            lambda r: "🎯 LINKED" if r["is_linked"] else ("⚠️ " + r["severity"] if r["severity"] in ["CRITICAL", "HIGH"] else "ℹ️ " + r["severity"]),
            axis=1,
        )

        column_configurations = {
            "Status": st.column_config.TextColumn("Status", width="small", disabled=True),
            "event_id": st.column_config.TextColumn("ID", width="small", disabled=True),
            "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss", disabled=True),
            "host": st.column_config.TextColumn("Target Host", width="small", disabled=True),
            "source_file": st.column_config.TextColumn("Source File", width="small", disabled=True),
            "ip_address": st.column_config.TextColumn("IP Address", width="small", disabled=True),
            "username": st.column_config.TextColumn("User", width="small", disabled=True),
            "severity": st.column_config.TextColumn("Severity", width="small", disabled=True),
            "action": st.column_config.TextColumn("Event Action", width="medium", disabled=True),
            "details": st.column_config.TextColumn("Details", width="large", disabled=True),
            "tag": st.column_config.SelectboxColumn(
                "Tag",
                help="Assign investigation status to this event",
                options=["Untagged", "Investigating", "Suspicious", "Malicious", "False Positive", "Resolved"],
                required=True,
                width="medium",
            ),
            "notes": st.column_config.TextColumn(
                "Analyst Notes",
                help="Type incident response notes here",
                width="large",
            ),
        }

        cols_to_render = [
            "Status",
            "event_id",
            "timestamp",
            "host",
            "source_file",
            "ip_address",
            "username",
            "severity",
            "action",
            "details",
            "tag",
            "notes",
        ]

        edited_results = st.data_editor(
            table_df[cols_to_render],
            column_config=column_configurations,
            use_container_width=True,
            num_rows="fixed",
            key="siem_data_editor_v2",
        )

        # Sync changes back to session state DataFrame
        if edited_results is not None:
            for _, e_row in edited_results.iterrows():
                eid = e_row["event_id"]
                m_indices = df[df["event_id"] == eid].index
                if len(m_indices) > 0:
                    midx = m_indices[0]
                    st.session_state.events_df.at[midx, "tag"] = e_row["tag"]
                    st.session_state.events_df.at[midx, "notes"] = e_row["notes"]

        # Export Report Section
        st.divider()
        st.subheader("📥 Export Triage Report")

        annotated_count = len(df[df["tag"] != "Untagged"])
        exp_col1, exp_col2 = st.columns([3, 1])

        exp_col1.write(
            f"Tagged / Reviewed Events: **{annotated_count}** of **{len(df)}** total events. "
            "Export the annotated findings to CSV for your incident post-mortem or SIEM ticketing."
        )

        csv_data = df.to_csv(index=False).encode("utf-8")
        now_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exp_col2.download_button(
            label="Download Report (CSV)",
            data=csv_data,
            file_name=f"siem_incident_triage_{now_stamp}.csv",
            mime="text/csv",
            use_container_width=True,
        )


if __name__ == "__main__":
    main()

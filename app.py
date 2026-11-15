"""
Mini SIEM Dashboard
Single-file Streamlit application for security event monitoring, log correlation,
and interactive incident response tagging.
"""

import os
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
import altair as alt

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
    # 1. Bracket ISO time [2026-11-16 03:02:40]
    m = WEB_BRACKET_TIME_REGEX.search(raw_text)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    # 2. Standard ISO time: 2026-11-16 03:02:14
    m = ISO_TIME_REGEX.search(raw_text)
    if m:
        try:
            t_str = m.group(1).replace("T", " ")
            return datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            pass

    # 3. Apache/Nginx combined: 16/Nov/2026:03:02:40 +0000
    m = WEB_APACHE_TIME_REGEX.search(raw_text)
    if m:
        t_str = m.group(1).split()[0]
        try:
            return datetime.strptime(t_str, "%d/%b/%Y:%H:%M:%S")
        except Exception:
            pass

    # 4. Standard Syslog format: Nov 16 03:02:14
    m = SYSLOG_TIME_REGEX.search(raw_text)
    if m:
        try:
            curr_year = datetime.now().year
            return datetime.strptime(f"{curr_year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        except Exception:
            pass

    return None


def parse_log_line(line: str, filename: str) -> Optional[Dict]:
    """Extract structured fields from a single log line."""
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

        # Heuristic severity for web traffic
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
            columns=["event_id", "timestamp", "source_file", "ip_address", "username", "severity", "action", "details", "tag", "notes", "raw_log"]
        )

    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values(by="timestamp", ascending=True).reset_index(drop=True)
    df.insert(0, "event_id", [f"EVT-{i+1:04d}" for i in range(len(df))])
    df["tag"] = "Untagged"
    df["notes"] = ""
    return df


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
        st.caption("Upload multiple logs or test right away with sample data.")

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
            **How correlation works:**
            1. Select an **IP** or **Username** (via button, table row, or filter).
            2. The timeline highlights linked events within the chosen **time window**.
            3. Review the unified attack chain across Web, SSH, and Firewall logs!
            """
        )

    # ---------------------------------------------------------
    # Main Dashboard Header & Empty State
    # ---------------------------------------------------------
    st.title("🛡️ Mini SIEM & Security Event Correlator")
    st.caption("Unify multiple log sources into a single timeline, pivot on suspicious entities, and tag events for triage.")

    df = st.session_state.events_df

    if df is None or df.empty:
        st.info("👋 **Welcome to your Mini SIEM Dashboard!** Upload log files from the sidebar, or click below to load sample attack data.")
        col_c1, _ = st.columns([1, 2])
        if col_c1.button("⚡ Click to Load Sample Attack Logs Now", type="primary", use_container_width=True):
            # Trigger load
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
            ### 🔍 What is in the included sample data?
            * **`sample_auth.log`**: External brute force on SSH (`198.51.100.23`), unauthorized sudo shadow file read (`david`), and firewall drops (`203.0.113.88`).
            * **`sample_web.log`**: Nginx/Apache access logs showing SQL injection probing, web login brute force, and sensitive database dump exfiltration.
            * **The Story**: When you correlate by IP `198.51.100.23`, you will see web probing followed directly by SSH brute force, privilege escalation, and database theft!
            """
        )
        return

    # ---------------------------------------------------------
    # KPI Metrics Banner
    # ---------------------------------------------------------
    total_events = len(df)
    distinct_ips = len([ip for ip in df["ip_address"].unique() if ip != "-"])
    distinct_users = len([u for u in df["username"].unique() if u != "-"])
    critical_count = len(df[df["severity"].isin(["CRITICAL", "HIGH"])])
    timespan_str = (
        f"{df['timestamp'].min().strftime('%H:%M:%S')} - {df['timestamp'].max().strftime('%H:%M:%S')}"
    )

    k1, k2, k3, k4, k5 = st.columns(5)
    k1.markdown(f"<div class='kpi-card'><div class='kpi-title'>Total Events</div><div class='kpi-value'>{total_events:,}</div></div>", unsafe_allow_html=True)
    k2.markdown(f"<div class='kpi-card'><div class='kpi-title'>Distinct IPs</div><div class='kpi-value'>{distinct_ips}</div></div>", unsafe_allow_html=True)
    k3.markdown(f"<div class='kpi-card'><div class='kpi-title'>Distinct Users</div><div class='kpi-value'>{distinct_users}</div></div>", unsafe_allow_html=True)
    k4.markdown(f"<div class='kpi-card'><div class='kpi-title'>High / Critical</div><div class='kpi-value'>{critical_count}</div></div>", unsafe_allow_html=True)
    k5.markdown(f"<div class='kpi-card'><div class='kpi-title'>Time Span</div><div class='kpi-value' style='font-size:1.15rem; margin-top:10px;'>{timespan_str}</div></div>", unsafe_allow_html=True)

    st.write("")

    # ---------------------------------------------------------
    # SIEM Heuristics & Threat Detection Engine
    # ---------------------------------------------------------
    st.subheader("🚨 Automated Threat Detections")
    t_col1, t_col2 = st.columns(2)

    with t_col1:
        # Detect SSH Brute force (>2 failed logins)
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

    # ---------------------------------------------------------
    # Unified Multi-Log Timeline Chart
    # ---------------------------------------------------------
    st.subheader("📈 Unified Timeline Histogram")

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

    # ---------------------------------------------------------
    # Entity Click-to-Pivot & Filter Controls
    # ---------------------------------------------------------
    st.subheader("🔗 Click Any Entity to Highlight Linked Events")
    st.caption("Click any IP or username chip below to correlate all events occurring around that activity across every log source.")

    unique_ips = [ip for ip in df["ip_address"].unique() if ip != "-"]
    unique_users = [u for u in df["username"].unique() if u != "-"]

    # Quick Pivot Buttons (IPs and Users)
    chip_row = st.container()
    with chip_row:
        chip_cols = st.columns(max(len(unique_ips) + len(unique_users) + 1, 6))
        c_idx = 0

        # "View All" chip
        if chip_cols[c_idx].button("🔄 View All", key="chip_all", use_container_width=True):
            st.session_state.selected_ip = "All IPs"
            st.session_state.selected_user = "All Users"
            st.session_state.focal_timestamp = None
            st.rerun()
        c_idx += 1

        for ip_val in unique_ips:
            if c_idx < len(chip_cols):
                is_active = (st.session_state.selected_ip == ip_val)
                label = f"🌐 {ip_val}" + (" (Active)" if is_active else "")
                if chip_cols[c_idx].button(label, key=f"chip_ip_{ip_val}", use_container_width=True):
                    st.session_state.selected_ip = ip_val
                    st.session_state.selected_user = "All Users"
                    st.session_state.focal_timestamp = df[df["ip_address"] == ip_val]["timestamp"].iloc[0]
                    st.rerun()
                c_idx += 1

        for u_val in unique_users:
            if c_idx < len(chip_cols):
                is_active = (st.session_state.selected_user == u_val)
                label = f"👤 {u_val}" + (" (Active)" if is_active else "")
                if chip_cols[c_idx].button(label, key=f"chip_user_{u_val}", use_container_width=True):
                    st.session_state.selected_user = u_val
                    st.session_state.selected_ip = "All IPs"
                    st.session_state.selected_user_timestamp = df[df["username"] == u_val]["timestamp"].iloc[0]
                    st.session_state.focal_timestamp = df[df["username"] == u_val]["timestamp"].iloc[0]
                    st.rerun()
                c_idx += 1

    # Filter selector bar
    f_col1, f_col2, f_col3 = st.columns([2, 2, 2])

    avail_ips = ["All IPs"] + sorted(unique_ips)
    cur_ip_idx = avail_ips.index(st.session_state.selected_ip) if st.session_state.selected_ip in avail_ips else 0
    sel_ip = f_col1.selectbox("Filter IP Address", avail_ips, index=cur_ip_idx)

    avail_users = ["All Users"] + sorted(unique_users)
    cur_user_idx = avail_users.index(st.session_state.selected_user) if st.session_state.selected_user in avail_users else 0
    sel_user = f_col2.selectbox("Filter Username", avail_users, index=cur_user_idx)

    chosen_severities = f_col3.multiselect(
        "Filter Severity",
        ["INFO", "WARNING", "HIGH", "CRITICAL"],
        default=["INFO", "WARNING", "HIGH", "CRITICAL"],
    )

    st.session_state.selected_ip = sel_ip
    st.session_state.selected_user = sel_user

    # Correlation calculation
    is_entity_focused = (sel_ip != "All IPs") or (sel_user != "All Users")
    correlated_indices = set()

    if is_entity_focused:
        # Build mask for target entity
        entity_matches = pd.Series([False] * len(df), index=df.index)
        if sel_ip != "All IPs":
            entity_matches = entity_matches | (df["ip_address"] == sel_ip)
        if sel_user != "All Users":
            entity_matches = entity_matches | (df["username"] == sel_user)

        target_events = df[entity_matches]

        if not target_events.empty:
            if st.session_state.focal_timestamp is not None:
                pivot_time = pd.to_datetime(st.session_state.focal_timestamp)
            else:
                pivot_time = target_events["timestamp"].iloc[0]

            window_delta = timedelta(minutes=st.session_state.time_window_mins)
            t_start = pivot_time - window_delta
            t_end = pivot_time + window_delta

            # Events matching entity OR occurring in proximity
            linked_mask = entity_matches & (df["timestamp"] >= t_start) & (df["timestamp"] <= t_end)
            correlated_indices = set(df[linked_mask].index)
            correlated_events = df.loc[list(correlated_indices)].sort_values(by="timestamp")

            # Correlated Banner
            entity_desc = []
            if sel_ip != "All IPs":
                entity_desc.append(f"IP: <b>{sel_ip}</b>")
            if sel_user != "All Users":
                entity_desc.append(f"User: <b>{sel_user}</b>")

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

            # Attack Sequence Flow
            with st.expander("🔍 Chronological Attack Progression Flow", expanded=True):
                for _, cev in correlated_events.iterrows():
                    b_cls = f"badge-{cev['severity'].lower()}"
                    t_str = cev["timestamp"].strftime("%H:%M:%S")
                    st.markdown(
                        f"**`{t_str}`** &nbsp;|&nbsp; `{cev['source_file']}` &nbsp;|&nbsp; "
                        f"<span class='{b_cls}'>{cev['severity']}</span> &nbsp;|&nbsp; "
                        f"**{cev['action']}** &nbsp;|&nbsp; `{cev['details']}`",
                        unsafe_allow_html=True,
                    )

    # ---------------------------------------------------------
    # Interactive Table with In-line Tagging (st.data_editor)
    # ---------------------------------------------------------
    st.subheader("📋 Interactive Log Table & Incident Tagging")
    st.caption(
        "💡 **Edit directly:** Change the **'Tag'** dropdown or type into **'Analyst Notes'**. "
        "Your annotations are immediately persisted in memory and exportable."
    )

    # Filter DataFrame
    table_df = df.copy()

    if chosen_severities:
        table_df = table_df[table_df["severity"].isin(chosen_severities)]

    if sel_ip != "All IPs":
        table_df = table_df[table_df["ip_address"] == sel_ip]

    if sel_user != "All Users":
        table_df = table_df[table_df["username"] == sel_user]

    # Tag and indicator columns
    table_df["is_linked"] = table_df.index.isin(correlated_indices)
    table_df["Status"] = table_df.apply(
        lambda r: "🎯 LINKED" if r["is_linked"] else ("⚠️ " + r["severity"] if r["severity"] in ["CRITICAL", "HIGH"] else "ℹ️ " + r["severity"]),
        axis=1,
    )

    column_configurations = {
        "Status": st.column_config.TextColumn("Status", width="small", disabled=True),
        "event_id": st.column_config.TextColumn("ID", width="small", disabled=True),
        "timestamp": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss", disabled=True),
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
        key="siem_data_editor",
    )

    # Sync modifications back to master session state DataFrame
    if edited_results is not None:
        for _, e_row in edited_results.iterrows():
            eid = e_row["event_id"]
            m_indices = df[df["event_id"] == eid].index
            if len(m_indices) > 0:
                midx = m_indices[0]
                st.session_state.events_df.at[midx, "tag"] = e_row["tag"]
                st.session_state.events_df.at[midx, "notes"] = e_row["notes"]

    # ---------------------------------------------------------
    # Row Quick Selector for Correlation
    # ---------------------------------------------------------
    st.markdown("##### 🎯 Quick Pivot from Table Row")
    row_pick_col1, row_pick_col2 = st.columns([3, 1])

    event_options = [
        f"{r['event_id']} | {r['timestamp'].strftime('%H:%M:%S')} | {r['action']} | IP: {r['ip_address']} | User: {r['username']}"
        for _, r in table_df.iterrows()
    ]

    if event_options:
        selected_option = row_pick_col1.selectbox(
            "Select an event from the filtered table to pivot on its entity & timestamp:",
            event_options,
            label_visibility="collapsed",
        )
        if row_pick_col2.button("🎯 Focus Event", use_container_width=True):
            chosen_eid = selected_option.split(" | ")[0]
            matched_row = df[df["event_id"] == chosen_eid].iloc[0]
            if matched_row["ip_address"] != "-":
                st.session_state.selected_ip = matched_row["ip_address"]
            if matched_row["username"] != "-":
                st.session_state.selected_user = matched_row["username"]
            st.session_state.focal_timestamp = matched_row["timestamp"]
            st.rerun()

    # ---------------------------------------------------------
    # Incident Report Export
    # ---------------------------------------------------------
    st.divider()
    st.subheader("📥 Export Triage Report")

    annotated_count = len(df[df["tag"] != "Untagged"])
    exp_col1, exp_col2 = st.columns([3, 1])

    exp_col1.write(
        f"Tagged / Reviewed Events: **{annotated_count}** of **{len(df)}** total events. "
        "Export the annotated telemetry to CSV for your SOC incident log or executive summary."
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

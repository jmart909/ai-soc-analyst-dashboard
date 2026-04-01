import json
import pandas as pd
import streamlit as st

from log_generator import generate_logs
from detection import detect_threats
from ai_analysis import analyze_alert

st.set_page_config(page_title="AI SOC Analyst", layout="wide")

st.title("AI-Powered SOC Analyst Dashboard")
st.write("Simulates security monitoring, threat detection, and AI-based analysis.")

# -----------------------------
# Session state setup
# -----------------------------
if "logs" not in st.session_state:
    st.session_state.logs = None

if "alerts" not in st.session_state:
    st.session_state.alerts = None

if "scenario_name" not in st.session_state:
    st.session_state.scenario_name = None

# -----------------------------
# Helpers
# -----------------------------
def load_uploaded_logs(uploaded_file):
    if uploaded_file.name.endswith(".csv"):
        df = pd.read_csv(uploaded_file)
        return df.to_dict(orient="records")

    if uploaded_file.name.endswith(".json"):
        data = json.load(uploaded_file)
        if isinstance(data, list):
            return data
        raise ValueError("JSON file must contain a list of log objects.")

    raise ValueError("Unsupported file type. Please upload a CSV or JSON file.")


def build_dataframe(logs):
    df = pd.DataFrame(logs)

    if "timestamp" in df.columns:
        try:
            df["timestamp_readable"] = pd.to_datetime(df["timestamp"], unit="s")
        except Exception:
            df["timestamp_readable"] = pd.to_datetime(df["timestamp"], errors="coerce")

    return df


# -----------------------------
# Input method
# -----------------------------
input_method = st.radio(
    "Choose log source",
    ["Simulated Attack Scenario", "Upload Real Logs"]
)

if input_method == "Simulated Attack Scenario":
    if st.button("Run SOC Analysis"):
        scenario_name, logs = generate_logs()
        alerts = detect_threats(logs)

        st.session_state.logs = logs
        st.session_state.alerts = alerts
        st.session_state.scenario_name = scenario_name

else:
    uploaded_file = st.file_uploader(
        "Upload logs as CSV or JSON",
        type=["csv", "json"]
    )

    if uploaded_file is not None:
        if st.button("Analyze Uploaded Logs"):
            try:
                logs = load_uploaded_logs(uploaded_file)
                alerts = detect_threats(logs)

                st.session_state.logs = logs
                st.session_state.alerts = alerts
                st.session_state.scenario_name = "Uploaded Logs"
            except Exception as e:
                st.error(f"Could not load logs: {e}")

# -----------------------------
# Display results
# -----------------------------
logs = st.session_state.logs
alerts = st.session_state.alerts
scenario_name = st.session_state.scenario_name

if logs is not None:
    st.subheader("Selected Scenario")
    st.info(scenario_name)

    # -----------------------------
    # Metrics
    # -----------------------------
    total_logs = len(logs)
    total_alerts = len(alerts) if alerts else 0
    failed_count = len([log for log in logs if log.get("status") == "FAILED"])

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Logs", total_logs)
    col2.metric("Alerts Detected", total_alerts)
    col3.metric("Failed Logins", failed_count)

    # -----------------------------
    # Generated / Uploaded Logs
    # -----------------------------
    st.subheader("Generated Logs")
    st.json(logs)

    df = build_dataframe(logs)

    # -----------------------------
    # Attack Visualization Dashboard
    # -----------------------------
    st.subheader("Attack Visualization Dashboard")

    viz_col1, viz_col2 = st.columns(2)

    with viz_col1:
        st.markdown("### Login Status Counts")
        if "status" in df.columns:
            status_counts = df["status"].value_counts()
            st.bar_chart(status_counts)

    with viz_col2:
        st.markdown("### Activity by User")
        if "user" in df.columns:
            user_counts = df["user"].value_counts()
            st.bar_chart(user_counts)

    # -----------------------------
    # Attack Timeline
    # -----------------------------
    st.subheader("Attack Timeline")

    if "timestamp_readable" in df.columns:
        timeline_df = df.sort_values("timestamp_readable").copy()
        timeline_df["event_count"] = range(1, len(timeline_df) + 1)
        timeline_chart = timeline_df.set_index("timestamp_readable")[["event_count"]]
        st.line_chart(timeline_chart)
    else:
        st.info("No usable timestamp field found for timeline visualization.")

    # -----------------------------
    # Alerts
    # -----------------------------
    st.subheader("Detected Alerts")

    if alerts:
        for i, alert in enumerate(alerts, start=1):
            severity = alert.get("severity", "Low")

            if severity == "High":
                st.error(f"{alert['type']} - {severity}")
            elif severity == "Medium":
                st.warning(f"{alert['type']} - {severity}")
            else:
                st.success(f"{alert['type']} - {severity}")

            st.write(alert["description"])
            st.caption(f"MITRE: {alert.get('mitre_technique', 'N/A')}")

            risk = alert.get("risk_score", 0)

            if risk >= 80:
                st.error(f"Risk Score: {risk}/100 🔴")
            elif risk >= 50:
                st.warning(f"Risk Score: {risk}/100 🟡")
            else:
                st.success(f"Risk Score: {risk}/100 🟢")

            suspicious_ip = alert.get("source_ip", "Unknown")
            st.write(f"Suspicious IP: {suspicious_ip}")

            if st.button(f"🚫 Block Suspicious IP ({suspicious_ip})", key=f"block_{i}"):
                st.success(f"IP {suspicious_ip} has been blocked (simulation).")

        # -----------------------------
        # AI Analysis
        # -----------------------------
        st.subheader("AI Analysis")

        for i, alert in enumerate(alerts, start=1):
            with st.spinner(f"Analyzing alert {i}..."):
                analysis = analyze_alert(alert, logs)

            st.markdown(f"### Alert {i}")
            st.write(analysis)

    else:
        st.success("No threats detected.")
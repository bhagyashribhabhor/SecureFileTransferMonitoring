import streamlit as st
import csv
import os

st.set_page_config(
    page_title="Secure File Transfer Monitoring",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Secure File Transfer Monitoring System")

st.write(
    "Cybersecurity dashboard for monitoring file activity, "
    "risk analysis, and security events."
)

audit_file = "audit_log.csv"

# Default values
total_events = 0
high_risk = 0
medium_risk = 0
low_risk = 0

# Read real audit log if available
if os.path.exists(audit_file):

    with open(audit_file, "r", encoding="utf-8", errors="ignore") as file:

        reader = csv.DictReader(file)

        for row in reader:

            total_events += 1

            severity = str(row.get("Severity", "")).strip().upper()

            if severity == "HIGH":
                high_risk += 1

            elif severity == "MEDIUM":
                medium_risk += 1

            elif severity == "LOW":
                low_risk += 1

    demo_mode = False

else:
    # Demo values for deployed application
    total_events = 264
    high_risk = 4
    medium_risk = 3
    low_risk = 257

    demo_mode = True


st.subheader("📊 Security Dashboard")

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Events", total_events)

with col2:
    st.metric("High Risk", high_risk)

with col3:
    st.metric("Medium Risk", medium_risk)

with col4:
    st.metric("Low Risk", low_risk)


st.subheader("📋 Audit Log")

if demo_mode:
    st.info(
        "Demo Mode: Sample security statistics are displayed because "
        "the local audit log is not included in the deployed application."
    )
else:
    st.success(
        "Audit log is available with {} recorded events.".format(
            total_events
        )
    )


st.subheader("🛡️ Project Features")

features = [
    "File activity monitoring",
    "Sensitive file detection",
    "Suspicious destination detection",
    "SHA-256 file integrity verification",
    "Risk score calculation",
    "Security audit logging",
    "Security report generation"
]

for feature in features:
    st.write("• " + feature)


st.subheader("🚀 Project Status")

st.success(
    "Secure File Transfer Monitoring System is running successfully."
)
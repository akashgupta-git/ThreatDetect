import streamlit as st
import json

st.title("🚨 ThreatDetect - IDS Alerts Dashboard")

with open("../alerts/alert_log.json", "r") as f:
    alerts = [json.loads(line) for line in f.readlines()]

for alert in reversed(alerts[-20:]):
    st.error(f"🔴 {alert['message']} @ {alert['timestamp']}")
    st.write(f"From: {alert['source_ip']} ➡️ To: {alert['destination_ip']}")

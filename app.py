import streamlit as st
from detector import run_all_detections
import requests
import os
from dotenv import load_dotenv

# LOAD ENV VARIABLES
load_dotenv()

# CONFIGURATION
st.set_page_config(page_title="SOC Threat Detection Dashboard", layout="wide")

# UI HEADER 
st.markdown("<h1 style='text-align: center;'>AI-Powered Security Operations Center (SOC) Dashboard</h1>", unsafe_allow_html=True)

st.markdown("""
<p style='text-align: center; font-size:18px;'>
This dashboard provides real-time cybersecurity monitoring by combining <b>AI-powered anomaly detection</b> and <b>rule-based analysis</b>. 
It analyzes system logs to detect threats such as brute force attacks, suspicious login behavior, and unusual activity patterns, 
while also integrating <b>threat intelligence APIs</b> to perform IP reputation checks and identify potential phishing URLs.
</p>
""", unsafe_allow_html=True)

st.markdown("""
<p style='text-align: center; color:gray; font-size:14px;'>
Developed by Abhiram Reddy<br>
<a href='https://github.com/abhiramreddie' target='_blank' style='text-decoration:none; color:#00FFA6;'>
GitHub: abhiramreddie
</a>
</p>
""", unsafe_allow_html=True)

st.write("---")

# SIDEBAR
st.sidebar.header("Control Panel")

# READ LOG FILE
with open("sample_logs.txt", "r") as file:
    logs = [line.strip() for line in file.readlines()]

# LOGS ANALYZER 
if st.sidebar.button("📂 Run Logs Analyzer"):

    with st.spinner("Running AI + Rule-Based Detection..."):

        alerts = run_all_detections(logs)

        st.subheader("🚨 Alerts Generated")

        if alerts:
            for alert in alerts:
                if "[AI]" in alert:
                    st.error(alert)
                else:
                    st.warning(alert)
        else:
            st.success("No threats detected")

# -------------------- ABUSE IP CHECK FUNCTION --------------------
def check_ip_abuse(ip):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Accept": "application/json",
        "Key": os.getenv("ABUSEIPDB_API_KEY")
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()["data"]
    else:
        return None

# -------------------- IP BLACKLIST CHECK --------------------
st.sidebar.subheader("🌐 IP Blacklist Check")

ip_input = st.sidebar.text_input("Enter IP Address")

if st.sidebar.button("Check IP Reputation"):

    if ip_input:

        with st.spinner("Checking IP reputation..."):

            result = check_ip_abuse(ip_input)

            if result:
                score = result["abuseConfidenceScore"]

                if score > 50:
                    st.error(f"🚫 {ip_input} is MALICIOUS (Score: {score})")
                elif score > 20:
                    st.warning(f"⚠️ {ip_input} is SUSPICIOUS (Score: {score})")
                else:
                    st.success(f"✅ {ip_input} is SAFE (Score: {score})")

                st.write("📊 Total Reports:", result["totalReports"])
                st.write("🌍 Country:", result["countryCode"])
                st.write("🏢 ISP:", result["isp"])

            else:
                st.warning("Failed to fetch data. Check API key or internet.")

    else:
        st.warning("Please enter an IP address")

# -------------------- PHISHING URL CHECK --------------------
st.sidebar.subheader("🔗 Phishing URL Check")

url_input = st.sidebar.text_input("Enter URL")

if st.sidebar.button("Check URL Safety"):

    if url_input:

        with st.spinner("Checking URL safety..."):

            try:
                vt_url = "https://www.virustotal.com/api/v3/urls"

                headers = {
                    "x-apikey": os.getenv("PHISHING_API_KEY")
                }

                # Step 1: Submit URL
                response = requests.post(vt_url, headers=headers, data={"url": url_input})
                result = response.json()

                analysis_id = result["data"]["id"]

                # Step 2: Get Report
                report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                report = requests.get(report_url, headers=headers).json()

                stats = report["data"]["attributes"]["stats"]
                malicious = stats["malicious"]

                if malicious > 0:
                    st.error(f"⚠️ Phishing/Malicious URL detected ({malicious} engines)")
                else:
                    st.success("✅ Safe URL")

            except Exception as e:
                st.error(f"Error: {e}")

    else:
        st.warning("Please enter a URL")

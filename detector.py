from datetime import datetime
import pandas as pd
from sklearn.ensemble import IsolationForest


# Convert raw logs into structured and usable format
def parse_logs(logs):
    parsed = []

    for log in logs:
        parts = log.strip().split("|")

        if len(parts) != 5:
            continue

        try:
            time = datetime.strptime(parts[0].strip(), "%Y-%m-%d %H:%M:%S.%f")
            ip = parts[1].strip()
            user = parts[2].strip()
            country = parts[3].strip()
            status = parts[4].strip()

            parsed.append({
                "time": time,
                "ip": ip,
                "user": user,
                "country": country,
                "status": status
            })
        except:
            continue

    return parsed

# RULE-BASED DETECTION

# Brute force detection
def detect_bruteforce(parsed_logs):
    failed_count = {}
    alerts = []

    for log in parsed_logs:
        if "FAILED" in log["status"]:
            ip = log["ip"]
            failed_count[ip] = failed_count.get(ip, 0) + 1

    for ip, count in failed_count.items():
        if count >= 5:
            alerts.append(f"[RULE] Brute force attack from {ip} ({count} failed logins)")

    return alerts


# Suspicious login time (2 AM – 4 AM)
def detect_suspicious_time(parsed_logs):
    alerts = []

    for log in parsed_logs:
        hour = log["time"].hour

        if 2 <= hour <= 4:
            alerts.append(f"[RULE] Suspicious login time: {log['user']} at {log['time']}")

    return alerts


# Impossible travel time and location change
def detect_impossible_travel(parsed_logs):
    alerts = []
    last_seen = {}

    for log in parsed_logs:
        user = log["user"]
        country = log["country"]
        time = log["time"]

        if user in last_seen:
            prev_country, prev_time = last_seen[user]
            time_diff = (time - prev_time).total_seconds()

            if prev_country != country and time_diff < 60:
                alerts.append(
                    f"[RULE] Impossible travel for {user}: {prev_country} → {country}"
                )

        last_seen[user] = (country, time)

    return alerts

# AI-BASED DETECTION
def detect_anomalies(parsed_logs):
    alerts = []

    if len(parsed_logs) < 10:
        return alerts

    data = []

    for log in parsed_logs:
        ip_value = sum(int(x) for x in log["ip"].split("."))
        failed = 1 if "FAILED" in log["status"] else 0
        hour = log["time"].hour

        data.append([ip_value, failed, hour])

    df = pd.DataFrame(data, columns=["ip", "failed", "hour"])

    model = IsolationForest(contamination=0.1)
    df["anomaly"] = model.fit_predict(df)

    for i, row in df.iterrows():
        if row["anomaly"] == -1:
            log = parsed_logs[i]
            alerts.append(
                f"[AI] Anomaly: {log['user']} from {log['ip']} at {log['time']}"
            )

    return alerts

# MAIN FUNCTION
def run_all_detections(logs):
    parsed_logs = parse_logs(logs)

    alerts = []

    alerts += detect_bruteforce(parsed_logs)
    alerts += detect_suspicious_time(parsed_logs)
    alerts += detect_impossible_travel(parsed_logs)

    alerts += detect_anomalies(parsed_logs)

    return alerts
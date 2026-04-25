import time
from detector import run_all_detections


LOG_FILE = "sample_logs.txt"


def follow_logs(file_path):
    """
    Generator function that watches file in real-time
    """
    with open(file_path, "r") as file:
        file.seek(0, 2) 
        while True:
            line = file.readline()
            if not line:
                time.sleep(1)
                continue
            yield line


def display_alerts(alerts):
    """
    Print alerts
    """
    for alert in alerts:
        print(f"🚨 {alert}")


def main():
    print("[INFO] Real-Time Threat Detection Started...\n")

    log_stream = follow_logs(LOG_FILE)
    buffer = []

    for log in log_stream:
        buffer.append(log)

        # Run detection every 5 logs
        if len(buffer) >= 5:
            alerts = run_all_detections(buffer)

            if alerts:
                display_alerts(alerts)

            buffer.clear()


if __name__ == "__main__":
    main()
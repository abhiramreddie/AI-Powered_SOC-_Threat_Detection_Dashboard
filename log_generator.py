import random
from datetime import datetime, timedelta

# Normal IP addr
normal_ips = ["192.168.1.1", "192.168.1.5", "10.0.0.2"]

# Attackers IP addr
attacker_ip = "192.168.1.200"

# List of users
users = ["admin", "john", "guest"]

# List of Countries
countries = ["India", "USA", "Russia"]

def generate_logs():
    logs = []
    now = datetime.now()

    # Normal activity
    for i in range(70):
        ip = random.choice(normal_ips)
        user = random.choice(users)
        country = random.choice(countries)
        status = random.choice(["SUCCESS", "FAILED"])

        time = now - timedelta(seconds=random.randint(0, 300))

        log = f"{time} | {ip} | {user} | {country} | LOGIN_{status}"
        logs.append(log)

    # Brute force attack 
    for i in range(10):
        time = now - timedelta(seconds=i)
        log = f"{time} | {attacker_ip} | admin | Russia | LOGIN_FAILED"
        logs.append(log)

    # Success after brute force
    logs.append(f"{now} | {attacker_ip} | admin | Russia | LOGIN_SUCCESS")

    #  Impossible travel
    logs.append(f"{now} | 10.0.0.5 | john | India | LOGIN_SUCCESS")
    logs.append(f"{now + timedelta(seconds=10)} | 185.23.1.1 | john | USA | LOGIN_SUCCESS")

    #  Midnight Logins
    late_time = now.replace(hour=3, minute=0, second=0)
    logs.append(f"{late_time} | 172.16.0.9 | guest | India | LOGIN_SUCCESS")

    return logs


def save_logs(logs):
    print("Number of logs:", len(logs))  # debug line

    with open("sample_logs.txt", "w") as f:
        for log in logs:
            f.write(log + "\n")


if __name__ == "__main__":
    logs = generate_logs()
    save_logs(logs)
    print(len(logs))
    print("Logs generated successfully")
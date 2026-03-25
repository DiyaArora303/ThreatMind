# ============================================================
# ThreatMind v3 - Log Generator
# Creates realistic sample logs for testing our detection engine
# ============================================================

import random
import json
from datetime import datetime, timedelta

# ── CONCEPT: We're simulating what a real Windows/Linux system
# would log. Each entry has a timestamp, event type, user,
# source IP, and extra details. This mirrors real SIEM data.

# Pool of fake users and IPs to make logs realistic
USERS = ["admin", "john.smith", "sarah.jones", "svc_account", "guest"]
INTERNAL_IPS = ["192.168.1.101", "192.168.1.102", "192.168.1.103", "10.0.0.5"]
EXTERNAL_IPS = ["45.33.32.156", "185.220.101.45", "91.108.4.0", "194.165.16.11"]
SENSITIVE_FILES = [
    "C:\\passwords.txt",
    "C:\\Users\\admin\\Documents\\credentials.xlsx",
    "C:\\Windows\\System32\\SAM",
    "C:\\secret_project\\design.pdf"
]

def generate_timestamp(base_time, offset_seconds):
    """Creates a timestamp offset from a base time"""
    return (base_time + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%d %H:%M:%S")

def generate_normal_logs(base_time, count=20):
    """Generates boring, normal activity — the baseline"""
    logs = []
    for i in range(count):
        logs.append({
            "timestamp": generate_timestamp(base_time, i * 30),
            "event_type": random.choice(["FILE_ACCESS", "LOGIN_SUCCESS", "NETWORK_CONN"]),
            "user": random.choice(USERS[:3]),  # Normal users only
            "source_ip": random.choice(INTERNAL_IPS),
            "dest_ip": random.choice(INTERNAL_IPS),
            "details": "normal activity",
            "is_malicious": False
        })
    return logs

def generate_attack_sequence(base_time):
    """
    Generates a realistic attack sequence:
    Phase 1 - Brute force login attempts
    Phase 2 - Successful login after brute force
    Phase 3 - Sensitive file access (reconnaissance)
    Phase 4 - External connection (data exfiltration)
    """
    logs = []
    attacker_ip = "185.220.101.45"  # Known bad IP
    target_user = "admin"

    # Phase 1: Brute force — multiple failed logins
    for i in range(7):
        logs.append({
            "timestamp": generate_timestamp(base_time, i * 2),
            "event_type": "LOGIN_FAILED",
            "user": target_user,
            "source_ip": attacker_ip,
            "dest_ip": "192.168.1.101",
            "details": f"Failed login attempt {i+1}",
            "is_malicious": True
        })

    # Phase 2: Successful login (brute force worked)
    logs.append({
        "timestamp": generate_timestamp(base_time, 20),
        "event_type": "LOGIN_SUCCESS",
        "user": target_user,
        "source_ip": attacker_ip,
        "dest_ip": "192.168.1.101",
        "details": "Login succeeded after failed attempts",
        "is_malicious": True
    })

    # Phase 3: Sensitive file access (attacker looking around)
    for f in SENSITIVE_FILES[:2]:
        logs.append({
            "timestamp": generate_timestamp(base_time, 25),
            "event_type": "FILE_ACCESS",
            "user": target_user,
            "source_ip": attacker_ip,
            "dest_ip": "192.168.1.101",
            "details": f"Accessed sensitive file: {f}",
            "is_malicious": True
        })

    # Phase 4: External connection (sending data out)
    logs.append({
        "timestamp": generate_timestamp(base_time, 35),
        "event_type": "NETWORK_CONN",
        "user": target_user,
        "source_ip": "192.168.1.101",
        "dest_ip": "45.33.32.156",
        "details": "Outbound connection to external IP on port 4444",
        "is_malicious": True
    })

    return logs

def generate_log_file():
    """Combines normal + attack logs and saves to file"""
    base_time = datetime.now()

    # Mix normal logs with attack sequence
    all_logs = []
    all_logs.extend(generate_normal_logs(base_time, count=15))
    all_logs.extend(generate_attack_sequence(base_time))
    all_logs.extend(generate_normal_logs(base_time, count=10))

    # Sort by timestamp so it looks like a real log file
    all_logs.sort(key=lambda x: x["timestamp"])

    # Save as JSON — easy for our engine to read later
    with open("data/sample_logs.json", "w") as f:
        json.dump(all_logs, f, indent=2)

    print(f"[+] Generated {len(all_logs)} log entries")
    print(f"[+] Attack sequences hidden inside normal traffic")
    print(f"[+] Saved to data/sample_logs.json")
    return all_logs

if __name__ == "__main__":
    logs = generate_log_file()
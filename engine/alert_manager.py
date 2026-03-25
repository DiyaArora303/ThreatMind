# ============================================================
# ThreatMind v3 - Alert Manager
# Saves, loads, and manages all generated alerts
# ============================================================
#
# CONCEPT: In real SIEMs every alert is stored in a database.
# We're using JSON files for now — same idea, simpler setup.
# When we build the dashboard it will read from here.
# ============================================================

import json
import os
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

ALERTS_FILE = "reports/alerts.json"

def save_alerts(alerts):
    """
    Saves all alerts to a JSON file with a run timestamp.
    Every time ThreatMind runs, alerts are recorded here.
    """
    os.makedirs("reports", exist_ok=True)
    
    report = {
        "scan_time":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_alerts": len(alerts),
        "critical":     len([a for a in alerts if a["severity"] == "CRITICAL"]),
        "high":         len([a for a in alerts if a["severity"] == "HIGH"]),
        "alerts":       alerts
    }
    
    with open(ALERTS_FILE, "w") as f:
        json.dump(report, f, indent=2)
    
    print(Fore.GREEN + f"\n[+] Alerts saved to {ALERTS_FILE}")
    return report

def load_alerts():
    """Loads previously saved alerts"""
    if not os.path.exists(ALERTS_FILE):
        print(Fore.YELLOW + "[*] No previous alerts found.")
        return None
    
    with open(ALERTS_FILE, "r") as f:
        return json.load(f)

def print_summary(report):
    """Prints a clean summary of the scan"""
    print(Fore.CYAN + "\n" + "="*55)
    print(Fore.CYAN + "   THREATMIND v3 — SCAN SUMMARY")
    print(Fore.CYAN + "="*55)
    print(Fore.WHITE + f"  Scan Time:     {report['scan_time']}")
    print(Fore.WHITE + f"  Total Alerts:  {report['total_alerts']}")
    print(Fore.RED   + f"  CRITICAL:      {report['critical']}")
    print(Fore.YELLOW+ f"  HIGH:          {report['high']}")
    print(Fore.CYAN  + "="*55)
    
    print(Fore.WHITE + "\n  MITRE ATT&CK Techniques Detected:")
    seen = set()
    for alert in report["alerts"]:
        key = alert["mitre_id"]
        if key not in seen:
            seen.add(key)
            print(Fore.MAGENTA + f"  → {alert['mitre_id']} | {alert['mitre_name']} | {alert['mitre_tactic']}")
    print()
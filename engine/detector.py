# ============================================================
# ThreatMind v3 - Detection Engine
# This is the brain that reads logs and spots attacks
# ============================================================
#
# CONCEPT: We're codifying human analyst instincts into rules.
# Everything in this file is based on exactly what YOU spotted
# when you read the logs — same IP, repeated failures, then
# success, then suspicious behavior after.
# ============================================================

import json
from collections import defaultdict
from colorama import Fore, Style, init
import sys
sys.path.append(".")
from engine.alert_manager import save_alerts, print_summary

init(autoreset=True)

# ── MITRE ATT&CK MAPPINGS ──────────────────────────────────
# Every detection rule maps to a real MITRE technique.
# This is what makes ThreatMind different from a basic alert system.
MITRE_MAPPINGS = {
    "BRUTE_FORCE":        {"id": "T1110", "name": "Brute Force",                  "tactic": "Credential Access"},
    "BRUTE_SUCCESS":      {"id": "T1078", "name": "Valid Accounts",               "tactic": "Initial Access"},
    "SENSITIVE_FILE":     {"id": "T1083", "name": "File & Directory Discovery",   "tactic": "Discovery"},
    "EXTERNAL_CONN":      {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "SUSPICIOUS_PORT":    {"id": "T1571", "name": "Non-Standard Port",            "tactic": "Command & Control"},
}

# ── DETECTION THRESHOLDS ──────────────────────────────────
# These are tunable — in real SIEMs analysts adjust these
# based on their environment to reduce false positives
BRUTE_FORCE_THRESHOLD = 5      # How many failed logins = brute force
SUSPICIOUS_PORTS = [4444, 1337, 8080, 9999, 31337]  # Known hacker ports
SENSITIVE_KEYWORDS = ["password", "credential", "secret", "SAM", "shadow", ".key"]


class DetectionEngine:
    """
    The core detection engine.
    Reads logs, applies rules, generates alerts with MITRE mappings.
    """

    def __init__(self):
        self.alerts = []           # All alerts we generate
        self.failed_logins = defaultdict(list)  # Tracks failed logins per IP
        
        print(Fore.CYAN + "[*] Detection Engine initialized")
        print(Fore.CYAN + f"[*] Brute force threshold: {BRUTE_FORCE_THRESHOLD} attempts")
        print(Fore.CYAN + f"[*] Monitoring {len(SUSPICIOUS_PORTS)} suspicious ports\n")

    def load_logs(self, filepath):
        """
        Loads log file and returns list of log entries.
        CONCEPT: In a real SIEM this would be a live stream.
        For now we read from a file.
        """
        with open(filepath, "r") as f:
            logs = json.load(f)
        print(Fore.GREEN + f"[+] Loaded {len(logs)} log entries from {filepath}\n")
        return logs

    def generate_alert(self, severity, rule_name, log_entry, description):
        """
        Creates a structured alert — every alert has:
        - What happened (rule name)
        - How serious it is (severity)
        - Which MITRE technique it maps to
        - The raw log that triggered it
        """
        mitre = MITRE_MAPPINGS.get(rule_name, {"id": "Unknown", "name": "Unknown", "tactic": "Unknown"})
        
        alert = {
            "severity":       severity,
            "rule":           rule_name,
            "description":    description,
            "timestamp":      log_entry.get("timestamp"),
            "user":           log_entry.get("user"),
            "source_ip":      log_entry.get("source_ip"),
            "dest_ip":        log_entry.get("dest_ip"),
            "mitre_id":       mitre["id"],
            "mitre_name":     mitre["name"],
            "mitre_tactic":   mitre["tactic"],
        }
        
        self.alerts.append(alert)
        self.print_alert(alert)

    def print_alert(self, alert):
        """Prints a colored alert to the terminal"""
        colors = {
            "CRITICAL": Fore.RED,
            "HIGH":     Fore.RED,
            "MEDIUM":   Fore.YELLOW,
            "LOW":      Fore.CYAN
        }
        color = colors.get(alert["severity"], Fore.WHITE)
        
        print(color + f"  ⚠  [{alert['severity']}] {alert['rule']} DETECTED")
        print(Fore.WHITE + f"     Time:        {alert['timestamp']}")
        print(Fore.WHITE + f"     User:        {alert['user']}")
        print(Fore.WHITE + f"     Source IP:   {alert['source_ip']}")
        print(Fore.WHITE + f"     Description: {alert['description']}")
        print(Fore.MAGENTA + f"     MITRE:       {alert['mitre_id']} — {alert['mitre_name']} ({alert['mitre_tactic']})")
        print()

    # ── DETECTION RULES ───────────────────────────────────
    # Each method below is ONE rule.
    # CONCEPT: This is exactly how real SIEM rules work —
    # each rule watches for one specific pattern.

    def rule_brute_force(self, log):
        """
        Rule: If the same IP fails to login 5+ times → Brute Force
        This is exactly what you spotted in the data.
        """
        if log["event_type"] == "LOGIN_FAILED":
            ip = log["source_ip"]
            self.failed_logins[ip].append(log)
            
            # Fire alert when threshold is crossed
            if len(self.failed_logins[ip]) == BRUTE_FORCE_THRESHOLD:
                self.generate_alert(
                    severity="HIGH",
                    rule_name="BRUTE_FORCE",
                    log_entry=log,
                    description=f"{ip} has failed login {BRUTE_FORCE_THRESHOLD}+ times against user '{log['user']}'"
                )

    def rule_brute_force_success(self, log):
        """
        Rule: If an IP that previously failed many times now succeeds → Critical
        This is the most dangerous moment — the attacker is now INSIDE.
        """
        if log["event_type"] == "LOGIN_SUCCESS":
            ip = log["source_ip"]
            if len(self.failed_logins.get(ip, [])) >= BRUTE_FORCE_THRESHOLD:
                self.generate_alert(
                    severity="CRITICAL",
                    rule_name="BRUTE_SUCCESS",
                    log_entry=log,
                    description=f"BREACH: {ip} succeeded after {len(self.failed_logins[ip])} failed attempts — account '{log['user']}' likely compromised"
                )

    def rule_sensitive_file_access(self, log):
        """
        Rule: If someone accesses a file with sensitive keywords → Suspicious
        Attackers always go for passwords, credentials, keys first.
        """
        if log["event_type"] == "FILE_ACCESS":
            details_lower = log["details"].lower()
            for keyword in SENSITIVE_KEYWORDS:
                if keyword.lower() in details_lower:
                    self.generate_alert(
                        severity="HIGH",
                        rule_name="SENSITIVE_FILE",
                        log_entry=log,
                        description=f"Sensitive file access by '{log['user']}' — keyword '{keyword}' detected in: {log['details']}"
                    )
                    break

    def rule_external_connection(self, log):
        """
        Rule: If an internal machine connects to an external IP on a suspicious port → Exfiltration
        Port 4444 is the default Metasploit port — a massive red flag.
        """
        if log["event_type"] == "NETWORK_CONN":
            dest = log["dest_ip"]
            # Check if destination is external (not internal)
            is_external = not (
                dest.startswith("192.168.") or
                dest.startswith("10.") or
                dest.startswith("172.")
            )
            if is_external:
                # Check for suspicious port in details
                for port in SUSPICIOUS_PORTS:
                    if str(port) in log.get("details", ""):
                        self.generate_alert(
                            severity="CRITICAL",
                            rule_name="EXTERNAL_CONN",
                            log_entry=log,
                            description=f"Possible exfiltration: internal host connecting to {dest} on suspicious port {port}"
                        )
                        break

    def run(self, log_filepath):
        """
        Main method — loads logs and runs every rule against every log entry.
        CONCEPT: This is called 'rule-based detection' — the foundation of every SIEM.
        """
        print(Fore.CYAN + "="*55)
        print(Fore.CYAN + "   THREATMIND v3 — DETECTION ENGINE RUNNING")
        print(Fore.CYAN + "="*55 + "\n")

        logs = self.load_logs(log_filepath)

        print(Fore.WHITE + f"[*] Running detection rules on {len(logs)} events...\n")
        print(Fore.WHITE + "-"*55 + "\n")

        # Run EVERY rule against EVERY log entry
        # This is exactly how a real SIEM processes events
        for log in logs:
            self.rule_brute_force(log)
            self.rule_brute_force_success(log)
            self.rule_sensitive_file_access(log)
            self.rule_external_connection(log)

        # Summary
        print(Fore.WHITE + "-"*55)
        print(Fore.CYAN + f"\n[*] Scan complete.")
        print(Fore.GREEN + f"[+] Total alerts generated: {len(self.alerts)}")
        
        critical = [a for a in self.alerts if a["severity"] == "CRITICAL"]
        high     = [a for a in self.alerts if a["severity"] == "HIGH"]
        
        print(Fore.RED    + f"[!] CRITICAL: {len(critical)}")
        print(Fore.YELLOW + f"[!] HIGH:     {len(high)}")
        # Save alerts and print summary
        report = save_alerts(self.alerts)
        print_summary(report)
        
        return self.alerts
   


if __name__ == "__main__":
    engine = DetectionEngine()
    alerts = engine.run("data/sample_logs.json")
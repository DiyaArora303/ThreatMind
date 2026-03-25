# ============================================================
# ThreatMind v3 - Real Data Fetcher
# Pulls real threat data from public sources
# ============================================================

import requests
import json
import csv
import os
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

def fetch_phishtank():
    """
    Fetches real phishing URL data from PhishTank.
    PhishTank is a free public database of confirmed phishing sites
    used by real threat intelligence teams worldwide.
    """
    print(Fore.CYAN + "[*] Fetching real phishing data from PhishTank...")
    
    # PhishTank's public JSON feed — no API key needed
    url = "http://data.phishtank.com/data/online-valid.json"
    
    try:
        headers = {"User-Agent": "ThreatMind/3.0 Research Tool"}
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            # Take first 50 entries — enough to work with
            samples = data[:50]
            
            # Restructure into ThreatMind format
            processed = []
            for entry in samples:
                processed.append({
                    "timestamp":    entry.get("submission_time", ""),
                    "event_type":   "PHISHING_URL",
                    "url":          entry.get("url", ""),
                    "target":       entry.get("target", "Unknown"),
                    "verified":     entry.get("verified", ""),
                    "country":      entry.get("details", [{}])[0].get("announcing_network", "Unknown") if entry.get("details") else "Unknown",
                    "source":       "PhishTank",
                    "is_malicious": True
                })
            
            # Save to file
            os.makedirs("data", exist_ok=True)
            with open("data/real_phishing_data.json", "w") as f:
                json.dump(processed, f, indent=2)
            
            print(Fore.GREEN + f"[+] Fetched {len(processed)} real phishing entries")
            print(Fore.GREEN + f"[+] Saved to data/real_phishing_data.json")
            return processed
            
        else:
            print(Fore.YELLOW + f"[!] PhishTank returned status {response.status_code}")
            print(Fore.YELLOW + "[!] Trying backup source...")
            return fetch_phishtank_backup()
            
    except Exception as e:
        print(Fore.YELLOW + f"[!] PhishTank unavailable: {e}")
        print(Fore.YELLOW + "[!] Trying backup source...")
        return fetch_phishtank_backup()


def fetch_phishtank_backup():
    """
    Backup: Pulls from OpenPhish — another free public phishing feed
    Used when PhishTank is rate limiting or unavailable
    """
    print(Fore.CYAN + "[*] Trying OpenPhish feed...")
    
    url = "https://openphish.com/feed.txt"
    
    try:
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            urls = response.text.strip().split("\n")[:50]
            
            processed = []
            for phish_url in urls:
                processed.append({
                    "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "event_type":   "PHISHING_URL",
                    "url":          phish_url,
                    "target":       "Unknown",
                    "verified":     "yes",
                    "country":      "Unknown",
                    "source":       "OpenPhish",
                    "is_malicious": True
                })
            
            with open("data/real_phishing_data.json", "w") as f:
                json.dump(processed, f, indent=2)
            
            print(Fore.GREEN + f"[+] Fetched {len(processed)} entries from OpenPhish")
            print(Fore.GREEN + f"[+] Saved to data/real_phishing_data.json")
            return processed
        
    except Exception as e:
        print(Fore.RED + f"[!] Both sources unavailable: {e}")
        return []


def fetch_windows_logs():
    """
    Reads REAL security logs from your actual Windows machine.
    This is live data from your own system.
    
    CONCEPT: Windows logs everything in Event Logs.
    Security Event ID 4625 = Failed Login (exactly what we detect)
    Security Event ID 4624 = Successful Login
    Security Event ID 4688 = Process Created (attackers run processes)
    """
    print(Fore.CYAN + "\n[*] Reading real Windows Event Logs from your system...")
    
    try:
        import subprocess
        
        # PowerShell command to pull recent security events
        # Event ID 4625 = Failed logon — exactly what brute force generates
        ps_command = """
        Get-EventLog -LogName Security -Newest 100 -ErrorAction SilentlyContinue |
        Where-Object {$_.EventID -in @(4624, 4625, 4688)} |
        Select-Object TimeGenerated, EventID, Message |
        ConvertTo-Json
        """
        
        result = subprocess.run(
            ["powershell", "-Command", ps_command],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.stdout and result.stdout.strip():
            try:
                events = json.loads(result.stdout)
                if isinstance(events, dict):
                    events = [events]
                
                processed = []
                for event in events:
                    event_id = event.get("EventID", 0)
                    
                    # Map Windows Event IDs to our format
                    event_type_map = {
                        4624: "LOGIN_SUCCESS",
                        4625: "LOGIN_FAILED",
                        4688: "PROCESS_CREATED"
                    }
                    
                    processed.append({
                        "timestamp":  str(event.get("TimeGenerated", "")),
                        "event_type": event_type_map.get(event_id, "UNKNOWN"),
                        "event_id":   event_id,
                        "source":     "Windows Event Log",
                        "details":    str(event.get("Message", ""))[:200],
                        "is_malicious": False  # Real logs — we let our engine decide
                    })
                
                with open("data/real_windows_logs.json", "w") as f:
                    json.dump(processed, f, indent=2)
                
                print(Fore.GREEN + f"[+] Pulled {len(processed)} real Windows events")
                print(Fore.GREEN + f"[+] Saved to data/real_windows_logs.json")
                return processed
                
            except json.JSONDecodeError:
                print(Fore.YELLOW + "[!] Could not parse Windows logs — may need admin rights")
                return []
        else:
            print(Fore.YELLOW + "[!] No Windows logs returned — try running PowerShell as Administrator")
            return []
            
    except Exception as e:
        print(Fore.RED + f"[!] Windows log fetch failed: {e}")
        return []


if __name__ == "__main__":
    print(Fore.RED + """
╔══════════════════════════════════════════╗
║   THREATMIND v3 — REAL DATA FETCHER     ║
╚══════════════════════════════════════════╝
    """)
    
    # Fetch phishing data
    phishing = fetch_phishtank()
    
    # Fetch Windows logs
    windows = fetch_windows_logs()
    
    print(Fore.CYAN + "\n[*] Real Data Summary:")
    print(Fore.GREEN + f"    Phishing URLs:   {len(phishing)}")
    print(Fore.GREEN + f"    Windows Events:  {len(windows)}")
    print(Fore.CYAN + "\n[+] ThreatMind is now running on real data.")
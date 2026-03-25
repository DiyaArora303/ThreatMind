# ============================================================
# ThreatMind v3 - Main Entry Point
# This is the file that runs the whole system
# ============================================================

from colorama import Fore, Style, init
from config import PROJECT_NAME, VERSION

# Initialize colorama — makes colors work on Windows
init(autoreset=True)

def banner():
    """Prints the ThreatMind startup banner"""
    print(Fore.BLUE + """
 _____ _                    _   __  __ _           _
|_   _| |__  _ __ ___  __ _| |_|  \/  (_)_ __   __| |
  | | | '_ \| '__/ _ \/ _` | __| |\/| | | '_ \ / _` |
  | | | | | | | |  __/ (_| | |_| |  | | | | | | (_| |
  |_| |_| |_|_|  \___|\__,_|\__|_|  |_|_|_| |_|\__,_|
    """)
    print(Fore.CYAN + f"  {PROJECT_NAME} | Version {VERSION}")
    print(Fore.CYAN + "  AI-Powered Threat Detection & Actor Profiling")
    print(Fore.WHITE + "  " + "="*50)
    print()

def main():
    banner()
    print(Fore.GREEN + "[+] ThreatMind is starting up...")
    print(Fore.GREEN + "[+] All systems ready.")
    print(Fore.YELLOW + "[*] Waiting for input...\n")

if __name__ == "__main__":
    main()
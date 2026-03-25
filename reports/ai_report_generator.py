# ============================================================
# ThreatMind v3 - AI Threat Report Generator
# Uses local Mistral AI via Ollama — completely free, offline
# ============================================================
#
# CONCEPT: Instead of sending data to an external API,
# we run the AI model locally using Ollama.
# Ollama runs as a local server at http://localhost:11434
# Our code sends requests to it exactly like an API call
# except everything stays on your machine.
#
# WHY THIS IS MORE IMPRESSIVE THAN USING OPENAI:
# - Zero cost forever
# - Works completely offline
# - Sensitive incident data never leaves the machine
# - You own and control the entire AI pipeline
# This is how enterprise security tools actually work.
# ============================================================

import json
import os
from datetime import datetime
import ollama
from colorama import Fore, init

init(autoreset=True)


def load_all_outputs():
    """
    Loads everything ThreatMind has generated so far.
    Aggregates outputs from all modules for the AI to synthesize.
    """
    data = {}

    # Load SIEM alerts
    if os.path.exists("reports/alerts.json"):
        with open("reports/alerts.json", "r") as f:
            data["alerts"] = json.load(f)
        print(Fore.GREEN + f"[+] Loaded SIEM alerts")

    # Load phishing analysis
    if os.path.exists("reports/phishing_analysis.json"):
        with open("reports/phishing_analysis.json", "r") as f:
            phishing = json.load(f)
            data["phishing_summary"] = {
                "total_analyzed": len(phishing),
                "critical": len([p for p in phishing if p["risk_level"] == "CRITICAL"]),
                "high":     len([p for p in phishing if p["risk_level"] == "HIGH"]),
                "top_threats": [p for p in phishing if p["risk_level"] == "CRITICAL"][:3]
            }
        print(Fore.GREEN + f"[+] Loaded phishing analysis")

    return data


def build_prompt(data):
    """
    Builds the structured prompt for Mistral.

    CONCEPT — PROMPT ENGINEERING FOR LOCAL MODELS:
    Local models like Mistral need slightly more explicit
    instructions than cloud models. We structure the prompt
    very clearly so Mistral knows exactly what to produce.
    The clearer your prompt, the better the output.
    This skill — prompt engineering — is genuinely valued
    in security roles right now.
    """
    alerts = data.get("alerts", {})
    phishing = data.get("phishing_summary", {})

    alert_text = ""
    if alerts:
        alert_text = f"""
SIEM DETECTION RESULTS:
- Scan Time: {alerts.get('scan_time', 'Unknown')}
- Total Alerts: {alerts.get('total_alerts', 0)}
- Critical: {alerts.get('critical', 0)} | High: {alerts.get('high', 0)}

ATTACK CHAIN DETECTED:"""

        for alert in alerts.get("alerts", []):
            alert_text += f"""
  [{alert['severity']}] {alert['rule']} — {alert['timestamp']}
  User: {alert['user']} | Source IP: {alert['source_ip']}
  MITRE: {alert['mitre_id']} — {alert['mitre_name']} ({alert['mitre_tactic']})
  Details: {alert['description']}
"""

    phishing_text = ""
    if phishing:
        phishing_text = f"""
PHISHING INTELLIGENCE:
- Total URLs Analyzed: {phishing.get('total_analyzed', 0)}
- Critical Threats: {phishing.get('critical', 0)}
- High Threats: {phishing.get('high', 0)}
"""

    prompt = f"""You are a senior cybersecurity analyst. Write a formal incident report using ONLY the data provided below. Do not invent any information.

Structure your report with these exact numbered sections:

1. EXECUTIVE SUMMARY
Write 2-3 non-technical sentences summarizing what happened for senior management.

2. INCIDENT TIMELINE
List events chronologically with timestamps from the data.

3. ATTACK TECHNIQUE ANALYSIS
Explain each MITRE ATT&CK technique detected and what it means in plain terms.

4. THREAT ACTOR ASSESSMENT
Based only on the data, assess who likely did this and their skill level.

5. IMPACT ASSESSMENT
What systems, accounts, or data were at risk or compromised.

6. IMMEDIATE ACTIONS REQUIRED
Number each action. Be specific. What should the security team do right now.

7. LONG-TERM RECOMMENDATIONS
Strategic steps to prevent this type of attack in future.

=== THREAT INTELLIGENCE DATA ===
{alert_text}
{phishing_text}
=== END DATA ===

Write the complete incident report now. Be professional and specific."""

    return prompt


def generate_report(data):
    """
    Sends prompt to local Mistral model via Ollama.

    CONCEPT — HOW OLLAMA WORKS:
    Ollama runs as a background service on your machine.
    The ollama Python library talks to it over localhost.
    The model processes your prompt entirely on your CPU/GPU.
    Response time depends on your hardware — typically 30-90 seconds
    for a full report on a laptop. Worth the wait.
    """
    print(Fore.CYAN + "\n[*] Sending intelligence to local Mistral AI...")
    print(Fore.CYAN + "[*] Processing on your machine — this takes 30-60 seconds...")
    print(Fore.CYAN + "[*] No data leaving your computer.\n")

    prompt = build_prompt(data)

    try:
        response = ollama.chat(
            model="mistral",
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity analyst specializing in incident response and threat intelligence. Write clear, professional, actionable reports based only on provided data."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        )

        # Extract the report text from Ollama's response
        report_text = response["message"]["content"]

        # Save to timestamped file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"reports/incident_report_{timestamp}.txt"

        with open(report_filename, "w", encoding="utf-8") as f:
            f.write("=" * 60 + "\n")
            f.write("THREATMIND v3 — AI INCIDENT REPORT\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("AI Model: Mistral 7B (Local — Offline)\n")
            f.write("=" * 60 + "\n\n")
            f.write(report_text)

        return report_text, report_filename

    except Exception as e:
        print(Fore.RED + f"[!] Report generation failed: {e}")
        print(Fore.YELLOW + "[*] Make sure Ollama is running — check your system tray")
        return None, None


def display_report(report_text, filename):
    """Displays the finished report"""
    print(Fore.RED   + "=" * 60)
    print(Fore.RED   + "   THREATMIND v3 — AI INCIDENT REPORT")
    print(Fore.RED   + "        Powered by Mistral 7B (Local)")
    print(Fore.RED   + "=" * 60)
    print()
    print(Fore.WHITE + report_text)
    print()
    print(Fore.GREEN + f"[+] Report saved to {filename}")


if __name__ == "__main__":
    print(Fore.RED + """
╔══════════════════════════════════════════╗
║   THREATMIND v3 — AI REPORT GENERATOR  ║
║        Powered by Mistral (Local)       ║
╚══════════════════════════════════════════╝
    """)

    data = load_all_outputs()

    if not data:
        print(Fore.RED + "[!] No data found. Run the detection engine first.")
    else:
        report_text, filename = generate_report(data)

        if report_text:
            display_report(report_text, filename)
        else:
            print(Fore.RED + "[!] Generation failed. Is Ollama running?")
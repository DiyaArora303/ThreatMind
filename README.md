\# 🔴 ThreatMind v3

\### AI-Powered Threat Detection, MITRE ATT\&CK Mapping \& Psychological Actor Profiling



---



\## What is ThreatMind?



ThreatMind is an AI-powered security platform that does three things no single tool currently does together:



1\. \*\*Detects attacks in real time\*\* — ingests logs and fires alerts automatically

2\. \*\*Maps every alert to MITRE ATT\&CK\*\* — tells you exactly what technique the attacker is using

3\. \*\*Psychologically profiles the threat actor\*\* — analyzes attacker artifacts to infer motivation, skill level, and origin



---



\## Why This Exists



Current SIEM tools tell you \*what\* happened.  

MITRE ATT\&CK tells you \*how\* it happened.  

ThreatMind adds the missing layer — \*who\* did it and \*why\*.



---



\## Features Built So Far



\- ✅ Log ingestion and parsing engine

\- ✅ Rule-based detection (Brute Force, Credential Access, Exfiltration)

\- ✅ Automatic MITRE ATT\&CK technique mapping

\- ✅ Severity-based alert system (CRITICAL / HIGH / MEDIUM / LOW)

\- ✅ Persistent alert storage

\- ⬜ Real data ingestion (PhishTank, Windows Event Logs)

\- ⬜ Psychological threat actor profiling

\- ⬜ AI-generated threat reports

\- ⬜ Live dashboard



---



\## Attack Chain Detected (Example Output)

```

T1110 | Brute Force              | Credential Access

T1078 | Valid Accounts           | Initial Access  

T1083 | File \& Directory Discovery | Discovery

T1041 | Exfiltration Over C2     | Exfiltration

```



---



\## Tech Stack



\- Python 3.11

\- MITRE ATT\&CK Framework

\- Pandas, Colorama

\- NLP \& LLM integration (coming)

\- React Dashboard (coming)



---



\## Project Structure

```

ThreatMind/

├── data/           # Log data (real + synthetic)

├── engine/         # Detection rules + alert manager

├── profiler/       # Psychological profiling layer

├── dashboard/      # Visual interface

├── reports/        # AI-generated threat reports

├── logs/           # Log generator for testing

├── main.py         # Entry point

└── config.py       # Global configuration

```



---



\## Author



\*\*Diya Arora\*\* — Cybersecurity Student  

Interests: Threat Intelligence, AI Security, Cyber Psychology, SIEM


# ============================================================
# ThreatMind v3 - Configuration File
# All project settings live here in one place
# ============================================================

# Project info
PROJECT_NAME = "ThreatMind v3"
VERSION = "0.1.0"

# Folder paths — tells the rest of the project where things live
DATA_DIR = "data/"
LOGS_DIR = "logs/"
REPORTS_DIR = "reports/"

# Severity levels for alerts — we'll use these throughout the project
SEVERITY_LEVELS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1
}

# Colors for terminal output
COLORS = {
    "CRITICAL": "red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "white"
}
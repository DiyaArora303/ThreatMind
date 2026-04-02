# ============================================================
# ThreatMind v3 - Dashboard Backend
# Flask web server that connects all ThreatMind modules
# and serves data to the browser dashboard
# ============================================================
#
# CONCEPT: Flask is a micro web framework.
# It lets Python serve web pages and handle HTTP requests.
# When your browser visits localhost:5000, Flask responds.
# When the dashboard requests data, Flask runs our engines
# and returns the results as JSON.
#
# This is the standard pattern for security dashboards —
# Python backend doing the heavy lifting, browser showing results.
# ============================================================

import json
import os
import sys
sys.path.append(".")

from flask import Flask, render_template, jsonify
from colorama import Fore, init

init(autoreset=True)

app = Flask(__name__, template_folder="templates")


# ── HELPER FUNCTIONS ──────────────────────────────────────

def load_json_file(filepath):
    """Safely loads a JSON file — returns empty dict if not found"""
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def get_latest_report():
    """Finds the most recently generated incident report"""
    report_dir = "reports/"
    if not os.path.exists(report_dir):
        return "No report generated yet. Run the AI report generator first."
        
    reports = [
        f for f in os.listdir(report_dir)
        if f.startswith("incident_report_") and f.endswith(".txt")
    ]
    if not reports:
        return "No report generated yet. Run the AI report generator first."

    # Sort by filename (which contains timestamp) to get latest
    latest = sorted(reports)[-1]
    with open(os.path.join(report_dir, latest), "r", encoding="utf-8") as f:
        return f.read()


# ── ROUTES ────────────────────────────────────────────────
# CONCEPT: Routes are URLs that Flask responds to.
# @app.route("/") means "when browser visits /, run this function"
# @app.route("/api/alerts") means "when browser requests /api/alerts,
# return this data as JSON"
# This pattern — serving data via /api/ routes — is called a REST API.
# Every major security platform uses this architecture.

@app.route("/")
def index():
    """Serves the main dashboard page"""
    return render_template("index.html")


@app.route("/api/alerts")
def get_alerts():
    """Returns all SIEM alerts as JSON"""
    data = load_json_file("reports/alerts.json")
    return jsonify(data)


@app.route("/api/phishing")
def get_phishing():
    """Returns phishing analysis summary as JSON"""
    data = load_json_file("reports/phishing_analysis.json")
    if isinstance(data, list):
        summary = {
            "total":      len(data),
            "critical":   len([p for p in data if p["risk_level"] == "CRITICAL"]),
            "high":       len([p for p in data if p["risk_level"] == "HIGH"]),
            "medium":     len([p for p in data if p["risk_level"] == "MEDIUM"]),
            "low":        len([p for p in data if p["risk_level"] == "LOW"]),
            "top_threats": sorted(
                [p for p in data if p["risk_level"] in ["CRITICAL", "HIGH"]],
                key=lambda x: x["risk_score"],
                reverse=True
            )[:10]
        }
        return jsonify(summary)
    return jsonify({})


@app.route("/api/report")
def get_report():
    """Returns the latest AI-generated incident report"""
    report = get_latest_report()
    return jsonify({"report": report})


@app.route("/api/scan", methods=["POST"])
def run_scan():
    """
    Runs the full ThreatMind detection pipeline.
    CONCEPT: This is a POST route — it performs an action
    rather than just returning data. When the dashboard's
    'Run Scan' button is clicked, it calls this route,
    which runs our detection engine and returns fresh results.
    """
    try:
        from engine.detector import DetectionEngine
        engine = DetectionEngine()
        alerts = engine.run("data/sample_logs.json")
        return jsonify({
            "status": "success",
            "alerts_generated": len(alerts),
            "critical": len([a for a in alerts if a["severity"] == "CRITICAL"]),
            "high":     len([a for a in alerts if a["severity"] == "HIGH"])
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})


@app.route("/api/status")
def get_status():
    """Returns system status — what data is available"""
    # Added check to ensure directory exists before listdir
    reports_exist = os.path.exists("reports/")
    return jsonify({
        "alerts_ready":   os.path.exists("reports/alerts.json"),
        "phishing_ready": os.path.exists("reports/phishing_analysis.json"),
        "report_ready":   reports_exist and any(
            f.startswith("incident_report_")
            for f in os.listdir("reports/")
        ),
        "version": "3.0"
    })

@app.route("/api/profile")
def get_profile():
    """
    Runs the psychological profiler against the latest alerts
    and returns a structured profile.
    """
    try:
        import sys
        sys.path.append(".")
        from profiler.threat_actor_profiler import ThreatActorProfiler
        
        alerts = load_json_file("reports/alerts.json")
        if not alerts or not alerts.get("alerts"):
            return jsonify({"error": "No alerts available"})
        
        # Use alert descriptions as text artifacts for profiling
        combined_text = " ".join([
            a.get("description", "") 
            for a in alerts.get("alerts", [])
        ])
        
        profiler = ThreatActorProfiler()
        profile = profiler.build_profile(
            text=combined_text,
            alerts=alerts.get("alerts", []),
            source_label="SIEM Alert Chain"
        )
        
        return jsonify(profile)
    except Exception as e:
        return jsonify({"error": str(e)})

# ── START SERVER ──────────────────────────────────────────

if __name__ == "__main__":
    print(Fore.RED + """
╔══════════════════════════════════════════╗
║      THREATMIND v3 — DASHBOARD                     ║
║      Starting web server...                        ║
╚══════════════════════════════════════════╝
    """)
    print(Fore.GREEN + "[+] Dashboard running at: http://localhost:5000")
    print(Fore.CYAN  + "[*] Open your browser and go to http://localhost:5000")
    print(Fore.YELLOW + "[*] Press Ctrl+C to stop the server\n")

    app.run(debug=True, port=5000)
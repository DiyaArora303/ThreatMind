# ============================================================
# ThreatMind v3 - Phishing URL Analyzer
# Analyzes real phishing URLs and explains WHY they're suspicious
# ============================================================
#
# CONCEPT: This is feature extraction — we're pulling signals
# out of raw data that tell us something meaningful.
# Every signal here is based on what YOU spotted visually.
# We're just teaching the computer to see what you see.
# ============================================================

import json
import re
from urllib.parse import urlparse
from colorama import Fore, init

init(autoreset=True)

# ── KNOWN SIGNALS ─────────────────────────────────────────

# Brands attackers commonly impersonate
TARGET_BRANDS = [
    "paypal", "amazon", "apple", "google", "microsoft",
    "netflix", "facebook", "instagram", "bank", "secure",
    "verify", "account", "login", "update", "confirm"
]

# TLDs heavily abused by attackers — you spotted this
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
    ".top", ".click", ".loan", ".work", ".link"
]

# Words in URLs that scream phishing
SUSPICIOUS_WORDS = [
    "secure", "verify", "login", "update", "confirm",
    "account", "banking", "signin", "validate", "suspend",
    "urgent", "alert", "limited", "access", "restore"
]


class PhishingAnalyzer:
    """
    Analyzes URLs and extracts signals that indicate phishing.
    Each signal maps to a real detection technique used by
    threat intelligence teams.
    """

    def __init__(self):
        self.results = []
        print(Fore.CYAN + "[*] Phishing Analyzer initialized")
        print(Fore.CYAN + f"[*] Monitoring {len(TARGET_BRANDS)} brand impersonations")
        print(Fore.CYAN + f"[*] Tracking {len(SUSPICIOUS_TLDS)} suspicious TLDs\n")

    def extract_domain(self, url):
        """
        Pulls the real domain out of a URL.
        CONCEPT: urlparse is a Python tool that breaks URLs into parts.
        'https://login.verify.evil.tk/paypal' → evil.tk is the real domain
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc or parsed.path
            # Remove www. prefix
            hostname = hostname.replace("www.", "")
            return hostname
        except:
            return url

    def get_real_domain(self, hostname):
        """
        Extracts just the root domain — the part that matters.
        'login.verify.secure.evil.tk' → 'evil.tk'
        This is what YOU spotted — the dots are misleading.
        """
        parts = hostname.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return hostname

    def check_typosquatting(self, url):
        """
        Detects brand impersonation in the URL.
        Checks if a known brand name appears in a suspicious context.
        """
        url_lower = url.lower()
        found_brands = []
        for brand in TARGET_BRANDS:
            if brand in url_lower:
                found_brands.append(brand)
        return found_brands

    def check_suspicious_tld(self, hostname):
        """
        Checks if URL uses a TLD heavily abused by attackers.
        You spotted this — the weird endings.
        """
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                return tld
        return None

    def check_subdomain_abuse(self, hostname):
        """
        Counts subdomain depth — more dots = more suspicious.
        'login.verify.secure.evil.tk' has 3 subdomains = very suspicious.
        Legitimate sites rarely go beyond 1-2 levels deep.
        """
        parts = hostname.split(".")
        subdomain_count = len(parts) - 2
        return subdomain_count if subdomain_count > 1 else 0

    def check_suspicious_words(self, url):
        """
        Looks for psychological manipulation words in the URL itself.
        Attackers use words like 'urgent', 'verify', 'suspended'
        to create fear and make you click without thinking.
        """
        url_lower = url.lower()
        found = []
        for word in SUSPICIOUS_WORDS:
            if word in url_lower:
                found.append(word)
        return found

    def check_url_length(self, url):
        """
        Phishing URLs are often very long — they try to hide
        the real domain by burying it in a long string.
        Legitimate URLs are usually under 75 characters.
        """
        return len(url) > 75

    def calculate_risk_score(self, signals):
        """
        Combines all signals into a single risk score 0-100.
        CONCEPT: This is how real threat scoring works —
        no single signal is definitive, but combined they paint a picture.
        """
        score = 0
        if signals["brands_found"]:       score += 30
        if signals["suspicious_tld"]:     score += 25
        if signals["subdomain_abuse"]:    score += 20 * min(signals["subdomain_abuse"], 2)
        if signals["suspicious_words"]:   score += 10 * min(len(signals["suspicious_words"]), 2)
        if signals["url_too_long"]:       score += 10
        return min(score, 100)

    def analyze_url(self, url_entry):
        """
        Runs all checks on a single URL and returns a full analysis.
        """
        url = url_entry.get("url", "")
        hostname = self.extract_domain(url)
        real_domain = self.get_real_domain(hostname)

        # Run all signal checks
        signals = {
            "brands_found":    self.check_typosquatting(url),
            "suspicious_tld":  self.check_suspicious_tld(hostname),
            "subdomain_abuse": self.check_subdomain_abuse(hostname),
            "suspicious_words":self.check_suspicious_words(url),
            "url_too_long":    self.check_url_length(url),
        }

        risk_score = self.calculate_risk_score(signals)

        # Determine risk level
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 40:
            risk_level = "HIGH"
        elif risk_score >= 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        result = {
            "url":          url,
            "real_domain":  real_domain,
            "risk_score":   risk_score,
            "risk_level":   risk_level,
            "signals":      signals,
            "source":       url_entry.get("source", "Unknown")
        }

        return result

    def print_result(self, result):
        """Prints a single URL analysis in a readable format"""
        colors = {
            "CRITICAL": Fore.RED,
            "HIGH":     Fore.YELLOW,
            "MEDIUM":   Fore.CYAN,
            "LOW":      Fore.WHITE
        }
        color = colors.get(result["risk_level"], Fore.WHITE)

        print(color + f"  [{result['risk_level']}] Risk Score: {result['risk_score']}/100")
        print(Fore.WHITE + f"  Domain:  {result['real_domain']}")
        print(Fore.WHITE + f"  URL:     {result['url'][:70]}...")

        s = result["signals"]
        if s["brands_found"]:
            print(Fore.RED + f"  ⚠ Brand impersonation: {', '.join(s['brands_found'])}")
        if s["suspicious_tld"]:
            print(Fore.RED + f"  ⚠ Suspicious TLD: {s['suspicious_tld']}")
        if s["subdomain_abuse"]:
            print(Fore.YELLOW + f"  ⚠ Subdomain abuse: {s['subdomain_abuse']} levels deep")
        if s["suspicious_words"]:
            print(Fore.YELLOW + f"  ⚠ Manipulation words: {', '.join(s['suspicious_words'])}")
        if s["url_too_long"]:
            print(Fore.CYAN + f"  ⚠ Unusually long URL")
        print()

    def run(self, filepath):
        """Loads real phishing data and analyzes every URL"""
        print(Fore.CYAN + "="*55)
        print(Fore.CYAN + "   THREATMIND v3 — PHISHING ANALYZER")
        print(Fore.CYAN + "="*55 + "\n")

        with open(filepath, "r") as f:
            data = json.load(f)

        print(Fore.WHITE + f"[*] Analyzing {len(data)} real phishing URLs...\n")
        print(Fore.WHITE + "-"*55 + "\n")

        for entry in data[:10]:  # Show first 10 in detail
            result = self.analyze_url(entry)
            self.results.append(result)
            self.print_result(result)

        # Analyze rest silently
        for entry in data[10:]:
            result = self.analyze_url(entry)
            self.results.append(result)

        # Save results
        with open("reports/phishing_analysis.json", "w") as f:
            json.dump(self.results, f, indent=2)

        # Summary
        critical = len([r for r in self.results if r["risk_level"] == "CRITICAL"])
        high =     len([r for r in self.results if r["risk_level"] == "HIGH"])
        medium =   len([r for r in self.results if r["risk_level"] == "MEDIUM"])

        print(Fore.WHITE + "-"*55)
        print(Fore.CYAN + "\n[*] Analysis Complete")
        print(Fore.RED    + f"    CRITICAL: {critical}")
        print(Fore.YELLOW + f"    HIGH:     {high}")
        print(Fore.CYAN   + f"    MEDIUM:   {medium}")
        print(Fore.GREEN  + f"\n[+] Full results saved to reports/phishing_analysis.json\n")

        return self.results


if __name__ == "__main__":
    analyzer = PhishingAnalyzer()
    analyzer.run("data/real_phishing_data.json")
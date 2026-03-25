# ============================================================
# ThreatMind v3 - Psychological Threat Actor Profiler
# Analyzes attacker artifacts to build behavioral profiles
# ============================================================
#
# CONCEPT: This is forensic linguistics + behavioral psychology
# applied to cybersecurity. Every signal we extract here is
# based on real techniques used by intelligence agencies and
# threat hunting teams to attribute attacks to specific actors.
# ============================================================

import json
import re
from colorama import Fore, init

init(autoreset=True)

# ── BEHAVIORAL SIGNAL LIBRARIES ───────────────────────────

# Words that indicate financial motivation
FINANCIAL_INDICATORS = [
    "bitcoin", "payment", "ransom", "decrypt", "wallet",
    "money", "pay", "transfer", "price", "cost", "fee",
    "btc", "crypto", "monero", "deadline", "hours"
]

# Words that indicate ideological/hacktivist motivation
IDEOLOGICAL_INDICATORS = [
    "government", "corrupt", "justice", "freedom", "truth",
    "expose", "leak", "anonymous", "operation", "protest",
    "war", "resistance", "people", "fight", "regime"
]

# Words that indicate nation-state / espionage motivation
ESPIONAGE_INDICATORS = [
    "intelligence", "classified", "military", "defense",
    "government", "ministry", "embassy", "infrastructure",
    "critical", "strategic", "national", "state"
]

# Linguistic markers suggesting non-native English
NON_NATIVE_PATTERNS = [
    r"\byour files (is|are) encrypt",     # Grammar error common in Eastern European actors
    r"\bwrite (us|me) (on|to) email",     # Unusual preposition usage
    r"\bdo not (worry|be afraid)",        # Overly formal phrasing
    r"\bwe (guarantee|ensure) (you)?",    # Formal reassurance pattern
    r"\ball (your|of your) files",        # Repetitive structure
    r"\bfor (free|nothing)",              # Unusual phrasing
]

# Patterns suggesting high technical skill
HIGH_SKILL_PATTERNS = [
    r"aes.{0,10}(256|128)",              # Mentions specific encryption
    r"rsa.{0,10}\d{4}",                  # Mentions RSA key sizes
    r"shadow (copies|volume)",            # Knows to delete backups
    r"(backup|restore) (point|file)",     # Understands recovery mechanisms
    r"domain (admin|controller)",         # Understands enterprise environments
]

# Patterns suggesting lower technical skill
LOW_SKILL_PATTERNS = [
    r"click (the|this) link",            # Simple social engineering
    r"call (us|this number)",            # Phone-based scam indicator
    r"your (computer|pc) (is|has been)", # Common scareware phrasing
    r"microsoft (support|technician)",   # Tech support scam
]


class ThreatActorProfiler:
    """
    Builds psychological and operational profiles of threat actors
    from text artifacts — ransom notes, phishing emails, malware comments.

    CONCEPT: Text is evidence. Every word choice, every grammatical
    pattern, every psychological technique reveals something about
    the person who wrote it. We're teaching the computer to read
    between the lines.
    """

    def __init__(self):
        print(Fore.CYAN + "[*] Threat Actor Profiler initialized")
        print(Fore.CYAN + "[*] Behavioral psychology engine loaded")
        print(Fore.CYAN + "[*] Linguistic analysis patterns loaded\n")

    def analyze_motivation(self, text):
        """
        Determines WHY the attacker is doing this.
        CONCEPT: Motivation shapes everything — target selection,
        technique choice, communication style, negotiation behavior.
        """
        text_lower = text.lower()

        scores = {
            "Financial":    sum(1 for w in FINANCIAL_INDICATORS   if w in text_lower),
            "Ideological":  sum(1 for w in IDEOLOGICAL_INDICATORS if w in text_lower),
            "Espionage":    sum(1 for w in ESPIONAGE_INDICATORS   if w in text_lower),
        }

        # Find dominant motivation
        primary = max(scores, key=scores.get)
        confidence = min(scores[primary] * 15, 90)

        if scores[primary] == 0:
            primary = "Unknown"
            confidence = 10

        return {
            "primary":    primary,
            "confidence": confidence,
            "scores":     scores
        }

    def analyze_skill_level(self, text, alerts=None):
        """
        Determines HOW sophisticated the attacker is.
        CONCEPT: Skill level determines what defenses can stop them.
        A script kiddie and an APT group need completely different responses.
        """
        text_lower = text.lower()
        skill_score = 50  # Start neutral

        # Technical language increases skill score
        high_matches = sum(1 for p in HIGH_SKILL_PATTERNS if re.search(p, text_lower))
        low_matches  = sum(1 for p in LOW_SKILL_PATTERNS  if re.search(p, text_lower))

        skill_score += high_matches * 15
        skill_score -= low_matches  * 15

        # Attack chain complexity from SIEM alerts
        if alerts:
            unique_techniques = len(set(a.get("mitre_id") for a in alerts))
            skill_score += unique_techniques * 10

        skill_score = max(0, min(skill_score, 100))

        if skill_score >= 75:
            level = "Advanced"
            description = "Sophisticated actor — likely organized group or nation-state"
        elif skill_score >= 50:
            level = "Intermediate"
            description = "Experienced attacker — knows standard tools and techniques"
        elif skill_score >= 25:
            level = "Basic"
            description = "Limited skill — likely using pre-built tools and scripts"
        else:
            level = "Novice"
            description = "Script kiddie — following tutorials, minimal original capability"

        return {
            "level":       level,
            "score":       skill_score,
            "description": description
        }

    def analyze_origin(self, text):
        """
        Looks for linguistic clues about the attacker's origin.
        CONCEPT: Language is deeply ingrained. Even when writing in
        English, non-native speakers leave patterns from their mother tongue.
        Intelligence agencies have used this for decades.
        """
        text_lower = text.lower()

        non_native_matches = [
            p for p in NON_NATIVE_PATTERNS
            if re.search(p, text_lower)
        ]

        if len(non_native_matches) >= 2:
            origin = "Likely non-native English speaker"
            confidence = min(len(non_native_matches) * 25, 85)
        elif len(non_native_matches) == 1:
            origin = "Possibly non-native English speaker"
            confidence = 35
        else:
            origin = "Native English or professionally translated"
            confidence = 40

        return {
            "assessment":  origin,
            "confidence":  confidence,
            "indicators":  len(non_native_matches)
        }

    def analyze_emotional_state(self, text):
        """
        Reads the emotional tone of the attacker's writing.
        CONCEPT: Emotional state predicts behavior.
        Calm = patient, organized, likely to follow through on threats.
        Aggressive = impulsive, may make mistakes, higher escalation risk.
        """
        text_lower = text.lower()

        # Urgency/aggression indicators
        urgency_words = [
            "immediately", "urgent", "warning", "final",
            "last chance", "do not", "never", "destroy",
            "permanently", "deadline", "hours", "days only"
        ]

        # Calm/professional indicators
        calm_words = [
            "please", "kindly", "we understand", "unfortunately",
            "however", "guarantee", "ensure", "professional",
            "service", "support", "contact us"
        ]

        urgency_score = sum(1 for w in urgency_words if w in text_lower)
        calm_score    = sum(1 for w in calm_words    if w in text_lower)

        if urgency_score > calm_score + 2:
            state = "Aggressive/Pressuring"
            risk  = "Higher escalation risk — may destroy data if demands not met"
        elif calm_score > urgency_score + 2:
            state = "Calm/Professional"
            risk  = "Calculated actor — likely to follow through methodically"
        else:
            state = "Mixed/Neutral"
            risk  = "Unpredictable — monitor closely"

        return {
            "state": state,
            "risk":  risk,
            "urgency_signals": urgency_score,
            "calm_signals":    calm_score
        }

    def determine_actor_type(self, motivation, skill, emotional_state):
        """
        Combines all signals to classify the type of threat actor.
        CONCEPT: Actor classification directly informs response strategy.
        You respond very differently to ransomware vs nation-state espionage.
        """
        m = motivation["primary"]
        s = skill["level"]
        e = emotional_state["state"]

        if m == "Espionage" and s in ["Advanced", "Intermediate"]:
            return "Nation-State / APT Group"
        elif m == "Financial" and s == "Advanced" and "Calm" in e:
            return "Organized Ransomware Group (e.g. LockBit, REvil pattern)"
        elif m == "Financial" and s in ["Basic", "Novice"]:
            return "Opportunistic Cybercriminal"
        elif m == "Ideological":
            return "Hacktivist Group (e.g. Anonymous pattern)"
        elif m == "Financial" and "Aggressive" in e:
            return "Aggressive Ransomware Actor — High Risk"
        else:
            return "Unclassified Threat Actor"

    def build_profile(self, text, alerts=None, source_label="Unknown"):
        """
        Master method — runs all analysis and builds the complete profile.
        This is what gets shown in the dashboard and threat reports.
        """
        print(Fore.CYAN + f"[*] Profiling artifact from: {source_label}\n")

        motivation     = self.analyze_motivation(text)
        skill          = self.analyze_skill_level(text, alerts)
        origin         = self.analyze_origin(text)
        emotional      = self.analyze_emotional_state(text)
        actor_type     = self.determine_actor_type(motivation, skill, emotional)

        profile = {
            "source":         source_label,
            "actor_type":     actor_type,
            "motivation":     motivation,
            "skill_level":    skill,
            "origin":         origin,
            "emotional_state":emotional,
        }

        self.print_profile(profile)
        return profile

    def print_profile(self, profile):
        """Prints the profile in a clean, readable format"""
        print(Fore.RED + "  ┌─────────────────────────────────────────┐")
        print(Fore.RED + "  │      THREAT ACTOR PROFILE               │")
        print(Fore.RED + "  └─────────────────────────────────────────┘")

        print(Fore.YELLOW + f"\n  Actor Type:    {profile['actor_type']}")
        print(Fore.WHITE  + f"  Motivation:    {profile['motivation']['primary']} "
                          + f"(confidence: {profile['motivation']['confidence']}%)")
        print(Fore.WHITE  + f"  Skill Level:   {profile['skill_level']['level']} "
                          + f"(score: {profile['skill_level']['score']}/100)")
        print(Fore.WHITE  + f"  Origin:        {profile['origin']['assessment']} "
                          + f"(confidence: {profile['origin']['confidence']}%)")
        print(Fore.WHITE  + f"  Emotional:     {profile['emotional_state']['state']}")
        print(Fore.YELLOW + f"  Risk Note:     {profile['emotional_state']['risk']}")
        print(Fore.WHITE  + f"  Description:   {profile['skill_level']['description']}")
        print()


# ── TEST WITH REAL RANSOM NOTE SAMPLES ────────────────────
# These are based on real ransom note patterns from known groups
# Sanitized and modified for educational use

SAMPLE_ARTIFACTS = [
    {
        "label": "Sample Ransom Note A (Financial Actor)",
        "text": """
        Your files have been encrypted using AES-256 encryption.
        All your backups and shadow copies have been deleted.
        To decrypt your files you must pay 0.5 Bitcoin to our wallet.
        You have 72 hours to make the payment before the price doubles.
        Do not contact the FBI or police — if you do, we will permanently
        destroy your decryption key. Contact us immediately at our email.
        We guarantee that after payment your files will be restored.
        """
    },
    {
        "label": "Sample Phishing Email (Low Skill Actor)",
        "text": """
        Dear user, your account has been suspended.
        Click this link to verify your microsoft account immediately.
        Your computer is at risk. Call our support technician now.
        Please provide your password to restore access.
        This is your final warning before your account is deleted.
        """
    },
    {
        "label": "Sample Hacktivist Message (Ideological Actor)",
        "text": """
        We are Anonymous. We have exposed the corrupt government files.
        The truth about this regime will be revealed to the people.
        We fight for freedom and justice. This is our operation against
        those who oppress. We will not stop until the truth is free.
        Expect us. We do not forgive. We do not forget.
        """
    }
]


if __name__ == "__main__":
    print(Fore.RED + """
╔══════════════════════════════════════════╗
║  THREATMIND v3 — PSYCHOLOGICAL PROFILER ║
╚══════════════════════════════════════════╝
    """)

    profiler = ThreatActorProfiler()

    for artifact in SAMPLE_ARTIFACTS:
        print(Fore.CYAN + "="*55)
        print(Fore.CYAN + f"  Analyzing: {artifact['label']}")
        print(Fore.CYAN + "="*55)
        profile = profiler.build_profile(
            text=artifact["text"],
            source_label=artifact["label"]
        )
        print()
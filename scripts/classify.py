"""
OPENTHREAT — classify.py
======================
What an item IS, inferred from its text: threat actors named in it,
severity, category, and CVE ids.

Moved out of fetch_intel.py unchanged; fetch_intel re-exports every name here,
so `fetch_intel.THREAT_ACTORS` and the like keep working.
"""

import re




# ── Threat Actor Detection ────────────────────────────────────────────────────

THREAT_ACTORS = {
    "Lazarus": ["lazarus", "hidden cobra", "zinc", "labyrinth chollima"],
    "APT29": ["apt29", "cozy bear", "cozy duke", "yttrium"],
    "APT28": ["apt28", "fancy bear", "sednit", "pawn storm", "strontium"],
    "APT41": ["apt41", "barium", "winnti", "wicked panda"],
    "APT1": ["apt1", "comment crew"],
    "APT32": ["apt32", "oceanlotus", "fin6", "gold dragon"],
    "APT33": ["apt33", "elfin", "shamoon"],
    "APT34": ["apt34", "oilrig"],
    "FIN7": ["fin7", "carbanak"],
    "DarkSide": ["darkside", "blackmatter"],
    "REvil": ["revil", "sodinokibi"],
    "LockBit": ["lockbit"],
    "BlackCat": ["blackcat", "alphv"],
    "Clop": ["clop", "cl0p"],
    "Conti": ["conti", "wizard spider"],
    "TrickBot": ["trickbot"],
    "Emotet": ["emotet", "heodo"],
    "Sandworm": ["sandworm", "voodoo bear"],
    "Nobelium": ["nobelium", "solarwinds"],
    "FunkSec": ["funksec"],
    "MirrorFace": ["mirrorface"],
    "Salt Typhoon": ["salt typhoon"],
    # ── Expanded set ────────────────────────────────────────────────────────
    # The geopolitical view is only as good as actor detection: with ~22 groups
    # a typical run surfaced a single attributed origin. These are the groups
    # that actually recur in the feeds this pipeline reads.
    "Volt Typhoon": ["volt typhoon", "vanguard panda", "bronze silhouette"],
    "Flax Typhoon": ["flax typhoon", "ethereal panda"],
    "Silk Typhoon": ["silk typhoon", "hafnium"],
    "Midnight Blizzard": ["midnight blizzard"],
    "Star Blizzard": ["star blizzard", "callisto", "seaborgium"],
    "Secret Blizzard": ["secret blizzard", "turla", "venomous bear", "snake malware"],
    "Forest Blizzard": ["forest blizzard"],
    "Kimsuky": ["kimsuky", "velvet chollima", "black banshee", "thallium"],
    "Andariel": ["andariel", "onyx sleet", "silent chollima"],
    "BlueNoroff": ["bluenoroff", "sapphire sleet", "stardust chollima"],
    "Charming Kitten": ["charming kitten", "apt35", "phosphorus", "mint sandstorm"],
    "MuddyWater": ["muddywater", "mango sandstorm", "static kitten"],
    "Scattered Spider": ["scattered spider", "octo tempest", "unc3944", "muddled libra"],
    "APT10": ["apt10", "stone panda", "menupass", "cicada"],
    "APT27": ["apt27", "emissary panda", "lucky mouse", "bronze union"],
    "APT37": ["apt37", "reaper", "scarcruft", "ricochet chollima"],
    "APT38": ["apt38", "bluenoroff group"],
    "APT39": ["apt39", "chafer", "remix kitten"],
    "APT40": ["apt40", "leviathan", "kryptonite panda", "gingham typhoon"],
    "APT43": ["apt43", "kimsuky group", "thallium group"],
    "Mustang Panda": ["mustang panda", "twill typhoon", "bronze president"],
    "Gamaredon": ["gamaredon", "primitive bear", "armageddon", "shuckworm"],
    "TA505": ["ta505", "graceful spider", "evil corp"],
    "Wizard Spider": ["ryuk"],
    "Black Basta": ["black basta"],
    "Play": ["play ransomware", "playcrypt"],
    "Akira": ["akira ransomware"],
    "Rhysida": ["rhysida"],
    "Medusa": ["medusa ransomware", "medusalocker"],
    "BianLian": ["bianlian"],
    "Royal": ["royal ransomware"],
    "Hive": ["hive ransomware"],
    "Vice Society": ["vice society"],
    "Qilin": ["qilin", "agenda ransomware"],
    "INC Ransom": ["inc ransom", "inc ransomware"],
    "Cl0p": ["cl0p ransomware"],
    "8Base": ["8base"],
    "Everest": ["everest ransomware"],
    "SafePay": ["safepay"],
    "RansomHub": ["ransomhub"],
    "Lapsus$": ["lapsus", "lapsus$"],
    "Anonymous Sudan": ["anonymous sudan"],
    "Killnet": ["killnet"],
    "NoName057": ["noname057", "noname057(16)"],
    "Sidewinder": ["sidewinder", "rattlesnake"],
    "Transparent Tribe": ["transparent tribe", "apt36", "mythic leopard"],
    "Patchwork": ["patchwork", "dropping elephant"],
    "Winnti Group": ["winnti group"],
    "Storm-0558": ["storm-0558"],
    "UNC5537": ["unc5537"],
}

# Pre-compile a word-boundary regex per alias so "apt" no longer matches
# "adapter"/"adapt" and "clop" no longer matches "develop". Aliases with their
# own separators (spaces, digits, "cl0p") still match as whole tokens because
# \b sits at the alnum/non-alnum transition on each end.
_ACTOR_PATTERNS = {
    actor: [re.compile(r"(?<![0-9A-Za-z])" + re.escape(kw) + r"(?![0-9A-Za-z])", re.IGNORECASE)
            for kw in keywords]
    for actor, keywords in THREAT_ACTORS.items()
}

def detect_threat_actors(text: str) -> list[str]:
    if not text:
        return []
    actors = []
    for actor, patterns in _ACTOR_PATTERNS.items():
        if any(p.search(text) for p in patterns):
            actors.append(actor)
    # Preserve THREAT_ACTORS declaration order, no dupes.
    return actors


# Keyword sets for rule-based classification. Matched as WHOLE TOKENS — the
# original `kw in text` form fired "rce" inside "source"/"force"/"resource",
# which mislabelled 31% of all `critical` items and, because ALERT_SEVERITIES
# defaults to `critical`, sent those false positives straight to Slack.
_SEVERITY_KEYWORDS = [
    ("critical", ["critical", "zero-day", "0-day", "actively exploited", "rce",
                  "remote code execution", "unauthenticated", "wormable",
                  "exploited in the wild", "pre-auth"]),
    ("high",     ["high", "privilege escalation", "authentication bypass",
                  "ransomware", "data breach", "nation-state", "apt",
                  "sandbox escape", "arbitrary code"]),
    ("medium",   ["medium", "xss", "csrf", "injection", "phishing", "malware",
                  "denial of service", "dos", "information disclosure"]),
    ("low",      ["low", "informational", "advisory", "guide"]),
]

_CATEGORY_KEYWORDS = [
    ("cve",      ["cve", "vulnerability", "vulnerabilities", "patch", "exploit",
                  "nvd", "advisory id", "security update"]),
    ("incident", ["breach", "attack", "ransomware", "hack", "hacked", "intrusion",
                  "stolen", "compromised", "leaked", "incident", "victim"]),
    ("advisory", ["advisory", "alert", "directive", "guidance", "warning",
                  "cisa", "recommendation", "patch tuesday", "bulletin"]),
]


def _compile_keyword_matcher(keywords: list[str]) -> re.Pattern:
    """Whole-token alternation. Lookarounds rather than \b so that keywords
    containing digits or spaces ("0-day", "patch tuesday") still match."""
    return re.compile(
        r"(?<![0-9A-Za-z])(?:"
        + "|".join(re.escape(k) for k in sorted(keywords, key=len, reverse=True))
        + r")(?![0-9A-Za-z])",
        re.IGNORECASE,
    )


_SEVERITY_MATCHERS = [(label, _compile_keyword_matcher(kws)) for label, kws in _SEVERITY_KEYWORDS]
_CATEGORY_MATCHERS = [(label, _compile_keyword_matcher(kws)) for label, kws in _CATEGORY_KEYWORDS]


def infer_severity(text: str, default: str = "medium") -> str:
    """Infer severity from text via whole-token keyword matching, most severe first."""
    if not text:
        return default
    for label, pattern in _SEVERITY_MATCHERS:
        if pattern.search(text):
            return label
    return default


def infer_category(text: str, default: str = "news") -> str:
    """Infer category from text via whole-token keyword matching."""
    if not text:
        return default
    for label, pattern in _CATEGORY_MATCHERS:
        if pattern.search(text):
            return label
    return default


def extract_cve_id(text: str) -> str | None:
    match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


_CVE_EXACT = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def valid_cve_id(value) -> str | None:
    """Return the normalised CVE id only if it is EXACTLY well-formed.

    Several fetchers take cve_id straight from an upstream API field. A
    startswith("CVE-") check is not validation: "CVE-../../x" passes it, and
    that value goes on to build a cache filename. Anything not matching the
    full pattern is dropped rather than trusted.
    """
    if not value:
        return None
    text = str(value).strip()
    return text.upper() if _CVE_EXACT.match(text) else None

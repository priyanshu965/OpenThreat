"""
CYBERWATCH — provenance.py
==========================
Tag every item with WHO PRODUCED IT.

This is the honest version of the "HUMINT" request. Human intelligence means
collection from human sources — agents, informants, debriefs — and this project
has no collection capability, so labelling scraped blog posts HUMINT would be a
category error that misleads anyone reading the dashboard.

What is genuinely useful, and what this does, is separate human-authored
intelligence from machine-generated feeds. A Unit 42 analyst write-up, a
ransomware crew's own leak-site post and an automated URLhaus row are three
different epistemic objects; the feed previously flattened them into one.

    vendor-research        a named security vendor's research team
    independent-researcher an individual researcher or small outfit
    journalism             reporters covering security
    government             CERTs, agencies, national advisories
    vendor-advisory        a vendor disclosing its own product's flaw
    adversary-authored     the attacker's own words (leak-site posts)
    automated-feed         machine-generated indicators, no human author

Provenance is derived from the SOURCE, not guessed from text, so it costs
nothing at runtime and cannot be wrong in the way a classifier can.
"""

from __future__ import annotations

VENDOR_RESEARCH = "vendor-research"
INDEPENDENT = "independent-researcher"
JOURNALISM = "journalism"
GOVERNMENT = "government"
VENDOR_ADVISORY = "vendor-advisory"
ADVERSARY = "adversary-authored"
AUTOMATED = "automated-feed"

PROVENANCE_ORDER = [
    ADVERSARY, VENDOR_RESEARCH, INDEPENDENT, GOVERNMENT,
    JOURNALISM, VENDOR_ADVISORY, AUTOMATED,
]

PROVENANCE_LABELS = {
    VENDOR_RESEARCH: "Vendor research",
    INDEPENDENT: "Independent researcher",
    JOURNALISM: "Journalism",
    GOVERNMENT: "Government / CERT",
    VENDOR_ADVISORY: "Vendor advisory",
    ADVERSARY: "Adversary-authored",
    AUTOMATED: "Automated feed",
}

# Short note explaining what each class is worth to a reader, shown in the UI.
PROVENANCE_NOTES = {
    VENDOR_RESEARCH: "Written by a named research team. Usually first-hand telemetry.",
    INDEPENDENT: "An individual researcher. Often earliest, varies in rigour.",
    JOURNALISM: "Reported, not researched. Good for context and confirmation.",
    GOVERNMENT: "Official advisory. Authoritative, usually lagging.",
    VENDOR_ADVISORY: "A vendor disclosing its own flaw. Definitive on scope.",
    ADVERSARY: "The attacker's own claim. Self-serving and often exaggerated, "
               "but it is the adversary speaking directly.",
    AUTOMATED: "Machine-generated indicators. No human author, no narrative.",
}

# Source name -> provenance. Anything unlisted falls back to AUTOMATED, which is
# the cautious default: it claims the least.
_SOURCE_PROVENANCE = {
    # Government / CERT
    "CISA": GOVERNMENT,
    "NVD": GOVERNMENT,
    "Mitre CWE": GOVERNMENT,
    "SANS ISC": GOVERNMENT,

    # Vendor advisories (disclosing their own or their distro's flaws)
    "MSRC": VENDOR_ADVISORY,
    "GitHub Advisories": VENDOR_ADVISORY,
    "ZDI": VENDOR_ADVISORY,
    "VMware": VENDOR_ADVISORY,
    "Fedora": VENDOR_ADVISORY,
    "Gentoo": VENDOR_ADVISORY,
    "Arch Linux": VENDOR_ADVISORY,
    "Amazon Linux": VENDOR_ADVISORY,
    "CentOS Stream": VENDOR_ADVISORY,
    "CentOS": VENDOR_ADVISORY,

    # Vendor research teams
    "Cisco Talos": VENDOR_RESEARCH,
    "Unit 42": VENDOR_RESEARCH,
    "ESET WeLiveSecurity": VENDOR_RESEARCH,
    "Securelist": VENDOR_RESEARCH,
    "Check Point Research": VENDOR_RESEARCH,
    "Microsoft Security": VENDOR_RESEARCH,
    "SentinelOne": VENDOR_RESEARCH,
    "Malwarebytes": VENDOR_RESEARCH,
    "Recorded Future": VENDOR_RESEARCH,

    # Independent researchers / community
    "Krebs on Security": INDEPENDENT,
    "Graham Cluley": INDEPENDENT,
    "Reddit/netsec": INDEPENDENT,
    "PoC-in-GitHub": INDEPENDENT,

    # Journalism
    "The Hacker News": JOURNALISM,
    "Bleeping Computer": JOURNALISM,
    "Dark Reading": JOURNALISM,
    "SecurityWeek": JOURNALISM,
    "TheRecord Media": JOURNALISM,
    "CyberSecurity News": JOURNALISM,

    # Adversary-authored: leak-site posts are written BY the attacker.
    "Ransomware.live": ADVERSARY,

    # Automated indicator feeds
    "URLhaus": AUTOMATED,
    "ThreatFox": AUTOMATED,
    "MalwareBazaar": AUTOMATED,
    "Feodo Tracker": AUTOMATED,
    "Spamhaus": AUTOMATED,
    "SSL Blacklist": AUTOMATED,
    "AlienVault OTX": AUTOMATED,
    "AbuseIPDB": AUTOMATED,
    "PhishTank": AUTOMATED,
    # Leak-site posts are the crew's own marketing, republished. The adversary
    # is speaking, so this is not an automated indicator feed.
    "RansomLook": ADVERSARY,
}

# Which classes were written by a person. Used for the "human-authored" filter.
HUMAN_AUTHORED = {VENDOR_RESEARCH, INDEPENDENT, JOURNALISM, GOVERNMENT,
                  VENDOR_ADVISORY, ADVERSARY}


# Allow-list, so a fetcher hint cannot introduce an arbitrary label.
_VALID_PROVENANCE = set(HUMAN_AUTHORED) | {AUTOMATED}


def classify_provenance(item: dict) -> str:
    """Source registry first, but a fetcher may override with an explicit hint.

    Some sources carry more than one kind of content, and the fetcher knows
    which. RansomLook posts are the adversary's own words, which the registry
    alone would flatten to "automated-feed" and lose the distinction that
    matters most about them.
    """
    hint = item.get("provenance_hint")
    if hint and hint in _VALID_PROVENANCE:
        return hint
    return _SOURCE_PROVENANCE.get(item.get("source", ""), AUTOMATED)


def annotate_provenance(items: list[dict]) -> dict[str, int]:
    """Tag every item in place; return a provenance -> count breakdown."""
    counts: dict[str, int] = {}
    for item in items:
        prov = classify_provenance(item)
        item["provenance"] = prov
        item["human_authored"] = prov in HUMAN_AUTHORED
        counts[prov] = counts.get(prov, 0) + 1
    return counts

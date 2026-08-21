"""Shared pipeline utilities — imported by fetch_intel.py and tests."""

import re
from typing import Optional


_CVSS_PATTERN = re.compile(r"CVSS[:\s]*([0-9]+\.[0-9])", re.IGNORECASE)
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

_EXTRACTORS = {
    "ipv4": re.compile(r"(?<![.\d])(?:\d{1,3}\.){3}\d{1,3}(?![.\d])"),
    "domain": re.compile(r"(?<![a-z0-9.-])[a-z0-9.-]+\.[a-z]{2,}(?![a-z0-9.-])", re.I),
    "url": re.compile(r"https?://[^\s<>{}]+", re.I),
    "sha256": re.compile(r"(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])", re.I),
    "sha1": re.compile(r"(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])", re.I),
    "md5": re.compile(r"(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])", re.I),
    "email": re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", re.I),
    "cidr": re.compile(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}"),
}

# IOC types that are exported (matches exports.py _EXPORT_TYPES)
EXPORT_IOC_TYPES = ["ipv4", "domain", "url", "sha256", "sha1", "md5", "email", "cidr"]


def extract_cve_id(text: str) -> Optional[str]:
    """Extract the first CVE ID from text."""
    m = _CVE_PATTERN.search(text)
    return m.group(0).upper() if m else None


def infer_severity(text: str, default: str = "medium") -> str:
    """Infer severity from text using keyword matching."""
    t = text.lower()
    if any(kw in t for kw in ["critical", "zero-day", "0-day", "actively exploited",
                                "rce", "remote code execution", "unauthenticated", "wormable"]):
        return "critical"
    if any(kw in t for kw in ["high", "privilege escalation", "authentication bypass",
                                "ransomware", "data breach", "nation-state", "apt"]):
        return "high"
    if any(kw in t for kw in ["medium", "xss", "csrf", "injection", "phishing", "malware"]):
        return "medium"
    if any(kw in t for kw in ["low", "informational", "advisory", "guide"]):
        return "low"
    return default


def infer_category(text: str, default: str = "news") -> str:
    """Infer category from text using keyword matching."""
    t = text.lower()
    if any(kw in t for kw in ["cve-", "vulnerability", "patch", "exploit", "nvd"]):
        return "cve"
    if any(kw in t for kw in ["breach", "attack", "ransomware", "hack", "intrusion",
                                "stolen", "compromised", "leaked", "incident"]):
        return "incident"
    if any(kw in t for kw in ["advisory", "alert", "directive", "guidance", "warning",
                                "cisa", "recommendation", "patch tuesday"]):
        return "advisory"
    return default


def extract_iocs(text: str) -> dict:
    """Extract IOCs from text using regex patterns."""
    if not text:
        return {}
    iocs = {}
    for ioc_type, pat in _EXTRACTORS.items():
        found = list(set(pat.findall(text)))
        if found:
            iocs[ioc_type] = found
    return iocs


def compute_priority(cvss: Optional[float], epss: Optional[float], kev: bool) -> Optional[dict]:
    """Compute priority score from CVSS, EPSS, and KEV status."""
    if cvss is None and epss is None and not kev:
        return None
    cvss_val = max(0.0, min(10.0, cvss or 0.0))
    epss_val = max(0.0, min(1.0, epss or 0.0))
    cvss_w, epss_w, kev_bonus = 40.0, 40.0, 20.0
    score = cvss_w * (cvss_val / 10.0) + epss_w * epss_val
    if kev:
        score += kev_bonus
        score = max(score, 90.0)
    score = round(max(0.0, min(100.0, score)), 1)
    if score >= 90:
        label = "urgent"
    elif score >= 70:
        label = "elevated"
    elif score >= 40:
        label = "moderate"
    else:
        label = "low"
    reasons = []
    if kev:
        reasons.append("CISA KEV")
    if epss is not None:
        reasons.append(f"EPSS {epss_val * 100:.1f}%")
    if cvss is not None:
        reasons.append(f"CVSS {cvss_val:.1f}")
    return {"score": score, "label": label, "rationale": " · ".join(reasons)}


def cvss_to_severity(cvss: Optional[float]) -> str:
    """Convert CVSS score to severity string."""
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"
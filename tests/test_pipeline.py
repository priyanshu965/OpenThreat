"""Unit tests for CyberWatch pipeline helpers."""

import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

# ── Helpers extracted from fetch_intel.py for isolated testing ──────────────

_CVSS_PATTERN = re.compile(r"CVSS[:\s]*([0-9]+\.[0-9])", re.IGNORECASE)
_CVE_PATTERN  = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

def extract_cve_id(text: str) -> str | None:
    m = _CVE_PATTERN.search(text)
    return m.group(0).upper() if m else None

def infer_severity(text: str, default: str = "medium") -> str:
    t = text.lower()
    if any(kw in t for kw in ["critical", "zero-day", "0-day", "actively exploited",
                                "rce", "remote code execution", "unauthenticated",
                                "wormable"]):
        return "critical"
    if any(kw in t for kw in ["high", "privilege escalation", "authentication bypass",
                                "ransomware", "data breach", "nation-state", "apt"]):
        return "high"
    if any(kw in t for kw in ["medium", "xss", "csrf", "injection", "phishing",
                                "malware"]):
        return "medium"
    if any(kw in t for kw in ["low", "informational", "advisory", "guide"]):
        return "low"
    return default


def infer_category(text: str, default: str = "news") -> str:
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

_EXTRACTORS = {
    "ipv4": re.compile(r"(?<![.\d])(?:\d{1,3}\.){3}\d{1,3}(?![.\d])"),
    "md5":  re.compile(r"(?<![a-f0-9])[a-f0-9]{32}(?![a-f0-9])", re.I),
    "sha1": re.compile(r"(?<![a-f0-9])[a-f0-9]{40}(?![a-f0-9])", re.I),
}

def extract_iocs(text: str) -> dict:
    if not text:
        return {}
    iocs = {}
    for ioc_type, pat in _EXTRACTORS.items():
        found = list(set(pat.findall(text)))
        if found:
            iocs[ioc_type] = found
    return iocs


def compute_priority(cvss: float | None, epss: float | None, kev: bool) -> dict | None:
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
    if score >= 90:   label = "urgent"
    elif score >= 70: label = "elevated"
    elif score >= 40: label = "moderate"
    else:             label = "low"
    reasons = []
    if kev:
        reasons.append("CISA KEV")
    if epss is not None:
        reasons.append(f"EPSS {epss_val * 100:.1f}%")
    if cvss is not None:
        reasons.append(f"CVSS {cvss_val:.1f}")
    return {"score": score, "label": label, "rationale": " · ".join(reasons)}


# ── Tests ────────────────────────────────────────────────────────────────────

class TestCveExtraction(unittest.TestCase):
    def test_standard_cve(self):
        self.assertEqual(extract_cve_id("CVE-2024-1234 found in the wild"), "CVE-2024-1234")

    def test_cve_in_text(self):
        self.assertEqual(extract_cve_id("See CVE-2023-49113 for details"), "CVE-2023-49113")

    def test_no_cve(self):
        self.assertIsNone(extract_cve_id("No vulnerability here"))

    def test_multiple_cves_returns_first(self):
        self.assertEqual(extract_cve_id("CVE-2024-1111 and CVE-2024-2222"), "CVE-2024-1111")


class TestSeverityInference(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(infer_severity("critical rce vulnerability"), "critical")
        self.assertEqual(infer_severity("zero-day exploit released"), "critical")
        self.assertEqual(infer_severity("actively exploited in the wild"), "critical")

    def test_high(self):
        self.assertEqual(infer_severity("privilege escalation in kernel"), "high")
        self.assertEqual(infer_severity("data breach at major corp"), "high")

    def test_medium(self):
        self.assertEqual(infer_severity("xss vulnerability in plugin"), "medium")
        self.assertEqual(infer_severity("phishing campaign detected"), "medium")

    def test_low(self):
        self.assertEqual(infer_severity("informational guide released"), "low")

    def test_default(self):
        self.assertEqual(infer_severity("something random here"), "medium")


class TestCategoryInference(unittest.TestCase):
    def test_cve_category(self):
        self.assertEqual(infer_category("CVE-2024-1234 in Apache"), "cve")
        self.assertEqual(infer_category("new vulnerability in nginx"), "cve")

    def test_incident_category(self):
        self.assertEqual(infer_category("data breach at company"), "incident")
        self.assertEqual(infer_category("ransomware attack"), "incident")

    def test_advisory_category(self):
        self.assertEqual(infer_category("cisa advisory released"), "advisory")
        self.assertEqual(infer_category("security advisory update"), "advisory")

    def test_news_default(self):
        self.assertEqual(infer_category("something else entirely"), "news")


class TestIocExtraction(unittest.TestCase):
    def test_ipv4_extraction(self):
        result = extract_iocs("malicious IP 192.168.1.1 was observed")
        self.assertIn("ipv4", result)
        self.assertIn("192.168.1.1", result["ipv4"])

    def test_md5_extraction(self):
        result = extract_iocs("file hash: d41d8cd98f00b204e9800998ecf8427e")
        self.assertIn("md5", result)
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", result["md5"])

    def test_sha1_extraction(self):
        result = extract_iocs("sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertIn("sha1", result)
        self.assertIn("da39a3ee5e6b4b0d3255bfef95601890afd80709", result["sha1"])

    def test_no_iocs(self):
        self.assertEqual(extract_iocs(""), {})
        self.assertEqual(extract_iocs("just a plain description"), {})

    def test_multiple_iocs(self):
        result = extract_iocs("IP 10.0.0.1 and hash d41d8cd98f00b204e9800998ecf8427e")
        self.assertIn("ipv4", result)
        self.assertIn("md5", result)
        self.assertIn("10.0.0.1", result["ipv4"])
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", result["md5"])


class TestPriorityScoring(unittest.TestCase):
    def test_urgent_kev(self):
        result = compute_priority(5.0, 0.1, kev=True)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result["score"], 90)
        self.assertEqual(result["label"], "urgent")

    def test_elevated(self):
        # CVSS=10 + EPSS=0.75 → 40*1 + 40*0.75 = 70 → "elevated"
        result = compute_priority(10.0, 0.75, kev=False)
        self.assertIsNotNone(result)
        self.assertEqual(result["label"], "elevated")

    def test_none_on_no_data(self):
        self.assertIsNone(compute_priority(None, None, kev=False))

    def test_rationale_includes_kev(self):
        result = compute_priority(None, None, kev=True)
        self.assertIn("CISA KEV", result["rationale"])
        self.assertEqual(result["score"], 90.0)


if __name__ == "__main__":
    unittest.main()

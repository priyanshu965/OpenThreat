"""Unit tests for CyberWatch pipeline helpers.

These import the REAL implementations from scripts/fetch_intel.py.

The previous version of this file re-implemented extract_cve_id, infer_severity,
infer_category, extract_iocs and compute_priority inside the test module and
then tested those copies, so all 30 tests passed while exercising zero lines of
production code — including a verbatim copy of the `rce`-substring bug that
mislabelled 31% of all `critical` items.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import fetch_intel as fi                                     # noqa: E402
from mitre_ttps import map_ttps                              # noqa: E402


class TestCveExtraction(unittest.TestCase):
    def test_standard_cve(self):
        self.assertEqual(fi.extract_cve_id("CVE-2024-1234 found in the wild"), "CVE-2024-1234")

    def test_lowercase_is_normalised(self):
        self.assertEqual(fi.extract_cve_id("see cve-2023-49113"), "CVE-2023-49113")

    def test_no_cve(self):
        self.assertIsNone(fi.extract_cve_id("No vulnerability here"))

    def test_multiple_cves_returns_first(self):
        self.assertEqual(fi.extract_cve_id("CVE-2024-1111 and CVE-2024-2222"), "CVE-2024-1111")


class TestSeverityInference(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(fi.infer_severity("critical rce vulnerability"), "critical")
        self.assertEqual(fi.infer_severity("zero-day exploit released"), "critical")
        self.assertEqual(fi.infer_severity("actively exploited in the wild"), "critical")

    def test_high(self):
        self.assertEqual(fi.infer_severity("privilege escalation in kernel"), "high")
        self.assertEqual(fi.infer_severity("data breach at major corp"), "high")

    def test_medium(self):
        self.assertEqual(fi.infer_severity("xss vulnerability in plugin"), "medium")

    def test_low(self):
        self.assertEqual(fi.infer_severity("informational guide released"), "low")

    def test_default(self):
        self.assertEqual(fi.infer_severity("something random here"), "medium")

    # ── Regression: whole-token matching ────────────────────────────────────
    # "rce" is a substring of source / force / resource / Salesforce, and the
    # original `kw in text` form made all of them `critical`. Measured against
    # a real run: 16 of 51 critical items were false for exactly this reason,
    # and ALERT_SEVERITIES defaults to `critical`, so they were paged out.
    def test_rce_does_not_match_inside_other_words(self):
        for text in ("Salesforce data exposure",
                     "a resource leak causes a crash",
                     "this enforcement action was taken",
                     "brute force login attempts observed"):
            self.assertNotEqual(fi.infer_severity(text), "critical",
                                f"false critical on: {text!r}")

    def test_rce_still_matches_as_a_word(self):
        self.assertEqual(fi.infer_severity("Critical RCE in Apache Struts"), "critical")
        self.assertEqual(fi.infer_severity("unauthenticated rce, patch now"), "critical")

    def test_apt_does_not_match_adapter(self):
        self.assertNotEqual(fi.infer_severity("network adapter driver update"), "high")


class TestCategoryInference(unittest.TestCase):
    def test_cve_category(self):
        self.assertEqual(fi.infer_category("CVE-2024-1234 in Apache"), "cve")
        self.assertEqual(fi.infer_category("new vulnerability in nginx"), "cve")

    def test_incident_category(self):
        self.assertEqual(fi.infer_category("data breach at company"), "incident")

    def test_advisory_category(self):
        self.assertEqual(fi.infer_category("cisa advisory released"), "advisory")

    def test_news_default(self):
        self.assertEqual(fi.infer_category("something else entirely"), "news")


class TestIocExtraction(unittest.TestCase):
    """IOCs are only extracted from sources that actually publish indicators."""

    def test_ioc_feed_yields_indicators(self):
        result = fi.extract_iocs("malicious IP 203.0.113.45 seen", source="URLhaus")
        self.assertIn("203.0.113.45", result.get("ipv4", []))

    def test_hashes_from_ioc_feed(self):
        result = fi.extract_iocs("hash: d41d8cd98f00b204e9800998ecf8427e", source="ThreatFox")
        self.assertIn("d41d8cd98f00b204e9800998ecf8427e", result.get("md5", []))

    def test_private_ips_filtered(self):
        result = fi.extract_iocs("internal host 192.168.1.1 and 10.0.0.5", source="URLhaus")
        self.assertEqual(result.get("ipv4", []), [])

    # ── Regression: the STIX bundle used to publish these ───────────────────
    def test_news_prose_yields_no_network_indicators(self):
        text = "Contact steve.traylen@cern.ch about the redhat.com advisory at isc.sans.edu"
        result = fi.extract_iocs(text, source="Fedora")
        self.assertNotIn("domain", result)
        self.assertNotIn("email", result,
                         "maintainer emails must never be exported as indicators")

    def test_infrastructure_domains_rejected(self):
        result = fi.extract_iocs("see github.com and gmail.com", source="URLhaus")
        self.assertEqual(result.get("domain", []), [])

    def test_code_identifiers_rejected(self):
        result = fi.extract_iocs("in handlers.ts we call req.query and ops.dispatch",
                                 source="URLhaus")
        self.assertEqual(result.get("domain", []), [])

    def test_own_url_host_excluded(self):
        result = fi.extract_iocs("read more at https://malbearlabs.com/post",
                                 source="AlienVault OTX",
                                 own_url="https://malbearlabs.com/post")
        self.assertEqual(result.get("domain", []), [])

    def test_defanged_text_is_treated_as_indicators(self):
        result = fi.extract_iocs("C2 at evil-domain[.]tld and hxxp://bad[.]example",
                                 source="The Hacker News")
        self.assertIn("evil-domain.tld", result.get("domain", []))

    def test_cve_extracted_from_any_source(self):
        result = fi.extract_iocs("affects CVE-2024-3094", source="Krebs on Security")
        self.assertIn("CVE-2024-3094", result.get("cve", []))

    def test_empty(self):
        self.assertEqual(fi.extract_iocs(""), {})


class TestPriorityScoring(unittest.TestCase):
    def test_urgent_kev(self):
        result = fi.compute_priority({"cvss_score": 5.0, "epss_score": 0.1, "cisa_kev": True})
        self.assertGreaterEqual(result["score"], 90)
        self.assertEqual(result["label"], "urgent")

    def test_none_on_no_signal(self):
        self.assertIsNone(fi.compute_priority({"title": "just news"}))

    def test_rationale_includes_kev(self):
        result = fi.compute_priority({"cisa_kev": True})
        self.assertIn("CISA KEV", result["rationale"])
        self.assertEqual(result["score"], 90.0)

    def test_score_is_bounded(self):
        result = fi.compute_priority({"cvss_score": 10.0, "epss_score": 1.0, "cisa_kev": True,
                                      "has_poc": True, "ssvc_exploitation": "active",
                                      "ssvc_automatable": "yes",
                                      "ssvc_technical_impact": "total"})
        self.assertLessEqual(result["score"], 100.0)

    def test_ssvc_active_escalates(self):
        base = fi.compute_priority({"cvss_score": 6.0})
        ssvc = fi.compute_priority({"cvss_score": 6.0, "ssvc_exploitation": "active"})
        self.assertGreater(ssvc["score"], base["score"])
        self.assertEqual(ssvc["label"], "urgent")

    def test_every_scored_item_gets_an_action(self):
        for label in ("urgent", "elevated", "moderate", "low"):
            self.assertIn(label, fi._ACTION_BY_LABEL)
        result = fi.compute_priority({"cvss_score": 9.8, "cisa_kev": True})
        self.assertEqual(result["action"], "Patch now")

    def test_config_weights_are_honoured(self):
        """The old utils.compute_priority hardcoded 40/40/20, silently ignoring
        the documented PRIORITY_* environment overrides."""
        result = fi.compute_priority({"cvss_score": 10.0})
        self.assertAlmostEqual(result["score"], fi.CONFIG.priority_cvss_weight, places=1)


class TestTtpMapping(unittest.TestCase):
    def test_real_technique_matches(self):
        self.assertIn("T1190", [t["id"] for t in map_ttps("Critical RCE in Apache Struts")])

    def test_substring_false_positives_gone(self):
        for text in ("Salesforce data exposure",
                     "a resource leak causes a crash",
                     "authentication failure logged"):
            self.assertEqual(map_ttps(text), [], f"false TTP on: {text!r}")

    def test_capped(self):
        self.assertLessEqual(len(map_ttps("phishing ransomware powershell wmi " * 30)), 10)


class TestDeduplication(unittest.TestCase):
    def test_identical_urls_collapse(self):
        items = [{"title": "A", "url": "https://x.test/a", "source": "S1"},
                 {"title": "B", "url": "https://x.test/a/", "source": "S2"}]
        self.assertEqual(len(fi.deduplicate(items)), 1)

    def test_tracking_params_ignored(self):
        items = [{"title": "A", "url": "https://x.test/a", "source": "S1"},
                 {"title": "B", "url": "https://x.test/a?utm_source=rss", "source": "S2"}]
        self.assertEqual(len(fi.deduplicate(items)), 1)

    def test_distinct_stories_survive(self):
        items = [{"title": "Fortinet RCE patched", "url": "https://x.test/1", "source": "S"},
                 {"title": "Cisco DoS disclosed", "url": "https://x.test/2", "source": "S"}]
        self.assertEqual(len(fi.deduplicate(items)), 2)

    def test_source_authority_ranking(self):
        self.assertGreater(fi._source_rank("NVD"), fi._source_rank("Reddit/netsec"))


class TestCleanHtml(unittest.TestCase):
    def test_strips_tags(self):
        self.assertEqual(fi.clean_html("<p>hello <b>world</b></p>"), "hello world")

    def test_preserves_prose_with_angle_brackets(self):
        """`<[^>]+>` used to delete everything from a bare '<' to the next '>',
        silently truncating code snippets in advisory text."""
        out = fi.clean_html("Crash when if (a < b) and x > y")
        self.assertIn("a < b", out)
        self.assertIn("x > y", out)


class TestSourceHealth(unittest.TestCase):
    def test_fresh_items_have_low_median_age(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        self.assertLess(fi._median_age_days([{"published": now}] * 3), 1)

    def test_undated_items_return_none(self):
        self.assertIsNone(fi._median_age_days([{"title": "x"}]))

    def test_stale_feed_detected(self):
        """Regression: Threatpost returned 10 items every hour and reported
        'ok' while serving its 2022 archive."""
        old = [{"published": "2022-08-31T00:00:00+00:00"}] * 5
        self.assertGreater(fi._median_age_days(old), fi.CONFIG.source_stale_days)


if __name__ == "__main__":
    unittest.main()

"""Integration smoke tests for the CyberWatch pipeline.

Two layers:
  1. Offline schema validation of the committed data/intel.json — always runs.
  2. Live source checks (HTTP reachability of critical feeds/APIs) — only when
     RUN_LIVE_TESTS=1, so unit CI stays fast and deterministic.

Run:  python -m unittest tests/test_integration.py -v
Live: RUN_LIVE_TESTS=1 python -m unittest tests/test_integration.py -v
"""

import json
import os
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
INTEL_PATH = PROJECT_ROOT / "data" / "intel.json"

RUN_LIVE = os.environ.get("RUN_LIVE_TESTS") == "1"

REQUIRED_ITEM_FIELDS = {"title", "source", "category", "severity", "published"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CATEGORIES = {"cve", "news", "advisory", "incident"}


class TestIntelJsonSchema(unittest.TestCase):
    """Validate the shape of the committed intel.json output."""

    @classmethod
    def setUpClass(cls):
        if not INTEL_PATH.exists():
            raise unittest.SkipTest("data/intel.json not present")
        with open(INTEL_PATH, encoding="utf-8") as f:
            cls.data = json.load(f)

    def test_top_level_keys(self):
        for key in ("last_updated", "items"):
            self.assertIn(key, self.data)

    def test_items_nonempty(self):
        self.assertGreater(len(self.data["items"]), 0, "intel.json has no items")

    def test_item_required_fields(self):
        for item in self.data["items"]:
            missing = REQUIRED_ITEM_FIELDS - item.keys()
            self.assertFalse(missing, f"item missing {missing}: {item.get('title', '?')[:60]}")

    def test_item_severity_values(self):
        for item in self.data["items"]:
            self.assertIn((item.get("severity") or "").lower(), VALID_SEVERITIES,
                          f"bad severity on: {item.get('title', '?')[:60]}")

    def test_item_category_values(self):
        for item in self.data["items"]:
            self.assertIn(item.get("category"), VALID_CATEGORIES,
                          f"bad category on: {item.get('title', '?')[:60]}")

    def test_cve_id_format(self):
        import re
        pat = re.compile(r"^CVE-\d{4}-\d{4,7}$")
        for item in self.data["items"]:
            cve = item.get("cve_id")
            if cve:
                self.assertRegex(cve, pat, f"malformed cve_id: {cve}")

    def test_urls_are_absolute(self):
        for item in self.data["items"]:
            url = item.get("url")
            if url:
                self.assertTrue(url.startswith("http"),
                                f"non-absolute url: {url[:80]}")

    def test_no_fedora_build_name_urls(self):
        """Regression: Fedora URLs must use the FEDORA-XXXX-XXXX alias, not
        space-separated build names (which 404)."""
        for item in self.data["items"]:
            if item.get("source") == "Fedora" and item.get("url"):
                self.assertNotIn(" ", item["url"], f"Fedora URL has spaces: {item['url'][:100]}")
                self.assertNotIn("%20", item["url"], f"Fedora URL has %20: {item['url'][:100]}")

    def test_source_health_present(self):
        health = self.data.get("source_health", {})
        self.assertTrue(health, "source_health missing from output")
        for name, h in health.items():
            self.assertIn("status", h, f"health entry for {name} missing status")
            self.assertIn(h["status"], {"ok", "stale", "empty", "error"},
                          f"unknown health status for {name}: {h['status']}")

    def test_no_stale_source_reports_ok(self):
        """Regression: a feed serving a 4-year-old archive used to report green
        because health only counted items and never checked freshness."""
        for name, h in self.data.get("source_health", {}).items():
            age = h.get("median_age_days")
            if h["status"] == "ok" and age is not None:
                self.assertLessEqual(age, 400, f"{name} reports ok with median age {age}d")

    def test_graph_templates_shipped_once(self):
        """Attack-flow graphs are referenced by template id, not duplicated onto
        every item (that was 60 KB of byte-identical payload)."""
        self.assertIn("graph_templates", self.data)
        inline = sum(1 for i in self.data["items"] if i.get("workflow_graph"))
        ai_enriched = self.data.get("ai_enriched_count", 0)
        self.assertLessEqual(inline, max(ai_enriched, 5),
                             "workflow_graph should only be inline for AI-enriched items")

    def test_no_redundant_rule_summaries(self):
        """Rule-based items must not carry an ai_summary that merely repeats
        `description` — 246 of 248 used to, wasting 58 KB per payload."""
        redundant = 0
        for item in self.data["items"]:
            if item.get("ai_provider") != "rule":
                continue
            summary = (item.get("ai_summary") or "").split(" [IOCs:")[0]
            desc = item.get("description") or ""
            if summary and desc.startswith(summary[:60]):
                redundant += 1
        self.assertEqual(redundant, 0, f"{redundant} rule items duplicate their description")

    def test_iocs_only_from_indicator_feeds(self):
        """Regression: the STIX bundle published gmail.com, redhat.com and two
        maintainers' work email addresses as malicious-activity indicators."""
        ioc_sources = {"URLhaus", "ThreatFox", "Feodo Tracker", "Spamhaus",
                       "MalwareBazaar", "AbuseIPDB", "PhishTank", "AlienVault OTX"}
        network_types = {"domain", "email", "ipv4", "url", "cidr"}
        for item in self.data["items"]:
            if item.get("source") in ioc_sources:
                continue
            leaked = network_types & set((item.get("iocs") or {}).keys())
            self.assertFalse(
                leaked,
                f"{item.get('source')} leaked {leaked} from prose: "
                f"{item.get('title', '?')[:60]}")

    def test_no_personal_emails_in_exports(self):
        export = PROJECT_ROOT / "data" / "exports" / "iocs.csv"
        if not export.exists():
            self.skipTest("no exports generated yet")
            return
        text = export.read_text(encoding="utf-8", errors="replace")
        for needle in ("@redhat.com", "@cern.ch", "@gmail.com", "@fedoraproject.org"):
            self.assertNotIn(needle, text, f"PII leaked into iocs.csv: {needle}")

    def test_scored_items_have_an_action(self):
        for item in self.data["items"]:
            if item.get("priority_score") is not None:
                self.assertTrue(item.get("action"),
                                f"scored item without action: {item.get('title', '?')[:60]}")

    def test_ssvc_values_are_valid(self):
        valid_exploitation = {"none", "poc", "active"}
        for item in self.data["items"]:
            val = item.get("ssvc_exploitation")
            if val:
                self.assertIn(val, valid_exploitation, f"bad SSVC exploitation: {val}")

    def test_priority_scores_in_range(self):
        for item in self.data["items"]:
            score = item.get("priority_score")
            if score is not None:
                self.assertGreaterEqual(score, 0)
                self.assertLessEqual(score, 100)


@unittest.skipUnless(RUN_LIVE, "set RUN_LIVE_TESTS=1 for live source checks")
class TestLiveSources(unittest.TestCase):
    """Reachability checks against the external APIs the pipeline depends on.

    These catch 'the URL changed again' breakage before data goes stale.
    """

    TIMEOUT = 15

    def _get(self, url, **kw):
        import requests
        return requests.get(url, timeout=self.TIMEOUT,
                            headers={"User-Agent": "CyberWatch-CI/1.0 (+github actions health check)"}, **kw)

    def test_epss_api(self):
        r = self._get("https://api.first.org/data/v1/epss?cve=CVE-2021-44228")
        self.assertEqual(r.status_code, 200)
        self.assertIn("data", r.json())

    def test_cisa_kev_catalog(self):
        r = self._get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        self.assertEqual(r.status_code, 200)
        self.assertIn("vulnerabilities", r.json())

    def test_nvd_api(self):
        r = self._get("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1")
        self.assertEqual(r.status_code, 200)

    def test_fedora_bodhi(self):
        r = self._get("https://bodhi.fedoraproject.org/updates/?limit=1&status=stable&type=security")
        self.assertEqual(r.status_code, 200)
        # Anubis PoW returns HTML — ensure we still get JSON.
        self.assertIn("updates", r.json())

    def test_fedora_fallback_rss(self):
        r = self._get("https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/feed/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("<rss", r.text[:200])

    def test_gentoo_glsa_rss(self):
        r = self._get("https://security.gentoo.org/glsa/feed.rss")
        self.assertEqual(r.status_code, 200)

    def test_msrc_rss(self):
        r = self._get("https://api.msrc.microsoft.com/update-guide/rss")
        self.assertEqual(r.status_code, 200)

    def test_urlhaus(self):
        r = self._get("https://urlhaus.abuse.ch/downloads/csv_recent/")
        self.assertEqual(r.status_code, 200)

    def test_cisa_advisories_feed(self):
        """The ICS-only feed returned zero items for months; this is the
        combined advisories feed that replaced it."""
        r = self._get("https://www.cisa.gov/cybersecurity-advisories/all.xml")
        self.assertEqual(r.status_code, 200)
        self.assertIn("<rss", r.text[:400] + r.text[:400].lower())

    def test_vulnrichment_raw(self):
        """CISA Vulnrichment SSVC records — free, no key."""
        r = self._get("https://raw.githubusercontent.com/cisagov/vulnrichment/"
                      "develop/2024/3xxx/CVE-2024-3094.json")
        self.assertIn(r.status_code, (200, 404))

    def test_epss_bulk_csv(self):
        """The full daily corpus, which replaced the per-run API cache that
        silently returned scores for the wrong CVE set."""
        r = self._get("https://epss.empiricalsecurity.com/epss_scores-current.csv.gz")
        self.assertEqual(r.status_code, 200)

    @unittest.skipUnless(os.environ.get("VULNCHECK_API_KEY"), "VULNCHECK_API_KEY not set")
    def test_vulncheck_kev(self):
        import requests
        r = requests.get("https://api.vulncheck.com/v3/index/vulncheck-kev",
                         headers={"Authorization": f"Bearer {os.environ['VULNCHECK_API_KEY']}"},
                         params={"limit": 1}, timeout=self.TIMEOUT)
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()

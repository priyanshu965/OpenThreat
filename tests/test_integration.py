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


if __name__ == "__main__":
    unittest.main()

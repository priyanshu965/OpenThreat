"""
OPENTHREAT — tests/test_catalogs.py
==================================
The KEV, lifecycle and CVE tables, and the lifecycle fetcher behind them.

The failure mode worth pinning is a board that is confidently wrong rather
than obviously broken. endoflife.date puts three different kinds of value in
one field — an ISO date, `true` meaning "already ended", and `false` meaning
"not announced" — and reports long-term support separately from `eol`. Read
naively, that produces a page stating that Debian 12 is out of support while
it still has two years of security updates.
"""

import sys
import unittest
from datetime import date
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

import lifecycle  # noqa: E402

TODAY = date(2026, 8, 28)


class TestCycleState(unittest.TestCase):

    def state(self, **cycle):
        return lifecycle._cycle_state(cycle, TODAY)[0]

    def test_past_eol_is_eol(self):
        self.assertEqual(self.state(eol="2025-04-02", support="2022-10-01"), "eol")

    def test_eol_true_is_eol_even_without_a_date(self):
        """`true` means it has already ended and no date was recorded. Dropping
        it because it will not parse as a date marks dead releases supported."""
        self.assertEqual(self.state(eol=True), "eol")

    def test_extended_support_is_not_eol(self):
        """Debian 12: eol 2026-07-11, extendedSupport 2028-06-30. Reporting it
        as out of support would be a firm, wrong answer about one of the most
        widely deployed server distributions there is."""
        self.assertEqual(
            self.state(eol="2026-07-11", extendedSupport="2028-06-30"), "extended")

    def test_expired_extended_support_is_eol(self):
        self.assertEqual(
            self.state(eol="2024-01-01", extendedSupport="2025-01-01"), "eol")

    def test_past_support_before_eol_is_security_only(self):
        self.assertEqual(self.state(eol="2029-04-25", support="2026-06-01"),
                         "security-only")

    def test_future_dates_are_supported(self):
        self.assertEqual(self.state(eol="2031-04-01", support="2028-10-01"),
                         "supported")

    def test_not_announced_is_supported_not_eol(self):
        """`eol: false` means no end date has been ANNOUNCED. Treating a
        boolean as an unparseable date and falling through to `eol` would
        condemn every actively maintained product on the board."""
        self.assertEqual(self.state(eol=False, support=True), "supported")

    def test_no_information_is_unknown(self):
        self.assertEqual(self.state(cycle="1.0"), "unknown")

    def test_days_are_signed_the_way_the_label_reads(self):
        _, _, past = lifecycle._cycle_state({"eol": "2025-04-02"}, TODAY)
        _, _, future = lifecycle._cycle_state({"eol": "2031-04-01"}, TODAY)
        self.assertGreater(past, 0)      # days SINCE
        self.assertGreater(future, 0)    # days UNTIL


class TestParseDate(unittest.TestCase):

    def test_booleans_are_not_dates(self):
        self.assertIsNone(lifecycle._parse_date(True))
        self.assertIsNone(lifecycle._parse_date(False))
        self.assertIsNone(lifecycle._parse_date(None))

    def test_iso_dates_parse(self):
        self.assertEqual(lifecycle._parse_date("2026-08-28"), TODAY)

    def test_garbage_does_not_raise(self):
        self.assertIsNone(lifecycle._parse_date("soon"))


class TestProductList(unittest.TestCase):

    def test_no_known_dead_slugs(self):
        """java, openssh, sonicos and exchange all 404 on endoflife.date. A
        dead slug costs a silent gap in the board, one log line deep."""
        for dead in ("java", "openssh", "sonicos", "exchange"):
            self.assertNotIn(dead, lifecycle._PRODUCTS)

    def test_products_are_unique(self):
        self.assertEqual(len(lifecycle._PRODUCTS), len(set(lifecycle._PRODUCTS)))

    def test_repos_are_owner_slash_name(self):
        for repo in lifecycle._REPOS:
            self.assertEqual(repo.count("/"), 1, repo)


class TestKevRecordShape(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = (PROJECT_ROOT / "scripts" / "kev_catalog.py").read_text(encoding="utf-8")

    def test_the_table_fields_are_captured(self):
        for field in ("vulnerabilityName", "shortDescription", "requiredAction"):
            self.assertIn(field, self.src)

    def test_cache_filename_was_versioned_with_the_shape_change(self):
        """A warm cache written before these fields existed is not detectably
        different from a complete one — the table would render blank names for
        a full TTL and look broken with nothing reporting an error. Same
        reasoning as the legacy-shape guard already in that module."""
        self.assertIn('_CACHE = "cisa_kev_v2.json"', self.src)


class TestCatalogViewsAreWired(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
        cls.js = (PROJECT_ROOT / "js" / "catalogs.js").read_text(encoding="utf-8")

    def test_all_three_views_are_fully_registered(self):
        views = self.app.split("const VIEWS = [", 1)[1].split("];", 1)[0]
        nodes = self.app.split("const VIEW_NODES = [", 1)[1].split("];", 1)[0]
        for view in ("kev", "lifecycle", "cve"):
            self.assertIn(f"'{view}'", views)
            self.assertIn(f"'{view}-view'", nodes)
            self.assertIn(f"case '{view}':", self.app)
            self.assertIn(f'id="{view}-view"', self.html)

    def test_endpoints_are_declared_on_both_sides(self):
        exports = (PROJECT_ROOT / "scripts" / "exports.py").read_text(encoding="utf-8")
        for endpoint in ("kev.json", "lifecycle.json"):
            self.assertIn(endpoint, self.app, f"app.js never fetches {endpoint}")
            self.assertIn(endpoint, exports, f"exports.py never writes {endpoint}")

    def test_pipeline_publishes_them(self):
        src = (PROJECT_ROOT / "scripts" / "fetch_intel.py").read_text(encoding="utf-8")
        for key in ("lifecycle", "kev_table"):
            self.assertIn(f'"{key}":', src, f"{key} never reaches `output`")

    def test_they_are_kept_out_of_the_feed_payload(self):
        """1,685 KEV records in intel.json would be downloaded by every visitor
        reading a list of headlines, and archived 90 times over."""
        src = (PROJECT_ROOT / "scripts" / "fetch_intel.py").read_text(encoding="utf-8")
        block = src.split("_RESEARCH_KEYS = (", 1)[1].split(")", 1)[0]
        self.assertIn("lifecycle", block)
        self.assertIn("kev_table", block)

    def test_catalogs_loads_after_tools(self):
        """catalogs.js closes over toolVerdict() from tools.js; these are
        classic scripts sharing one scope, so order is load-bearing."""
        self.assertGreater(self.html.find("js/catalogs.js"),
                           self.html.find("js/tools.js"))

    def test_no_html_sink(self):
        self.assertNotRegex(self.js, r"\.(innerHTML|outerHTML)\s*=")
        self.assertNotIn("insertAdjacentHTML", self.js)

    def test_cve_browser_reuses_the_loaded_corpus(self):
        """A second download of records already in memory would be a second
        source of truth for the same data."""
        body = self.js.split("function showCveView", 1)[1]
        self.assertIn("store.items", body)
        self.assertNotIn("fetch(", body)

    def test_federal_due_dates_are_labelled_as_federal(self):
        """BOD 22-01 binds US federal civilian agencies. Presenting their
        deadline as the reader's is borrowed urgency."""
        self.assertIn("BOD 22-01", self.js)
        self.assertIn("federal", self.js.lower())


if __name__ == "__main__":
    unittest.main()

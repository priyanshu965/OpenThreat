"""Unit tests for darkweb.py. Offline: the parsers are fed synthetic records."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import darkweb as dw                                   # noqa: E402


class TestTimestampParsing(unittest.TestCase):
    def test_ransomlook_format(self):
        self.assertEqual(dw._iso("2026-08-25 08:26:26.109019"),
                         "2026-08-25T08:26:26+00:00")

    def test_iso_input(self):
        self.assertEqual(dw._iso("2026-08-25T08:26:26"),
                         "2026-08-25T08:26:26+00:00")

    def test_junk_returns_empty(self):
        for bad in ("", None, "not a date", "2026"):
            self.assertEqual(dw._iso(bad), "")


class TestSummaryShape(unittest.TestCase):
    """build_darkweb_summary aggregates; it must not dump victim names."""

    def setUp(self):
        self.posts = [
            {"post_title": "Acme Corp", "group_name": "qilin",
             "discovered": "2026-08-25 08:00:00.0"},
            {"post_title": "Beta Ltd", "group_name": "qilin",
             "discovered": "2026-08-24 08:00:00.0"},
            {"post_title": "Gamma SA", "group_name": "beast",
             "discovered": "2026-08-23 08:00:00.0"},
        ]
        self.groups = ["qilin", "beast", "play"]
        self._orig = dw._fetch_json
        dw._fetch_json = lambda name, url: (
            self.posts if "recent" in name else self.groups)

    def tearDown(self):
        dw._fetch_json = self._orig

    def test_counts(self):
        s = dw.build_darkweb_summary()
        self.assertEqual(s["recent_posts"], 3)
        self.assertEqual(s["distinct_groups_active"], 2)
        self.assertEqual(s["tracked_leak_sites"], 3)

    def test_most_active_ranked(self):
        s = dw.build_darkweb_summary()
        self.assertEqual(s["most_active"][0], {"group": "qilin", "posts": 2})

    def test_date_window(self):
        s = dw.build_darkweb_summary()
        self.assertEqual(s["newest_post"], "2026-08-25")
        self.assertEqual(s["oldest_in_window"], "2026-08-23")

    def test_no_victim_names_in_summary(self):
        """The rollup is counts. Victim names belong on the item, not here."""
        import json
        blob = json.dumps(dw.build_darkweb_summary())
        for victim in ("Acme Corp", "Beta Ltd", "Gamma SA"):
            self.assertNotIn(victim, blob)

    def test_collection_note_is_honest(self):
        """It must say we consume a mirror rather than crawl Tor, and that a
        listing is a claim."""
        note = dw.build_darkweb_summary()["collection_note"].lower()
        self.assertIn("not crawl tor", note.replace("does not crawl tor", "not crawl tor"))
        self.assertIn("claim", note)


class TestPostsToItems(unittest.TestCase):
    def setUp(self):
        self._orig = dw._fetch_json
        dw._fetch_json = lambda name, url: [
            {"post_title": "Acme Corp", "group_name": "qilin",
             "discovered": "2026-08-25 08:00:00.0",
             "description": "Acme makes widgets.", "link": "/card/acme"},
            {"post_title": "", "group_name": "beast",
             "discovered": "2026-08-25 07:00:00.0"},   # no victim -> skipped
        ]

    def tearDown(self):
        dw._fetch_json = self._orig

    def test_items_built_and_blank_skipped(self):
        items = dw.fetch_leak_site_posts()
        self.assertEqual(len(items), 1)
        it = items[0]
        self.assertIn("qilin", it["title"])
        self.assertIn("Acme Corp", it["title"])
        self.assertEqual(it["source"], "RansomLook")
        self.assertEqual(it["category"], "incident")

    def test_marked_adversary_authored(self):
        """Leak-site posts are written BY the adversary, so they are claims."""
        it = dw.fetch_leak_site_posts()[0]
        self.assertEqual(it["provenance_hint"], "adversary-authored")
        self.assertIn("claim", it["description"].lower())

    def test_actor_hint_carries_the_group(self):
        self.assertEqual(dw.fetch_leak_site_posts()[0]["threat_actors_hint"], ["qilin"])

    def test_relative_link_is_absolutised(self):
        self.assertTrue(dw.fetch_leak_site_posts()[0]["url"].startswith("https://"))


if __name__ == "__main__":
    unittest.main()


class TestProvenanceIntegration(unittest.TestCase):
    """Leak-site posts must land as adversary-authored, not automated-feed.

    Regression: the provenance layer consulted only the source registry, so an
    unregistered source fell through to the default and the fetcher's explicit
    hint was discarded — which lost exactly the distinction that matters most
    about a leak-site post.
    """

    def setUp(self):
        import provenance
        self.p = provenance

    def test_hint_is_honoured(self):
        item = {"source": "Nowhere", "provenance_hint": self.p.ADVERSARY}
        self.assertEqual(self.p.classify_provenance(item), self.p.ADVERSARY)

    def test_registry_used_when_no_hint(self):
        self.assertEqual(
            self.p.classify_provenance({"source": "RansomLook"}), self.p.ADVERSARY)

    def test_bogus_hint_is_ignored(self):
        """A fetcher must not be able to invent a provenance class."""
        item = {"source": "RansomLook", "provenance_hint": "totally-legit"}
        self.assertEqual(self.p.classify_provenance(item), self.p.ADVERSARY)

    def test_leak_post_end_to_end(self):
        orig = dw._fetch_json
        dw._fetch_json = lambda name, url: [
            {"post_title": "Acme", "group_name": "qilin",
             "discovered": "2026-08-25 08:00:00.0"}]
        try:
            items = dw.fetch_leak_site_posts()
            self.p.annotate_provenance(items)
            self.assertEqual(items[0]["provenance"], self.p.ADVERSARY)
            self.assertTrue(items[0]["human_authored"])
        finally:
            dw._fetch_json = orig


class TestExposureIndex(unittest.TestCase):
    """The CASM-style searchable index and the standing watch."""

    def setUp(self):
        self._orig = dw._fetch_json

        def fake(name, url):
            if "victims_" in name:
                return [
                    {"victim": "Acme Manufacturing Ltd", "group": "qilin",
                     "attackdate": "2026-08-20", "country": "US", "activity": "Manufacturing"},
                    {"victim": "Contoso Health", "group": "beast",
                     "attackdate": "2026-08-19", "country": "GB", "activity": "Healthcare"},
                ]
            if "posts" in name:
                return {"posts": [
                    {"post_title": "Acme Manufacturing Ltd", "group_name": "qilin",
                     "discovered": "2026-08-20 10:00:00.0"},          # dupe
                    {"post_title": "Northwind Traders", "group_name": "play",
                     "discovered": "2026-08-18 10:00:00.0"},
                ]}
            return None

        dw._fetch_json = fake

    def tearDown(self):
        dw._fetch_json = self._orig

    def test_index_merges_and_dedupes(self):
        idx = dw.build_darkweb_index()
        names = sorted(r["v"] for r in idx["victims"])
        self.assertEqual(names, ["Acme Manufacturing Ltd", "Contoso Health",
                                 "Northwind Traders"])
        self.assertEqual(idx["count"], 3)

    def test_index_is_newest_first(self):
        idx = dw.build_darkweb_index()
        dates = [r["d"] for r in idx["victims"]]
        self.assertEqual(dates, sorted(dates, reverse=True))

    def test_internal_src_field_not_published(self):
        for row in dw.build_darkweb_index()["victims"]:
            self.assertNotIn("src", row)

    def test_coverage_declares_the_gaps(self):
        """A search tool that implies total coverage gives false assurance."""
        cov = dw.build_darkweb_index()["coverage"]
        blob = " ".join(cov["does_not_cover"]).lower()
        for gap in ("forum", "credential", "paste"):
            self.assertIn(gap, blob)
        self.assertIn("not evidence of safety", cov["caveat"].lower())

    def test_search_is_case_and_punctuation_insensitive(self):
        idx = dw.build_darkweb_index()
        for q in ("acme", "ACME", "Acme  Manufacturing", "acme-manufacturing"):
            self.assertTrue(dw.search_index(idx, q), q)

    def test_search_miss_returns_empty(self):
        self.assertEqual(dw.search_index(dw.build_darkweb_index(), "notpresentxyz"), [])

    def test_search_blank_term_returns_empty(self):
        idx = dw.build_darkweb_index()
        for q in ("", "   ", None):
            self.assertEqual(dw.search_index(idx, q), [])

    def test_search_respects_limit(self):
        idx = dw.build_darkweb_index()
        self.assertEqual(len(dw.search_index(idx, "a", limit=1)), 1)

    def test_watchlist_reports_hits(self):
        from config import CONFIG
        old = CONFIG.darkweb_watch
        try:
            CONFIG.darkweb_watch = "Acme, NotPresentCo"
            hits = dw.check_watchlist(dw.build_darkweb_index())
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["term"], "Acme")
            self.assertEqual(hits[0]["count"], 1)
        finally:
            CONFIG.darkweb_watch = old

    def test_watchlist_empty_when_unconfigured(self):
        from config import CONFIG
        old = CONFIG.darkweb_watch
        try:
            CONFIG.darkweb_watch = ""
            self.assertEqual(dw.check_watchlist(dw.build_darkweb_index()), [])
        finally:
            CONFIG.darkweb_watch = old

    def test_index_cap_keeps_newest(self):
        from config import CONFIG
        old = CONFIG.darkweb_index_max
        try:
            CONFIG.darkweb_index_max = 2
            idx = dw.build_darkweb_index()
            self.assertEqual(idx["count"], 2)
            self.assertTrue(idx["capped"])
            self.assertEqual(idx["total_available"], 3)
            self.assertEqual(idx["victims"][0]["d"], "2026-08-20")   # newest kept
        finally:
            CONFIG.darkweb_index_max = old

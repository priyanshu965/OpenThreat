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

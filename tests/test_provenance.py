"""Unit tests for provenance.py — the OSINT provenance layer (phase 6)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import provenance as p                                 # noqa: E402


class TestClassification(unittest.TestCase):
    def test_leak_site_is_adversary_authored(self):
        """The whole point of the layer: a ransomware crew's own leak-site post
        is the attacker speaking, not reporting about the attacker."""
        self.assertEqual(
            p.classify_provenance({"source": "Ransomware.live"}), p.ADVERSARY)

    def test_vendor_research(self):
        for src in ("Unit 42", "Cisco Talos", "Securelist", "Check Point Research"):
            self.assertEqual(p.classify_provenance({"source": src}),
                             p.VENDOR_RESEARCH, src)

    def test_journalism(self):
        for src in ("The Hacker News", "Bleeping Computer", "Dark Reading"):
            self.assertEqual(p.classify_provenance({"source": src}),
                             p.JOURNALISM, src)

    def test_government(self):
        self.assertEqual(p.classify_provenance({"source": "CISA"}), p.GOVERNMENT)
        self.assertEqual(p.classify_provenance({"source": "NVD"}), p.GOVERNMENT)

    def test_independent(self):
        self.assertEqual(p.classify_provenance({"source": "Krebs on Security"}),
                         p.INDEPENDENT)

    def test_automated_feed(self):
        for src in ("URLhaus", "ThreatFox", "SSL Blacklist", "Spamhaus"):
            self.assertEqual(p.classify_provenance({"source": src}),
                             p.AUTOMATED, src)

    def test_unknown_source_defaults_to_automated(self):
        """The cautious default: claim the least about an unmapped source."""
        self.assertEqual(p.classify_provenance({"source": "Something New"}),
                         p.AUTOMATED)


class TestHumanAuthored(unittest.TestCase):
    def test_automated_is_not_human_authored(self):
        self.assertNotIn(p.AUTOMATED, p.HUMAN_AUTHORED)

    def test_adversary_counts_as_human_authored(self):
        """A person wrote the leak-site post, even though that person is the
        attacker. That is precisely what makes it worth separating."""
        self.assertIn(p.ADVERSARY, p.HUMAN_AUTHORED)

    def test_research_and_journalism_are_human(self):
        for cls in (p.VENDOR_RESEARCH, p.JOURNALISM, p.GOVERNMENT, p.INDEPENDENT):
            self.assertIn(cls, p.HUMAN_AUTHORED)


class TestAnnotate(unittest.TestCase):
    def test_tags_in_place_and_counts(self):
        items = [
            {"source": "Unit 42"},
            {"source": "Ransomware.live"},
            {"source": "URLhaus"},
        ]
        counts = p.annotate_provenance(items)
        self.assertEqual(items[0]["provenance"], p.VENDOR_RESEARCH)
        self.assertTrue(items[0]["human_authored"])
        self.assertEqual(items[1]["provenance"], p.ADVERSARY)
        self.assertTrue(items[1]["human_authored"])
        self.assertEqual(items[2]["provenance"], p.AUTOMATED)
        self.assertFalse(items[2]["human_authored"])
        self.assertEqual(counts[p.VENDOR_RESEARCH], 1)

    def test_every_item_gets_a_provenance(self):
        items = [{"source": "Whatever"} for _ in range(5)]
        p.annotate_provenance(items)
        for i in items:
            self.assertIn("provenance", i)
            self.assertIn("human_authored", i)


class TestMetadata(unittest.TestCase):
    def test_every_class_has_a_label_and_note(self):
        for cls in p.PROVENANCE_ORDER:
            self.assertIn(cls, p.PROVENANCE_LABELS, cls)
            self.assertIn(cls, p.PROVENANCE_NOTES, cls)

    def test_order_covers_all_classes(self):
        self.assertEqual(set(p.PROVENANCE_ORDER), set(p.PROVENANCE_LABELS))

    def test_adversary_is_listed_first(self):
        """It is the rarest and most distinctive stream, so it leads."""
        self.assertEqual(p.PROVENANCE_ORDER[0], p.ADVERSARY)


if __name__ == "__main__":
    unittest.main()

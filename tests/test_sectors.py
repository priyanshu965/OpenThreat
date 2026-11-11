"""Unit tests for sectors.py — the confidence-laddered sector classifier."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import sectors as s                                    # noqa: E402


class TestExplicit(unittest.TestCase):
    def test_ransomware_activity_is_explicit(self):
        item = {"title": "x", "description": "y", "sector_hint": "Healthcare"}
        sector, conf = s.classify_sector(item)
        self.assertEqual(sector, s.HEALTHCARE)
        self.assertEqual(conf, "explicit")

    def test_unmapped_activity_still_explicit_as_corporate(self):
        item = {"title": "x", "description": "y", "sector_hint": "Widget Polishing"}
        sector, conf = s.classify_sector(item)
        self.assertEqual(sector, s.CORPORATE)
        self.assertEqual(conf, "explicit")

    def test_explicit_beats_keyword(self):
        # Hint says financial even though the text screams hospital.
        item = {"title": "Hospital breach", "description": "medical records",
                "sector_hint": "Banking"}
        sector, conf = s.classify_sector(item)
        self.assertEqual(sector, s.FINANCIAL)
        self.assertEqual(conf, "explicit")


class TestInferred(unittest.TestCase):
    def test_keyword_match_is_inferred(self):
        item = {"title": "Major hospital hit by ransomware",
                "description": "patient data exposed"}
        sector, conf = s.classify_sector(item)
        self.assertEqual(sector, s.HEALTHCARE)
        self.assertEqual(conf, "inferred")

    def test_defence_matches(self):
        item = {"title": "Army logistics network breached", "description": ""}
        self.assertEqual(s.classify_sector(item)[0], s.DEFENCE)

    def test_energy_phrase(self):
        item = {"title": "Attack on power grid operator", "description": ""}
        self.assertEqual(s.classify_sector(item)[0], s.ENERGY)


class TestWholeTokenGuards(unittest.TestCase):
    """The whole point of the word-boundary matcher: no substring false hits."""

    def test_navy_not_in_navigate(self):
        item = {"title": "How to navigate the new dashboard", "description": ""}
        self.assertIsNone(s.classify_sector(item)[0])

    def test_army_not_in_armygrp(self):
        item = {"title": "Malware sample armygrp.dll analysed", "description": ""}
        # "army" must not fire inside "armygrp"
        self.assertIsNone(s.classify_sector(item)[0])

    def test_bank_not_in_riverbank(self):
        item = {"title": "Flooding along the riverbank", "description": ""}
        self.assertIsNone(s.classify_sector(item)[0])

    def test_flight_still_matches_as_a_word(self):
        item = {"title": "Flight booking system outage", "description": ""}
        self.assertEqual(s.classify_sector(item)[0], s.AVIATION)


class TestNone(unittest.TestCase):
    def test_generic_item_gets_no_sector(self):
        item = {"title": "New TLS 1.3 library released", "description": "performance notes"}
        sector, conf = s.classify_sector(item)
        self.assertIsNone(sector)
        self.assertEqual(conf, "none")


class TestAnnotate(unittest.TestCase):
    def test_annotate_tags_in_place_and_counts(self):
        items = [
            {"title": "Hospital ransomware", "description": ""},
            {"title": "Bank data breach", "description": ""},
            {"title": "Generic CVE advisory", "description": "buffer overflow"},
        ]
        counts = s.annotate_sectors(items)
        self.assertEqual(items[0]["sector"], s.HEALTHCARE)
        self.assertEqual(items[0]["sector_confidence"], "inferred")
        self.assertEqual(items[1]["sector"], s.FINANCIAL)
        self.assertNotIn("sector", items[2])
        self.assertEqual(counts.get(s.HEALTHCARE), 1)
        self.assertEqual(counts.get(s.FINANCIAL), 1)

    def test_every_sector_has_a_label(self):
        for sec in s.SECTORS:
            self.assertIn(sec, s.SECTOR_LABELS)


if __name__ == "__main__":
    unittest.main()

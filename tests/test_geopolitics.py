"""Unit tests for geopolitics.py — actor origin x target, with attribution care."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import geopolitics as gp                               # noqa: E402


class TestTargetExtraction(unittest.TestCase):
    def test_country_name(self):
        out = {t["cc"] for t in gp.extract_target_countries("Attack on Ukraine power grid")}
        self.assertIn("UA", out)

    def test_demonym(self):
        out = {t["cc"] for t in gp.extract_target_countries("Ukrainian energy company breached")}
        self.assertIn("UA", out)

    def test_multiword_country(self):
        out = {t["cc"] for t in gp.extract_target_countries("United States federal agency hit")}
        self.assertIn("US", out)

    def test_dedupe(self):
        out = gp.extract_target_countries("American firm and US agency and United States dept")
        self.assertEqual(len([t for t in out if t["cc"] == "US"]), 1)

    def test_whole_token_no_false_positive(self):
        # "iranian" is a demonym, but "irate" must not match "iran".
        out = {t["cc"] for t in gp.extract_target_countries("The irate customer complained")}
        self.assertNotIn("IR", out)

    def test_empty(self):
        self.assertEqual(gp.extract_target_countries(""), [])


class TestOriginsMap(unittest.TestCase):
    def setUp(self):
        self.origins = gp.load_actor_origins()

    def test_map_loads(self):
        self.assertGreater(len(self.origins), 5)

    def test_every_entry_has_source_and_confidence(self):
        for actor, info in self.origins.items():
            self.assertIn("source", info, actor)
            self.assertTrue(info["source"], actor)
            self.assertIn(info["confidence"], ("suspected", "attributed"), actor)
            self.assertIn("cc", info, actor)

    def test_lazarus_is_north_korea(self):
        self.assertEqual(self.origins["Lazarus"]["cc"], "KP")


class TestBuildGeopolitics(unittest.TestCase):
    def _items(self):
        return [
            {"title": "APT28 targets Ukrainian ministry", "description": "",
             "threat_actors": ["APT28"], "sector": "government"},
            {"title": "Lazarus hits South Korean bank", "description": "",
             "threat_actors": ["Lazarus"], "sector": "financial"},
            {"title": "Generic CVE", "description": "buffer overflow"},
        ]

    def test_origins_rolled_up(self):
        g = gp.build_geopolitics(self._items())
        ccs = {o["cc"] for o in g["suspected_origins"]}
        self.assertIn("RU", ccs)   # APT28
        self.assertIn("KP", ccs)   # Lazarus

    def test_origin_by_sector(self):
        g = gp.build_geopolitics(self._items())
        ru = next(o for o in g["suspected_origins"] if o["cc"] == "RU")
        self.assertEqual(ru["by_sector"].get("government"), 1)

    def test_origin_by_target(self):
        g = gp.build_geopolitics(self._items())
        ru = next(o for o in g["suspected_origins"] if o["cc"] == "RU")
        self.assertEqual(ru["by_target"].get("UA"), 1)

    def test_every_origin_carries_a_source(self):
        """Attribution honesty: no origin may appear without provenance."""
        g = gp.build_geopolitics(self._items())
        for o in g["suspected_origins"]:
            self.assertTrue(o["sources"], o["cc"])
        for a in g["attributions"]:
            self.assertTrue(a["source"], a["actor"])
            self.assertIn(a["confidence"], ("suspected", "attributed"))

    def test_no_invented_confidence_number(self):
        """We must never manufacture a numeric confidence for attribution."""
        import json
        g = gp.build_geopolitics(self._items())
        blob = json.dumps(g)
        # confidence is a label, never a percentage.
        self.assertNotIn("confidence_pct", blob)
        self.assertNotIn("confidence_score", blob)

    def test_unknown_actor_ignored(self):
        items = [{"title": "SomeGroup attack", "threat_actors": ["NotInMap"],
                  "description": ""}]
        g = gp.build_geopolitics(items)
        self.assertEqual(g["suspected_origins"], [])

    def test_disclaimer_present(self):
        g = gp.build_geopolitics(self._items())
        self.assertIn("not", g["disclaimer"].lower())


if __name__ == "__main__":
    unittest.main()

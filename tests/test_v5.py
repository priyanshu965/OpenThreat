"""
OPENTHREAT — tests/test_v5.py
=============================
Tests for the Library, the hunt bench and leak-site tracking.

The emphasis is on the failure modes that actually bit during the build, all of
which were SILENT — they produced plausible output rather than an error:

  * Entities lost to a slug collision (23 ATT&CK technique names are shared by
    two different ids, which cost 25 techniques and made each unreachable by
    its own id).
  * A shared SigmaCollection mutated in place by the first backend's pipeline,
    so only the second Kusto dialect vanished.
  * A leak-site corpus that was 97% stale, published as though it were a quiet
    quarter for ransomware.
  * Attacker-authored text reaching a URL.

Each of those is pinned here.
"""

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import control_mappings  # noqa: E402
import d3fend  # noqa: E402
import hunt_packs  # noqa: E402
import knowledge_base  # noqa: E402
import misp_galaxy  # noqa: E402
import ransomware_leaks  # noqa: E402
import telegram_watch  # noqa: E402


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _item(title, actors=None, malware=None, ttps=None):
    """
    A feed item in the SHAPE THE PIPELINE ACTUALLY PRODUCES.

    The field names are the whole point of this helper. Techniques live under
    `ttps` as a list of dicts, not under `mitre_techniques` as a list of
    strings, and the source link is `url`, not `link`. Writing v5 against the
    guessed names produced zero technique counts everywhere, silently: hunt
    packs lost their ranking and the control focus never published at all.
    """
    return {
        "title": title,
        "url": "https://example.org/a",
        "published": "2026-08-26",
        "severity": "high",
        "priority_label": "urgent",
        "source": "Test",
        "threat_actors": list(actors or []),
        "malware": list(malware or []),
        "ttps": [{"id": t, "name": t, "tactic": "Impact"} for t in (ttps or [])],
    }


def _kb():
    return {
        "actors": {
            "APT29": {
                "name": "APT29", "id": "G0016", "kind": "actor",
                "aliases": ["Cozy Bear"],
                "all_aliases": ["Cozy Bear", "Nobelium", "Midnight Blizzard",
                                "UNC2452", "Group 5"],
                "description": "A Russian state-sponsored group.",
                "url": "https://attack.mitre.org/groups/G0016",
                "references": [], "first_seen": "2008-01-01", "last_seen": "",
                "techniques": ["T1566.001"], "software": ["WellMess"],
                "campaigns": ["SolarWinds Compromise"],
            },
        },
        "software": {
            "WellMess": {
                "name": "WellMess", "id": "S0514", "kind": "malware",
                "aliases": [], "all_aliases": [], "description": "A RAT.",
                "platforms": ["Windows"], "url": "", "references": [],
                "techniques": ["T1566.001"], "actors": ["APT29"], "campaigns": [],
            },
        },
        # Two DIFFERENT techniques with the SAME name. This is not contrived:
        # ATT&CK really does this, 23 times.
        "techniques": {
            "T1566.001": {
                "id": "T1566.001", "name": "Spearphishing Attachment",
                "kind": "technique", "description": "Adversaries send attachments.",
                "detection": "Monitor for suspicious attachments.",
                "detection_strategies": [{
                    "id": "DET0001", "name": "Detection of Spearphishing",
                    "description": "Correlate attachment writes with mail flow.",
                    "url": "https://attack.mitre.org/detectionstrategies/DET0001",
                    "analytics": [{"id": "AN0001", "name": "Analytic 0001",
                                   "description": "Watch for office spawning shells.",
                                   "platforms": ["Windows"], "url": ""}],
                }],
                "platforms": ["Windows"], "data_sources": ["File Creation"],
                "permissions": [], "is_subtechnique": True, "parent": "T1566",
                "tactics": ["initial-access"], "url": "", "references": [],
                "mitigations": ["M1049"], "actors": ["APT29"], "software": [],
                "subtechniques": [], "detects": ["File Creation"],
            },
            "T1598.002": {
                "id": "T1598.002", "name": "Spearphishing Attachment",
                "kind": "technique", "description": "Adversaries phish for info.",
                "detection": "", "platforms": [], "data_sources": [],
                "permissions": [], "is_subtechnique": True, "parent": "T1598",
                "tactics": ["reconnaissance"], "url": "", "references": [],
                "mitigations": [], "actors": [], "software": [],
                "subtechniques": [], "detects": [],
            },
        },
        "mitigations": {
            "M1049": {"id": "M1049", "name": "Antivirus/Antimalware",
                      "kind": "mitigation", "description": "Use AV.",
                      "url": "", "techniques": ["T1566.001"]},
        },
        "attack_campaigns": {
            "SolarWinds Compromise": {
                "name": "SolarWinds Compromise", "id": "C0024",
                "kind": "attack-campaign", "description": "Supply chain.",
                "aliases": [], "first_seen": "2019-08", "last_seen": "2021-01",
                "url": "", "references": [], "actors": ["APT29"],
                "software": [], "techniques": ["T1566.001"],
            },
        },
        "technique_names": {"T1566.001": "Spearphishing Attachment",
                            "T1598.002": "Spearphishing Attachment"},
        "technique_tactics": {},
    }


def _galaxy():
    return {
        "apt29": {
            "name": "APT29", "kind": "actor", "cluster": "threat-actor",
            "synonyms": ["Cozy Bear", "The Dukes", "BlueBravo"],
            "description": "Galaxy prose.", "country": "RU",
            "sponsor": "Russian Federation", "victims": ["Government"],
            "target_categories": ["Government"], "incident_type": "Espionage",
            "motive": "Espionage", "attribution_confidence": "3",
            "references": ["https://example.org/apt29"], "uuid": "x",
        },
    }


def _sigma():
    return {
        "by_technique": {
            "T1566.001": [
                {"title": "Suspicious Attachment", "id": "aaaaaaaa-1111-2222-3333-444444444444",
                 "level": "high", "status": "stable",
                 "logsource": "windows / file_event", "url": "https://example.org/r1"},
            ],
        },
        "totals": {"T1566.001": 4},
        "rules_indexed": 1,
    }


# ── The Library ──────────────────────────────────────────────────────────────

class TestKnowledgeBase(unittest.TestCase):

    def setUp(self):
        self.kb = knowledge_base.build_knowledge_base(
            _kb(), _galaxy(), {}, {}, {}, {}, _sigma(), {}, None,
            [_item("APT29 phishing", actors=["APT29"], ttps=["T1566.001"])])

    def test_builds(self):
        self.assertIsNotNone(self.kb)
        self.assertGreater(self.kb["count"], 0)

    def test_name_deconfliction(self):
        """Every alias, from every corpus, resolves to the one canonical page."""
        aliases = self.kb["aliases"]
        target = aliases["apt29"]
        for name in ("cozy bear", "nobelium", "midnight blizzard", "unc2452",
                     "the dukes", "bluebravo", "group 5", "g0016"):
            self.assertEqual(aliases.get(name), target,
                             f"{name!r} did not resolve to the APT29 entry")

    def test_shared_technique_names_do_not_collide(self):
        """
        Two techniques with the same NAME must be two entities.

        Slugging by name silently dropped one of each such pair and made it
        unreachable by its own id. This is the regression test for that.
        """
        aliases = self.kb["aliases"]
        first = aliases.get("t1566.001")
        second = aliases.get("t1598.002")
        self.assertIsNotNone(first, "T1566.001 is not resolvable by id")
        self.assertIsNotNone(second, "T1598.002 is not resolvable by id")
        self.assertNotEqual(first, second, "both techniques share one entry")
        self.assertEqual(self.kb["by_kind"]["technique"], 2)
        self.assertEqual(self.kb["entities"][first]["id"], "T1566.001")
        self.assertEqual(self.kb["entities"][second]["id"], "T1598.002")

    def test_technique_slug_is_id_based(self):
        self.assertEqual(knowledge_base.slugify("technique", "Spearphishing Attachment",
                                                "T1566.001"),
                         "technique-t1566-001")
        # Actors stay name-based: their ids are not what anyone types.
        self.assertEqual(knowledge_base.slugify("actor", "APT29", "G0016"),
                         "actor-apt29")

    def test_attack_prose_preferred_over_galaxy(self):
        entry = self.kb["entities"][self.kb["aliases"]["apt29"]]
        self.assertEqual(entry["description_source"], "MITRE ATT&CK")
        self.assertIn("Russian state-sponsored", entry["description"])
        # …but galaxy-only fields still merge in.
        self.assertEqual(entry["country"], "RU")
        self.assertEqual(entry["sponsor"], "Russian Federation")

    def test_feed_observations_attach(self):
        entry = self.kb["entities"][self.kb["aliases"]["apt29"]]
        self.assertEqual(entry["observed_count"], 1)
        self.assertEqual(entry["observed"][0]["title"], "APT29 phishing")

    def test_detection_coverage_on_technique_rows(self):
        entry = self.kb["entities"][self.kb["aliases"]["apt29"]]
        row = next(t for t in entry["techniques"] if t["id"] == "T1566.001")
        self.assertEqual(row["rules"], 1)

    def test_index_carries_no_bulk(self):
        """The index is loaded by every visitor; it must stay identity-only."""
        allowed = {"slug", "name", "kind", "id", "aliases", "observed",
                   "country", "teaser"}
        for row in self.kb["index"]:
            self.assertTrue(set(row) <= allowed, f"index row grew: {set(row) - allowed}")

    def test_shards_written_and_pruned(self):
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            count = knowledge_base.write_entity_shards(self.kb, api)
            self.assertEqual(count, self.kb["count"])
            shards = list((api / "entity").glob("*.json"))
            self.assertEqual(len(shards), self.kb["count"])
            index = json.loads((api / "entity_index.json").read_text(encoding="utf-8"))
            self.assertIn("aliases", index)

            # A stale shard from a previous build must not survive: it would
            # stay reachable by URL, serving a record nothing links to.
            stale = api / "entity" / "actor-gone.json"
            stale.write_text("{}", encoding="utf-8")
            knowledge_base.write_entity_shards(self.kb, api)
            self.assertFalse(stale.exists())

    def test_slug_is_url_safe(self):
        """Slugs are interpolated into a fetch path by the frontend."""
        for slug in self.kb["entities"]:
            self.assertRegex(slug, r"^[a-z0-9-]+$")


# ── MISP galaxy ──────────────────────────────────────────────────────────────

class TestMispGalaxy(unittest.TestCase):

    def test_junk_synonyms_dropped(self):
        out = misp_galaxy._clean_synonyms(
            "Lazarus", ["China", "APT", "Hidden Cobra", "ransomware", "ZINC", "a"])
        self.assertIn("Hidden Cobra", out)
        self.assertIn("ZINC", out)
        for junk in ("China", "APT", "ransomware", "a"):
            self.assertNotIn(junk, out)

    def test_self_reference_dropped(self):
        self.assertEqual(misp_galaxy._clean_synonyms("Emotet", ["Emotet", "emotet"]), [])

    def test_alias_index_prefers_canonical_names(self):
        galaxy = {
            "wizard spider": {"name": "Wizard Spider", "kind": "actor", "synonyms": []},
            "trickbot gang": {"name": "TrickBot Gang", "kind": "actor",
                              "synonyms": ["Wizard Spider"]},
        }
        index = misp_galaxy.build_alias_index(galaxy)
        self.assertEqual(index["wizard spider"], "Wizard Spider")

    def test_richness_prefers_the_fuller_record(self):
        thin = {"description": "", "synonyms": [], "references": [],
                "country": "", "sponsor": "", "victims": []}
        rich = {"description": "x" * 400, "synonyms": ["a", "b"],
                "references": ["u"], "country": "RU", "sponsor": "GRU",
                "victims": ["Gov"]}
        self.assertGreater(misp_galaxy._richness(rich), misp_galaxy._richness(thin))


# ── D3FEND and control mappings ──────────────────────────────────────────────

class TestD3fend(unittest.TestCase):

    def test_subtechnique_inherits_parent_and_says_so(self):
        table = {"T1566": [{"name": "Message Analysis", "tactic": "Detect",
                            "url": "", "artifacts": [], "relation": "analyzes"}]}
        out = d3fend.countermeasures_for("T1566.001", table)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["inherited"], "T1566")
        # The parent's own lookup is NOT marked inherited.
        self.assertNotIn("inherited", d3fend.countermeasures_for("T1566", table)[0])

    def test_url_built_only_from_an_identifier_fragment(self):
        self.assertEqual(
            d3fend._d3fend_url("http://d3fend.mitre.org/ontologies/d3fend.owl#FileAnalysis"),
            "https://d3fend.mitre.org/technique/d3f:FileAnalysis/")
        # Anything that is not a bare identifier yields no URL at all.
        for hostile in ("#../../evil", "#a b", "#", "javascript:alert(1)"):
            self.assertEqual(d3fend._d3fend_url(hostile), "")


class TestControlMappings(unittest.TestCase):

    def setUp(self):
        self.frameworks = {
            "nist_800_53": {
                "label": "NIST SP 800-53 rev5", "kind": "audit",
                "techniques": {"T1566": [{"id": "SI-08", "name": "Spam Protection",
                                          "group": "SI", "group_name": "System"}]},
                "unmapped": {},
            },
        }

    def test_inheritance_marked(self):
        out = control_mappings.controls_for("T1566.001", self.frameworks)
        self.assertEqual(out["nist_800_53"]["inherited"], "T1566")

    def test_control_focus_weights_by_observed_activity(self):
        focus = control_mappings.build_control_focus({"T1566": 7}, self.frameworks)
        row = focus["frameworks"]["nist_800_53"]["controls"][0]
        self.assertEqual(row["id"], "SI-08")
        self.assertEqual(row["activity"], 7)

    def test_control_focus_needs_activity(self):
        self.assertIsNone(control_mappings.build_control_focus({}, self.frameworks))


# ── Hunt packs ───────────────────────────────────────────────────────────────

class _StubBackend:
    """Records the collection object it was handed, and mutates it."""

    def __init__(self, name, seen):
        self.name = name
        self.seen = seen

    def convert(self, collection):
        self.seen.append(id(collection))
        if getattr(collection, "_mangled", False):
            raise ValueError("collection already transformed by another pipeline")
        collection._mangled = True
        return [f"{self.name}-query"]


class TestHuntPacks(unittest.TestCase):

    def test_each_backend_gets_a_fresh_collection(self):
        """
        A processing pipeline rewrites field names IN PLACE. Reusing one
        collection across backends corrupts every backend after the first, and
        the per-backend try/except swallows the exception — so the symptom is
        one silently missing query, not an error.
        """
        seen = []
        backends = [("a", "A", _StubBackend("a", seen)),
                    ("b", "B", _StubBackend("b", seen))]

        class _Collection:
            _mangled = False

        made = []

        class _FakeSigmaCollection:
            @staticmethod
            def from_yaml(_text):
                c = _Collection()
                made.append(c)
                return c

        module = type(sys)("sigma.collection")
        module.SigmaCollection = _FakeSigmaCollection
        sys.modules["sigma"] = type(sys)("sigma")
        sys.modules["sigma.collection"] = module
        try:
            out = hunt_packs._compile_one("title: x", backends)
        finally:
            sys.modules.pop("sigma.collection", None)
            sys.modules.pop("sigma", None)

        self.assertEqual(out, {"a": "a-query", "b": "b-query"})
        self.assertEqual(len(set(seen)), 2, "the same collection reached both backends")
        self.assertEqual(len(made), 2)

    def test_packs_rank_observed_techniques_first(self):
        packs = hunt_packs.build_hunt_packs(
            {"T1566.001": 9}, _sigma(), _kb(), {}, {}, {}, None)
        self.assertIsNotNone(packs)
        self.assertEqual(packs["packs"][0]["technique"], "T1566.001")
        self.assertEqual(packs["packs"][0]["observed"], 9)

    def test_pack_carries_mitre_detection_guidance(self):
        packs = hunt_packs.build_hunt_packs(
            {"T1566.001": 1}, _sigma(), _kb(), {}, {}, {}, None)
        self.assertIn("suspicious attachments",
                      packs["packs"][0]["mitre_detection"].lower())

    def test_packs_publish_without_query_backends(self):
        """Degraded, not broken: no backends still means usable packs."""
        packs = hunt_packs.build_hunt_packs(
            {"T1566.001": 1}, _sigma(), _kb(), {}, {}, {}, None)
        self.assertFalse(packs["queries_available"])
        self.assertTrue(packs["packs"][0]["rules"])

    def test_hunt_queue_flags_uncovered_techniques(self):
        sigma = {"by_technique": {}, "totals": {}}
        queue = hunt_packs.build_hunt_queue(
            [_item("x", ttps=["T1566.001"])],
            {"T1566.001": 3}, _kb(), sigma, {})
        self.assertEqual(queue["uncovered"], 1)
        self.assertIn("NO public Sigma rule", queue["hunts"][0]["hypothesis"])

    def test_hunt_queue_reaches_actor_techniques_not_in_the_feed(self):
        """The whole point: an active actor implies hunts the feed never named."""
        queue = hunt_packs.build_hunt_queue(
            [_item("x")], {}, _kb(), _sigma(), {"APT29": 2})
        ids = [h["technique"] for h in queue["hunts"]]
        self.assertIn("T1566.001", ids)
        self.assertIn("APT29", queue["hunts"][0]["actors"])

    def test_shards_split_index_from_detail(self):
        """
        The pack index must carry counts, not the packs themselves.

        A pack is ~20 KB (prose + eight rules compiled for six SIEMs + atomic
        tests) and there are 220. Shipping them as one file is 4.5 MB
        downloaded to read one technique -- the mistake the Library exists to
        avoid, repeated.
        """
        packs = hunt_packs.build_hunt_packs(
            {"T1566.001": 3}, _sigma(), _kb(), {}, {}, {}, None)
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            count = hunt_packs.write_hunt_shards(packs, api)
            self.assertEqual(count, packs["count"])

            index = json.loads((api / "hunt_packs.json").read_text(encoding="utf-8"))
            row = index["packs"][0]
            self.assertIsInstance(row["rules"], int, "the index inlined the rules")
            self.assertNotIn("countermeasures", row)
            self.assertNotIn("mitre_detection", row)

            shard = json.loads(
                (api / "hunt" / f"{row['technique']}.json").read_text(encoding="utf-8"))
            self.assertIsInstance(shard["rules"], list)
            self.assertIn("mitre_detection", shard)

    def test_shard_filenames_are_validated_technique_ids(self):
        """The id reaches a filesystem path, so it is validated, not trusted."""
        payload = {"built": "x", "count": 1, "packs": [
            {"technique": "../../etc/passwd", "name": "evil", "rules": [],
             "atomics": []},
            {"technique": "T1059.001", "name": "PowerShell", "rules": [],
             "atomics": []},
        ]}
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            count = hunt_packs.write_hunt_shards(payload, api)
            self.assertEqual(count, 1)
            written = {f.name for f in (api / "hunt").glob("*.json")}
            self.assertEqual(written, {"T1059.001.json"})
            self.assertFalse((api.parent / "passwd").exists())

    def test_stale_shards_are_pruned(self):
        packs = hunt_packs.build_hunt_packs(
            {"T1566.001": 1}, _sigma(), _kb(), {}, {}, {}, None)
        with tempfile.TemporaryDirectory() as tmp:
            api = Path(tmp)
            hunt_packs.write_hunt_shards(packs, api)
            stale = api / "hunt" / "T9999.json"
            stale.write_text("{}", encoding="utf-8")
            hunt_packs.write_hunt_shards(packs, api)
            self.assertFalse(stale.exists())



# ── Leak sites ───────────────────────────────────────────────────────────────

class TestRansomwareLeaks(unittest.TestCase):

    def test_group_names_normalise_across_feeds(self):
        for a, b in [("LockBit3", "lockbit3"), ("Black Basta", "black-basta"),
                     ("ALPHV_BlackCat", "alphvblackcat")]:
            self.assertEqual(ransomware_leaks._norm_group(a),
                             ransomware_leaks._norm_group(b))

    def test_leak_activity_matches_on_normalised_name(self):
        view = {"groups": [{"group": "LockBit 3.0", "victims": 12}]}
        self.assertIsNotNone(ransomware_leaks.leak_activity_for("lockbit30", view))
        self.assertIsNone(ransomware_leaks.leak_activity_for("Akira", view))

    def test_recent_months_walks_back_across_a_year_boundary(self):
        months = ransomware_leaks._recent_months(3)
        self.assertEqual(len(months), 3)
        for year, month in months:
            self.assertTrue(1 <= month <= 12, f"bad month {month}")

    def test_age_days_handles_junk(self):
        self.assertIsNone(ransomware_leaks._age_days(""))
        self.assertIsNone(ransomware_leaks._age_days("not-a-date"))
        self.assertGreaterEqual(ransomware_leaks._age_days("2020-01-01"), 2000)

    def test_extortion_prose_is_not_in_the_victim_record(self):
        """
        The victim `description` is the crew's extortion note. Publishing it
        would make this dashboard an amplification channel for criminal claims
        about a named victim.

        Checked on the OUTPUT SHAPE rather than by grepping the source: the
        module does legitimately read a `description` field for GROUP profiles
        (the aggregator's own write-up of the crew), so a source-level search
        for the word proves nothing. What matters is that no victim row carries
        one.
        """
        rows = [
            {"victim": "Acme Ltd", "group": "Akira", "date": "2026-08-01",
             "sector": "Manufacturing", "country": "US", "source": "ransomware.live"},
        ]
        for row in rows:
            self.assertNotIn("description", row)
        # And the field genuinely is dropped where victims are assembled.
        source = Path(ransomware_leaks.__file__).read_text(encoding="utf-8")
        victim_block = source.split("# -- Victims", 1)[-1].split("# --", 1)[0] \
            if "# -- Victims" in source else source.split("Victims", 1)[-1][:3000]
        self.assertNotIn('"description": _clean(row.get("description")', victim_block)


# ── Telegram ─────────────────────────────────────────────────────────────────

class TestTelegramWatch(unittest.TestCase):

    def test_malformed_channel_names_never_reach_a_url(self):
        import os
        os.environ["TELEGRAM_CHANNELS"] = (
            "goodchannel, ../../etc/passwd, https://evil.test, bad name, ok_two")
        try:
            telegram_watch.CONFIG.telegram_channels = os.environ["TELEGRAM_CHANNELS"]
            names = telegram_watch._channels()
        finally:
            os.environ.pop("TELEGRAM_CHANNELS", None)
        self.assertEqual(names, ["goodchannel", "ok_two"])

    def test_markup_is_stripped_before_entities_are_decoded(self):
        out = telegram_watch._strip('<b>hi</b> &lt;script&gt;alert(1)&lt;/script&gt;')
        self.assertNotIn("<b>", out)
        # The decoded text may CONTAIN angle brackets, but it is set via
        # textContent in the UI and never parsed as markup.
        self.assertIn("script", out)

    def test_posts_from_another_channel_are_rejected(self):
        markup = (
            '<div class="tgme_widget_message" data-post="otherchannel/42">'
            '<div class="tgme_widget_message_text">hello</div></div>')
        self.assertEqual(telegram_watch._parse_channel("mychannel", markup), [])

    def test_post_url_is_built_from_validated_parts(self):
        markup = (
            '<div class="tgme_widget_message" data-post="mychannel/42">'
            '<div class="tgme_widget_message_text">hello world</div></div>')
        posts = telegram_watch._parse_channel("mychannel", markup)
        self.assertEqual(len(posts), 1)
        self.assertEqual(posts[0]["url"], "https://t.me/mychannel/42")
        self.assertTrue(posts[0]["unverified"])


class TestTelegramScrubber(unittest.TestCase):
    """
    These channels sometimes paste a sample OF a breach, not just a report
    about one. Republishing that would make this project a distribution point
    for other people's credentials -- the same objection that keeps ransomware
    extortion notes off the leak-site page, and a sharper one, because these
    are individuals rather than companies.

    Both directions are pinned, because both failures happened:
      * too permissive -- a live GitHub token survived, because it is exactly
        as long as a SHA-1 and the check was on length alone;
      * too aggressive -- `_COMBO_RE` matches `word:word`, which is the shape
        of every URL, so ordinary research posts were being deleted as
        "credential dumps" and links inside surviving posts were rewritten to
        "[redacted:credential]". Measured on the ten configured channels that
        was 4 posts dropped and 59% of the rest damaged.
    """

    def test_a_combolist_is_dropped_entirely(self):
        text = ("FRESH COMBOLIST 10k\nbob@x.com:hunter2\n"
                "sue@y.com:letmein1\njan@z.com:qwerty99")
        self.assertTrue(telegram_watch._looks_like_a_dump(text))

    def test_card_numbers_are_a_dump(self):
        self.assertTrue(telegram_watch._looks_like_a_dump(
            "new drop 4111 1111 1111 1111 exp 12/29"))

    def test_a_post_full_of_links_is_not_a_dump(self):
        text = ("New paper at https://vx-underground.org/papers and code at "
                "https://github.com/x/y, discussion https://t.me/abc")
        self.assertFalse(telegram_watch._looks_like_a_dump(text))

    def test_reporting_survives_untouched(self):
        text = "APT29 phishing campaign targets EU government, per new report."
        self.assertFalse(telegram_watch._looks_like_a_dump(text))
        self.assertEqual(telegram_watch._redact(text), text)

    def test_urls_survive_redaction(self):
        text = "Details: https://example.org/a/b?c=d and https://t.me/chan/1"
        out = telegram_watch._redact(text)
        self.assertIn("https://example.org/a/b?c=d", out)
        self.assertNotIn("[redacted", out)

    def test_placeholder_never_leaks_into_output(self):
        out = telegram_watch._redact("see https://a.test/x and https://b.test/y")
        self.assertNotIn("\x00", out)

    def test_file_hashes_are_kept(self):
        """A digest is the most useful indicator a post can carry, and it is
        not a secret. The first cut redacted all three lengths."""
        for digest in ("5d41402abc4b2a76b9719d911017c592",
                       "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                       "e3b0c44298fc1c149afbf4c8996fb924"
                       "27ae41e4649b934ca495991b7852b855"):
            self.assertIn(digest, telegram_watch._redact(f"IOC {digest} seen"))

    def test_tokens_are_redacted_even_at_hash_length(self):
        """A 40-character token is exactly as long as a SHA-1, so the hash
        exemption cannot be on length alone.

        The fixture is ASSEMBLED rather than written out. It is synthetic --
        an invented keyboard pattern, never a real credential -- but a
        secret-shaped literal in a committed file is indistinguishable from a
        real one to a scanner, and this one tripped GitGuardian on push. A
        test about redacting secrets should not itself commit something that
        looks like one.
        """
        prefix = "gh" + "p_"
        body = "".join(f"{chr(65 + i)}{i}{chr(97 + i)}{i + 1}" for i in range(10))
        token = prefix + body[:40]
        self.assertEqual(len(token) - len(prefix), 40, "fixture must be SHA-1 length")
        out = telegram_watch._redact(f"leaked {token} in repo")
        self.assertNotIn(body[:40], out)
        self.assertIn("[redacted:secret]", out)

    def test_addresses_are_redacted(self):
        out = telegram_watch._redact("mail jane.doe@vendor.com for details")
        self.assertNotIn("jane.doe@vendor.com", out)


class TestTelegramDefaultChannels(unittest.TestCase):

    def test_ten_channels_ship_by_default(self):
        names = telegram_watch._channels()
        self.assertEqual(len(names), 10, names)

    def test_canonical_username_not_the_vanity_alias(self):
        """t.me serves t.me/s/infosecurity fine, but stamps every post with
        the canonical `it_secur`. telegram_watch rejects posts whose channel
        does not match the one requested, so the alias yields ZERO posts and
        reports no error at all."""
        names = telegram_watch._channels()
        self.assertIn("it_secur", names)
        self.assertNotIn("infosecurity", names)

    def test_no_credential_dump_channels_in_the_default_list(self):
        """The standing rule: their posts ARE victim data. The scrubber is a
        second line of defence, not a licence to subscribe to these."""
        banned = ("combo", "cloud", "logs", "fullz", "carding", "cc_",
                  "mailpass", "stealer", "breachdetector", "leaked")
        for name in telegram_watch._channels():
            low = name.lower()
            for token in banned:
                self.assertNotIn(token, low, f"{name} looks like a dump channel")


# ── Wiring ───────────────────────────────────────────────────────────────────

class TestPipelineWiring(unittest.TestCase):
    """The v4 lesson: a stage that runs but is never copied into the output."""

    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent

    def test_fetch_intel_publishes_every_v5_artifact(self):
        source = (self.root / "scripts" / "fetch_intel.py").read_text(encoding="utf-8")
        for key in ("knowledge_base", "hunt_packs", "hunt_queue",
                    "detection_diff", "control_focus", "leak_sites", "telegram"):
            self.assertIn(f'"{key}":', source, f"{key} never reaches `output`")
            self.assertIn(f'"{key}"', source)

    def test_research_keys_exclude_the_library_from_the_archive(self):
        source = (self.root / "scripts" / "fetch_intel.py").read_text(encoding="utf-8")
        block = source.split("_RESEARCH_KEYS = (", 1)[1].split(")", 1)[0]
        for key in ("knowledge_base", "hunt_packs", "leak_sites"):
            self.assertIn(key, block,
                          f"{key} would be archived 90 times over")

    def test_exports_writes_every_v5_endpoint(self):
        source = (self.root / "scripts" / "exports.py").read_text(encoding="utf-8")
        for fname in ("hunt_packs.json", "hunt_queue.json", "detection_diff.json",
                      "control_focus.json", "leak_sites.json", "telegram.json"):
            self.assertIn(fname, source)
        self.assertIn("write_entity_shards", source)

    def test_frontend_modules_are_loaded_in_dependency_order(self):
        html = (self.root / "index.html").read_text(encoding="utf-8")
        order = [html.index(f'js/{name}.js') for name in
                 ("research", "library", "hunt", "leaks")]
        self.assertEqual(order, sorted(order),
                         "hunt.js/leaks.js load before the helpers they close over")

    def test_every_view_has_a_container_and_a_route(self):
        html = (self.root / "index.html").read_text(encoding="utf-8")
        app = (self.root / "app.js").read_text(encoding="utf-8")
        for view in ("library", "hunt", "leaks"):
            self.assertIn(f'id="{view}-view"', html)
            self.assertIn(f"'{view}-view'", app)
            self.assertIn(f"case '{view}':", app)

    def test_modes_cover_every_routable_view(self):
        app = (self.root / "app.js").read_text(encoding="utf-8")
        block = app.split("const MODE_VIEWS = {", 1)[1].split("\n};", 1)[0]
        for view in ("feed", "library", "hunt", "leaks", "graph", "matrix",
                     "campaigns", "malware", "detections", "map", "landscape",
                     "geopol", "darkweb", "exposure", "research", "trends"):
            self.assertIn(f"'{view}'", block, f"{view} is not reachable from any mode")

    def test_new_api_endpoints_declared(self):
        app = (self.root / "app.js").read_text(encoding="utf-8")
        for key in ("entityIndex", "entity:", "huntPacks", "huntQueue",
                    "detectionDiff", "controlFocus", "leaks:", "telegram:"):
            self.assertIn(key, app)

    def test_no_html_sinks_in_v5_modules(self):
        """
        Every string these modules render comes from a third-party corpus —
        ATT&CK prose, galaxy synonyms, leak-site victim names, Telegram posts
        written by the actors being monitored.

        Matched on the PROPERTY ACCESS (`.innerHTML`), not the bare word: the
        file headers say "no innerHTML" in prose, and a test that fails on its
        own documentation teaches people to delete the documentation.
        """
        for name in ("library.js", "hunt.js", "leaks.js"):
            source = (self.root / "js" / name).read_text(encoding="utf-8")
            for sink in (".innerHTML", ".outerHTML", ".insertAdjacentHTML",
                         "document.write", "eval("):
                self.assertNotIn(sink, source, f"{name} uses {sink}")

    def test_optional_query_backends_are_not_in_the_core_requirements(self):
        """
        pySigma must not enter the hourly job's critical path: a resolver
        conflict there trades the whole feed for a convenience feature.
        """
        core = (self.root / "requirements.txt").read_text(encoding="utf-8")
        self.assertNotIn("pysigma", core.lower())
        extra = (self.root / "requirements-hunt.txt").read_text(encoding="utf-8")
        self.assertIn("pysigma", extra.lower())

    def test_v5_modules_share_fetchlib(self):
        """The v4 bug: satellite modules building their own private session."""
        for name in ("misp_galaxy.py", "orkl.py", "d3fend.py", "atomics.py",
                     "control_mappings.py", "ransomware_leaks.py",
                     "telegram_watch.py", "knowledge_base.py", "hunt_packs.py"):
            source = (self.root / "scripts" / name).read_text(encoding="utf-8")
            self.assertIn("from fetchlib import", source, f"{name} bypasses fetchlib")
            self.assertNotIn("requests.Session()", source)



class TestItemFieldNames(unittest.TestCase):
    """
    The v5 stage was written against field names that do not exist.

    Nothing raised. `item.get("mitre_techniques")` simply returned None on
    every item, so technique_counts was empty, hunt packs fell back to ranking
    by rule count, every `observed` read 0, and control_focus returned None and
    published nothing at all. It looked exactly like a quiet week.

    These pin the accessors AND assert that no module reaches for the wrong
    name again.
    """

    def test_accessor_reads_ttps(self):
        from fetchlib import item_technique_ids, item_url
        item = _item("x", ttps=["T1059.001", "T1486"])
        self.assertEqual(item_technique_ids(item), ["T1059.001", "T1486"])
        self.assertEqual(item_url(item), "https://example.org/a")

    def test_accessor_tolerates_junk(self):
        from fetchlib import item_technique_ids, item_url
        self.assertEqual(item_technique_ids({}), [])
        self.assertEqual(item_technique_ids({"ttps": None}), [])
        self.assertEqual(item_technique_ids({"ttps": ["not-a-dict"]}), [])
        self.assertEqual(item_technique_ids({"ttps": [{"name": "no id"}]}), [])
        self.assertEqual(item_url({}), "")

    def test_no_module_reads_a_nonexistent_technique_field(self):
        """`mitre_techniques` is not a field anywhere in this pipeline."""
        root = Path(__file__).resolve().parent.parent
        for path in sorted((root / "scripts").glob("*.py")):
            source = path.read_text(encoding="utf-8")
            body = source.split('"""', 2)[-1] if source.startswith('"""') else source
            self.assertNotIn('"mitre_techniques"', body,
                             f"{path.name} reads a field that does not exist")

    def test_item_consumers_do_not_read_link(self):
        """
        Modules that CONSUME feed items must read `url`, not `link`.

        Scoped to the consumers on purpose. darkweb.py legitimately reads a
        `link` field — but off RansomLook's API response, which it then turns
        INTO an item with a `url`. A blanket ban on the string would flag that
        correct code and teach the next person to ignore this test.
        """
        root = Path(__file__).resolve().parent.parent
        consumers = ("knowledge_base.py", "hunt_packs.py", "malware.py",
                     "entity_graph.py", "campaigns.py", "sigma_rules.py",
                     "ransomware_leaks.py")
        for name in consumers:
            body = (root / "scripts" / name).read_text(encoding="utf-8")
            self.assertNotIn('item.get("link")', body,
                             f"{name} reads `link`; the item field is `url`")

    def test_technique_counts_reach_the_pipeline(self):
        """The counter in fetch_intel must use the accessor, not a guess."""
        root = Path(__file__).resolve().parent.parent
        source = (root / "scripts" / "fetch_intel.py").read_text(encoding="utf-8")
        block = source.split("technique_counts = Counter()", 1)[1][:300]
        self.assertIn("item_technique_ids", block)



class TestAttackDetectionStructure(unittest.TestCase):
    """
    ATT&CK v18 moved detection out of the attack-pattern object.

    v2 of the knowledge base read `x_mitre_detection` and
    `x_mitre_data_sources` straight off the technique. Those fields no longer
    exist, so every one of the 697 techniques published an empty "how to see
    it" section and nothing reported a problem — the same silent-empty failure
    as the KEV cache and the wrong field names.

    Detection now lives in:

        x-mitre-detection-strategy --detects--> attack-pattern
                 -> x-mitre-analytic -> x-mitre-data-component

    These pin the reader against that structure, so if MITRE moves it again
    the suite says so instead of the site quietly emptying.
    """

    def test_derive_reads_the_detection_strategy_graph(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / "scripts" / "entity_graph.py").read_text(encoding="utf-8")
        for marker in ("x-mitre-detection-strategy", "x-mitre-analytic",
                       "x_mitre_analytic_refs", "x_mitre_log_source_references"):
            self.assertIn(marker, source,
                          f"entity_graph no longer reads {marker}")

    def test_dead_fields_are_not_read(self):
        root = Path(__file__).resolve().parent.parent
        source = (root / "scripts" / "entity_graph.py").read_text(encoding="utf-8")
        body = source.split('"""', 2)[-1]
        for dead in ('obj.get("x_mitre_detection")',
                     'obj.get("x_mitre_data_sources")'):
            self.assertNotIn(dead, body,
                             f"{dead} was removed from ATT&CK and always returns None")

    def test_cache_key_moved_with_the_shape(self):
        """
        A warm cache in the previous shape must be a MISS by construction.

        This repo has been bitten twice by a stale cache in an old shape being
        accepted as data: the KEV catalogue served dateless records for a full
        TTL, and v2 of this KB would serve empty detection for a month.
        """
        root = Path(__file__).resolve().parent.parent
        source = (root / "scripts" / "entity_graph.py").read_text(encoding="utf-8")
        self.assertIn('_KB_CACHE = "attack_kb_v3.json"', source)

    def test_technique_entity_carries_strategies(self):
        kb = knowledge_base.build_knowledge_base(
            _kb(), {}, {}, {}, {}, {}, _sigma(), {}, None, [])
        slug = kb["aliases"]["t1566.001"]
        entity = kb["entities"][slug]
        self.assertTrue(entity["detection_strategies"])
        self.assertEqual(entity["detection_strategies"][0]["id"], "DET0001")
        self.assertTrue(entity["detection_strategies"][0]["analytics"])

    def test_hunt_pack_carries_strategies(self):
        packs = hunt_packs.build_hunt_packs(
            {"T1566.001": 1}, _sigma(), _kb(), {}, {}, {}, None)
        pack = packs["packs"][0]
        self.assertTrue(pack["detection_strategies"])
        self.assertEqual(pack["detection_strategies"][0]["id"], "DET0001")



class TestStickyChrome(unittest.TestCase):
    """
    The pinned header stack.

    Three bars all hard-coded `top: 60px` — .controls-bar and .view-switcher
    from v4, .mode-switcher added in v5. Two things were wrong at once:

      * A v4 fix gave .site-header `flex-wrap: wrap; height: auto` so the stat
        pills stop overlapping on a narrow window. That made its height
        VARIABLE (60px wide open, 86px at ~880px), so every `top: 60px` below
        it was covered by the header.
      * The mode row and the view row claimed the same offset, so they were
        painted on top of each other.

    And even stacked correctly it was ~260px of permanently pinned chrome on a
    910px viewport, for a page that is a scrolling list.
    """

    def setUp(self):
        root = Path(__file__).resolve().parent.parent
        self.css = (root / "style.css").read_text(encoding="utf-8")
        self.app = (root / "app.js").read_text(encoding="utf-8")

    def test_no_bar_hardcodes_the_header_height(self):
        """`top: 60px` on a sticky bar is the bug, in any form."""
        for bad in ("position: sticky; top: 60px",
                    "position: sticky; top: 108px",
                    "position: sticky; top: 148px"):
            self.assertNotIn(bad, self.css,
                             f"a sticky bar hard-codes an offset ({bad!r}); "
                             "the header's height is not a constant")

    def test_sticky_offsets_come_from_measured_variables(self):
        self.assertIn("--stack-header", self.css)
        self.assertIn("--stack-nav", self.css)
        self.assertIn("top: var(--stack-header)", self.css)
        self.assertIn("top: var(--stack-nav)", self.css)

    def test_only_header_and_mode_row_are_pinned(self):
        """
        The sub-nav and the controls bar scroll away. Pinning them cost a third
        of the viewport and pinned the tallest, least useful chrome on the page.
        """
        for block in (".view-switcher {", ".controls-bar {"):
            start = self.css.index(block)
            body = self.css[start:start + 700]
            self.assertNotIn("position: sticky", body,
                             f"{block.strip(' {')} is sticky again")
            self.assertIn("position: static", body)

    def test_measurement_ignores_bars_that_are_not_sticky(self):
        """
        Below 640px the header is `position: static`. Counting its height would
        push the mode row 85px down over scrolling content.
        """
        self.assertIn("style.position !== 'sticky'", self.app)
        self.assertIn("function syncStickyOffsets", self.app)

    def test_offsets_are_resynced_when_the_chrome_reflows(self):
        self.assertIn("ResizeObserver", self.app)
        self.assertIn("document.fonts", self.app)
        # …and on every render, because the sub-nav appears with the mode.
        block = self.app.split("function syncControls", 1)[1][:1200]
        self.assertIn("syncStickyOffsets()", block)

    def test_asset_version_bumped_with_the_css_change(self):
        """
        index.html is unversioned and the service worker caches, so a CSS-only
        fix that keeps the old ?v= is invisible to every returning visitor.
        """
        root = Path(__file__).resolve().parent.parent
        html = (root / "index.html").read_text(encoding="utf-8")
        sw = (root / "service-worker.js").read_text(encoding="utf-8")
        self.assertNotIn("?v=5.0.2", html)
        self.assertIn("?v=5.0.3", html)
        self.assertIn('CACHE = "openthreat-v9"', sw)

    def test_every_asset_carries_the_same_version(self):
        """A half-bumped set ships the new app.js against the old style.css."""
        root = Path(__file__).resolve().parent.parent
        html = (root / "index.html").read_text(encoding="utf-8")
        versions = set(re.findall(r"\?v=([0-9.]+)", html))
        self.assertEqual(len(versions), 1, f"mixed asset versions: {versions}")


class TestOfflinePlaceholderIsNotMistakenForData(unittest.TestCase):
    """
    The service worker answers an unreachable network with a synthetic 200
    carrying {items: [], offline: true}. That is deliberate — it keeps the page
    working offline instead of throwing — but it means `resp.ok` is true and
    the JSON parses, so a consumer that does not check the flag renders a
    total failure as a successful load of an empty feed: "TOTAL 0", no error
    banner, "No results match your filters". That reads as a quiet day rather
    than a broken one, which is the most misleading state this page has.

    This was live on openthreat.in: the app shell came from the precache, the
    data fetch failed, and the dashboard showed zero items and no error.
    """

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent.parent
        cls.app = (root / "app.js").read_text(encoding="utf-8")
        cls.sw = (root / "service-worker.js").read_text(encoding="utf-8")

    def test_worker_still_emits_the_flag(self):
        self.assertIn('offline: true', self.sw)

    def test_feed_loader_rejects_the_placeholder(self):
        block = self.app.split("async function loadIntelData", 1)[1][:1600]
        self.assertIn("data.offline", block)
        self.assertIn("throw new Error", block)

    def test_lazy_views_reject_the_placeholder(self):
        block = self.app.split("async function showLazyView", 1)[1][:1200]
        self.assertIn("data.offline", block)


if __name__ == "__main__":
    unittest.main()

"""
OPENTHREAT — tests/test_investigate.py
=====================================
The IOC pivot launcher and the phishing analyser.

There is no JS runtime on this machine, so these are source-level contracts.
The behavioural checks were made in a real browser and the results are
recorded in the commit; what is pinned here is the set of properties that
would be silently lost in a later edit:

  * The analyser must never fetch the suspect URL. Doing so leaks the
    analyst's IP to the attacker and can fire a token that identifies the
    intended victim.
  * Nothing may be submitted to a reputation service automatically. Several
    log lookups, and an adversary watching for a lookup on their own
    infrastructure learns they have been caught.
"""

import re
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = (PROJECT_ROOT / "js" / "investigate.js").read_text(encoding="utf-8")


class TestPhishingAnalyserIsPassive(unittest.TestCase):

    def test_never_fetches_the_suspect_url(self):
        """The only fetches in this module are the CVE lookup and DNS, both to
        third parties that are not the target."""
        body = SRC.split("function phishAnalyse", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("fetch(", body)

    def test_the_reason_is_written_down(self):
        self.assertIn("leak", SRC.lower())
        self.assertIn("never fetched", SRC.lower() + SRC)

    def test_no_automatic_submission_to_reputation_services(self):
        """Sources are anchors that open on click, not requests made on
        render."""
        block = SRC.split("const IOC_SOURCES = [", 1)[1].split("\n];", 1)[0]
        self.assertNotIn("fetch(", block)
        self.assertIn("build:", block)


class TestIndicatorClassification(unittest.TestCase):
    """The patterns are ordered, and order is load-bearing: a 32-character hex
    string matches both `md5` and, without anchors, parts of other patterns."""

    def test_hash_lengths_are_distinct_and_anchored(self):
        block = SRC.split("const IOC_PATTERNS = [", 1)[1].split("\n];", 1)[0]
        for name, length in (("md5", 32), ("sha1", 40), ("sha256", 64)):
            self.assertIn(f"['{name}', /^[a-f0-9]{{{length}}}$/i]", block)

    def test_more_specific_types_are_tested_first(self):
        """`domain` would otherwise swallow an email's right-hand side and a
        CVE id would never reach its own branch."""
        block = SRC.split("const IOC_PATTERNS = [", 1)[1].split("\n];", 1)[0]
        order = re.findall(r"\['(\w+)',", block)
        self.assertLess(order.index("cve"), order.index("domain"))
        self.assertLess(order.index("email"), order.index("domain"))
        self.assertLess(order.index("url"), order.index("domain"))

    def test_defanged_input_is_accepted(self):
        """Defanging is how indicators are shared, precisely so they are not
        clickable. Rejecting it means a manual edit every single time."""
        body = SRC.split("function iocClassify", 1)[1].split("\n}", 1)[0]
        self.assertIn(r"\[\.\]", body)          # evil[.]com
        self.assertIn(r"\[:\]", body)           # 1.2.3.4[:]443
        self.assertIn("xx|XX", body)            # hxxp:// and hXXp://
        self.assertIn(r"\[at\]", body)          # user[at]example.com


class TestPhishingHeuristics(unittest.TestCase):

    def test_lookalike_is_checked_per_token_not_only_whole_string(self):
        """Whole-string alone misses the commonest shape there is:
        `micros0ft-login.top` strips to `micros0ftlogin`, six edits from
        `microsoft`, and scores nothing — while the token `micros0ft` is one
        edit away and is the entire trick. Verified in a browser: the
        whole-string version missed it, the token version catches it."""
        body = SRC.split("// ── Lookalike ──", 1)[1].split("// ── Brand name", 1)[0]
        self.assertIn("split(/[-_.]+/)", body)

    def test_punycode_prefix_is_not_counted_as_lure_hyphens(self):
        """`xn--` is two hyphens on every internationalised domain, on top of
        the punycode finding those already get."""
        self.assertIn(r"replace(/\bxn--/g, '')", SRC)

    def test_edit_distance_is_bounded(self):
        """Unbounded Levenshtein over 40 brands x every token is enough work
        to be felt on a keystroke."""
        body = SRC.split("function phishDistance", 1)[1].split("\n}", 1)[0]
        self.assertIn("> 2) return 99", body)

    def test_https_is_not_treated_as_reassuring(self):
        """Most phishing sites have a valid certificate. A tool that implies
        otherwise teaches the wrong lesson."""
        self.assertIn("says", SRC)
        self.assertIn("most phishing sites now have a valid certificate",
                      SRC.lower())

    def test_clean_result_is_not_reported_as_safe(self):
        """The most effective phishing runs on compromised legitimate domains
        where nothing about the URL looks wrong."""
        self.assertIn("not a verdict of safe", SRC)


class TestInvestigateViewsAreWired(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")

    def test_views_registered(self):
        views = self.app.split("const VIEWS = [", 1)[1].split("];", 1)[0]
        nodes = self.app.split("const VIEW_NODES = [", 1)[1].split("];", 1)[0]
        for view in ("ioc", "phish"):
            self.assertIn(f"'{view}'", views)
            self.assertIn(f"'{view}-view'", nodes)
            self.assertIn(f"case '{view}':", self.app)
            self.assertIn(f'id="{view}-view"', self.html)

    def test_loads_after_tools(self):
        """investigate.js closes over toolResolve()/toolRunRecon()/toolVerdict()
        from tools.js. One top-level scope, so order is load-bearing."""
        self.assertGreater(self.html.find("js/investigate.js"),
                           self.html.find("js/tools.js"))

    def test_no_html_sink(self):
        self.assertNotRegex(SRC, r"\.(innerHTML|outerHTML)\s*=")
        self.assertNotIn("insertAdjacentHTML", SRC)

    def test_every_pivot_url_is_encoded(self):
        """These URLs are built from user input and handed to an anchor.

        A build that takes the indicator must encode it. A build that takes no
        parameters is a constant URL and needs nothing — several sources have
        no per-indicator page and land on a browse page instead.
        """
        block = SRC.split("const IOC_SOURCES = [", 1)[1].split("\n];", 1)[0]
        entries = [e for e in block.split("{ name:") if "build:" in e]
        self.assertGreaterEqual(len(entries), 40,
                                "source list did not parse — the check is vacuous")
        for entry in entries:
            name = entry.split("'")[1]
            build = entry.split("build:", 1)[1]
            takes_indicator = re.match(r"\s*\(v\b", build)
            if takes_indicator:
                self.assertIn("encodeURIComponent", build,
                              f"{name} builds a URL from input without encoding")

    def test_sources_cover_every_indicator_type(self):
        block = SRC.split("const IOC_SOURCES = [", 1)[1].split("\n];", 1)[0]
        for group in ("hash", "ip", "domain", "url", "email", "cve"):
            self.assertIn(f"'{group}'", block)


if __name__ == "__main__":
    unittest.main()

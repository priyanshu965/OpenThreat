"""
OPENTHREAT — tests/test_tools.py
================================
The TOOLS mode: passive recon and credential utilities.

Everything on that page runs in the visitor's browser against third-party
APIs, which creates two failure modes that are invisible from the outside:

  * A fetch to an origin that is not in the CSP. The request is blocked by the
    browser, the panel shows an error, and nothing in CI notices — the same
    shape as the service-worker bug that rendered an unreachable feed as a
    quiet day.
  * A password generator with modulo bias. It produces plausible passwords
    with a quietly narrowed keyspace, and no output inspection reveals it.

Both are pinned here, from the source, because there is no JS runtime
available on this machine.
"""

import re
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

def js_origins(source: str) -> set:
    """Every external origin named anywhere in the frontend source.

    Deliberately NOT an attempt to work out which ones are fetched. The first
    version of this tried: it stripped comments with a regex, and the line-
    comment pattern ate the `//` inside a regex literal, silently mangling the
    code it was about to assert on. Parsing JavaScript with regular expressions
    to make a test smarter is a bad trade — a test that quietly analyses the
    wrong text is worse than one that over-reports.

    So it over-reports on purpose, and `LINK_ONLY_ORIGINS` below records the
    ones that are anchor targets rather than fetch targets. Anything new must
    land in the CSP or in that list, by hand, which is the decision that should
    be conscious anyway.
    """
    return set(re.findall(r"https://[a-z0-9.-]+\.[a-z]{2,}", source))


# Origins that appear only as <a href> targets. connect-src does not govern
# anchors, so these must NOT be added to the CSP just to make a test pass —
# that would widen the policy for no reason.
LINK_ONLY_ORIGINS = {
    "https://github.com",            # repo, discussions, advisories, policy
    "https://crt.sh",                # certificate history, opened in a tab
    "https://www.ssllabs.com",       # TLS analysis, opened in a tab
    "https://attack.mitre.org",
    "https://d3fend.mitre.org",
    "https://malpedia.caad.fkie.fraunhofer.de",
    "https://orkl.eu",
    "https://db-ip.com",
    "https://fonts.googleapis.com",  # stylesheet, governed by style-src
    "https://fonts.gstatic.com",     # font files, governed by font-src
    "https://t.me",
    "https://nvd.nist.gov",          # CVE detail pages (services.nvd is the API)
    "https://www.cve.org",           # CVE record pages
    "https://www.linkedin.com",      # about page
}


class TestCspCoversEveryFetch(unittest.TestCase):
    """The check that matters most: an origin the code calls but the policy
    does not allow fails only in a real browser."""

    @classmethod
    def setUpClass(cls):
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
        cls.js = "\n".join(
            (PROJECT_ROOT / "js" / name).read_text(encoding="utf-8")
            for name in ("tools.js", "community.js", "research.js", "library.js",
                         "hunt.js", "leaks.js", "query.js", "timetravel.js"))
        cls.js += (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        csp = re.search(r'content="(default-src[^"]*)"', cls.html).group(1)
        connect = [d for d in csp.split(";") if d.strip().startswith("connect-src")][0]
        cls.allowed = set(connect.split()[1:])

    def test_every_external_origin_is_accounted_for(self):
        """A fetch to an origin the CSP does not allow fails only in a real
        browser: blocked request, empty panel, green CI."""
        unknown = js_origins(self.js) - self.allowed - LINK_ONLY_ORIGINS
        self.assertEqual(unknown, set(),
                         f"origin is neither in connect-src nor recorded as "
                         f"link-only: {sorted(unknown)}")

    def test_the_check_is_not_vacuous(self):
        """If the extractor stops finding anything the test above passes while
        checking nothing — which is exactly how the view-parity guard in CI
        silently died once already."""
        self.assertGreaterEqual(len(js_origins(self.js)), 6)

    def test_no_model_api_in_connect_src(self):
        """Reaching a model API from a static page means shipping the key to
        every visitor. CI enforces this too; this is the local mirror."""
        for banned in ("generativelanguage", "api.openai", "api.groq",
                       "api.anthropic"):
            self.assertNotIn(banned, " ".join(self.allowed))

    def test_script_src_has_no_unsafe_inline(self):
        csp = re.search(r'content="(default-src[^"]*)"', self.html).group(1)
        script = [d for d in csp.split(";") if d.strip().startswith("script-src")][0]
        self.assertNotIn("unsafe-inline", script)

    def test_no_wildcard_in_connect_src(self):
        self.assertNotIn("*", " ".join(self.allowed))


class TestPasswordGenerator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = (PROJECT_ROOT / "js" / "tools.js").read_text(encoding="utf-8")

    def test_uses_a_csprng(self):
        self.assertIn("crypto.getRandomValues", self.src)
        # The panel's copy used to name Math.random in order to say it is not
        # used, which made this assertion match documentation rather than
        # code. The copy was reworded so the check stays honest.
        self.assertNotIn("Math.random", self.src)

    def test_rejection_sampling_not_plain_modulo(self):
        """`getRandomValues() % length` is biased: 256 does not divide most
        alphabet lengths, so early characters come up more often. A generator
        that quietly narrows its own keyspace is exactly what this project
        exists to point at."""
        body = self.src.split("function pwPick", 1)[1].split("\n}", 1)[0]
        self.assertIn("256 % alphabet.length", body)
        self.assertIn("< limit", body)

    def test_shuffle_is_also_unbiased(self):
        body = self.src.split("function pwRandomBelow", 1)[1].split("\n}", 1)[0]
        self.assertIn("4294967296 %", body)

    def test_every_selected_set_is_guaranteed_present(self):
        """'Include symbols' has to be a guarantee, not a probability."""
        body = self.src.split("function pwGenerate", 1)[1].split("\n}", 1)[0]
        self.assertIn("pools.map((pool) => pwPick(pool))", body)

    def test_ambiguous_characters_are_excluded(self):
        block = self.src.split("PW_ALPHABETS = {", 1)[1].split("};", 1)[0]
        self.assertNotIn("I", block.split("upper:")[1].split("'")[1])
        self.assertNotIn("0", block.split("digits:")[1].split("'")[1])


class TestBreachCheckIsKAnonymous(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = (PROJECT_ROOT / "js" / "tools.js").read_text(encoding="utf-8")

    def test_only_the_hash_prefix_is_sent(self):
        """The password must never leave the machine. That is a property of
        the protocol — five characters of the SHA-1 go out, the comparison
        happens locally — not a promise on the page."""
        body = self.src.split("async function pwCheckBreached", 1)[1].split("\n}", 1)[0]
        self.assertIn("hash.slice(0, 5)", body)
        self.assertIn("hash.slice(5)", body)
        # The request must carry the prefix ONLY.
        self.assertIn("PWNED_RANGE + prefix", body)
        self.assertNotIn("password)", body.split("fetch(")[1][:120])

    def test_no_email_breach_endpoint(self):
        """HIBP's per-account endpoint needs a paid key, and a key in a static
        page is a key every visitor can read. Absent, not built insecurely."""
        self.assertNotIn("breachedaccount", self.src)
        self.assertNotIn("hibp-api-key", self.src.lower())


class TestReconIsPassive(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = (PROJECT_ROOT / "js" / "tools.js").read_text(encoding="utf-8")

    def test_the_target_is_never_contacted(self):
        """Everything comes from a resolver or a registry. A fetch built from
        the user's input as an ORIGIN would make this an active scanner and
        change the project's legal posture."""
        self.assertNotIn("fetch('https://' + domain", self.src)
        self.assertNotIn("fetch(`https://${domain}", self.src)

    def test_hostname_is_validated_before_it_reaches_a_url(self):
        body = self.src.split("function toolHostname", 1)[1].split("\n}", 1)[0]
        self.assertIn("return ''", body)
        self.assertIn("{1,253}", body)

    def test_user_input_is_encoded_into_every_query(self):
        for call in re.findall(r"toolResolve\([^)]*\)", self.src):
            pass  # resolution is centralised; the encoding is asserted below
        body = self.src.split("async function toolResolve", 1)[1].split("\n}", 1)[0]
        self.assertIn("encodeURIComponent(name)", body)

    def test_rdap_degrades_instead_of_failing_opaquely(self):
        """A CSP applies to every hop of a redirect, so a TLD whose registry
        is not allowlisted cannot be queried at all. It gets a link."""
        self.assertIn("RDAP_KNOWN_TLDS", self.src)
        body = self.src.split("async function toolRenderRdap", 1)[1]
        self.assertIn("RDAP_KNOWN_TLDS.has(tld)", body)


class TestToolsFrontendHygiene(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = (PROJECT_ROOT / "js" / "tools.js").read_text(encoding="utf-8")
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")

    def test_no_html_sink(self):
        self.assertNotRegex(self.src, r"\.(innerHTML|outerHTML)\s*=")
        self.assertNotIn("insertAdjacentHTML", self.src)

    def test_third_party_values_go_through_text_content(self):
        self.assertIn("textContent", self.src)

    def test_tools_mode_is_registered(self):
        block = self.app.split("const MODE_VIEWS = {", 1)[1].split("\n};", 1)[0]
        self.assertIn("tools:", block)
        self.assertIn('data-mode="tools"', self.html)

    def test_both_views_are_fully_wired(self):
        views_list = self.app.split("const VIEWS = [", 1)[1].split("];", 1)[0]
        nodes = self.app.split("const VIEW_NODES = [", 1)[1].split("];", 1)[0]
        for view in ("recon", "creds"):
            self.assertIn(f"'{view}'", views_list)
            self.assertIn(f"'{view}-view'", nodes)
            self.assertIn(f"case '{view}':", self.app)
            self.assertIn(f'id="{view}-view"', self.html)

    def test_module_is_loaded_last(self):
        """tools.js closes over el/$/safeUrl/showToast from app.js."""
        self.assertGreater(self.html.find("js/tools.js"), self.html.find("app.js"))


if __name__ == "__main__":
    unittest.main()


class TestServiceWorkerPrecache(unittest.TestCase):
    """
    Every js/ module must be in PRECACHE.

    These are classic scripts sharing one top-level scope, not ES modules. A
    module missing from the precache is not a degraded offline experience — it
    is a ReferenceError the moment anything calls into it, and only offline, so
    nothing in normal testing sees it. Four modules were added in v6 and none
    of them landed in the list.
    """

    @classmethod
    def setUpClass(cls):
        cls.sw = (PROJECT_ROOT / "service-worker.js").read_text(encoding="utf-8")
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")

    def test_precache_matches_the_modules_index_html_loads(self):
        loaded = set(re.findall(r'src="(js/[a-z]+\.js)\?', self.html))
        block = self.sw.split("const PRECACHE = [", 1)[1].split("];", 1)[0]
        precached = {p.lstrip("./") for p in re.findall(r'"(\./js/[a-z]+\.js)"', block)}
        self.assertEqual(loaded - precached, set(),
                         "loaded by index.html but never precached")

    def test_the_check_is_not_vacuous(self):
        self.assertGreaterEqual(
            len(re.findall(r'src="js/[a-z]+\.js\?', self.html)), 8)

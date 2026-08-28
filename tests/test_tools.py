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


class TestFeedStalenessIsVisible(unittest.TestCase):
    """
    A stalled pipeline must not read as a quiet day.

    The feed age was already on screen and rendered identically at 20 minutes
    and at 11 hours, which is exactly how the scheduler failure went
    unnoticed: GitHub drops `schedule` events under load, the cadence decayed
    to one run in 11 hours, and the dashboard reported it in the same neutral
    voice it uses for fresh data.
    """

    @classmethod
    def setUpClass(cls):
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        cls.css = (PROJECT_ROOT / "style.css").read_text(encoding="utf-8")

    def test_staleness_is_computed_and_applied(self):
        self.assertIn("function markFeedStaleness", self.app)
        self.assertIn("FEED_STALE_HOURS", self.app)
        self.assertIn("FEED_VERY_STALE_HOURS", self.app)

    def test_it_is_called_when_the_header_is_painted(self):
        block = self.app.split("const updated = $('last-updated')", 1)[1][:600]
        self.assertIn("markFeedStaleness", block)

    def test_thresholds_allow_for_an_unreliable_scheduler(self):
        """The cron attempts twice an hour, so the warning must not fire on
        one unlucky dropped event."""
        body = self.app.split("const FEED_STALE_HOURS =", 1)[1][:60]
        self.assertGreaterEqual(int(body.split(";")[0].strip()), 2)

    def test_the_state_is_named_not_only_coloured(self):
        """Colour is not available to every reader, and 'stalled' is a
        different statement from 'quiet'."""
        self.assertIn("PIPELINE STALLED", self.app)
        self.assertIn("UPDATE OVERDUE", self.app)

    def test_styles_exist_for_both_levels(self):
        for cls in ("is-stale", "is-very-stale"):
            self.assertIn(f"#last-updated.{cls}", self.css)


class TestExternalTriggerIsDocumented(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import yaml
        path = PROJECT_ROOT / ".github" / "workflows" / "update.yml"
        cls.wf = path.read_text(encoding="utf-8")
        data = yaml.safe_load(cls.wf)
        # PyYAML reads the bare key `on` as the boolean True.
        cls.triggers = data.get("on") or data.get(True) or {}

    def test_workflow_dispatch_is_available_to_an_external_caller(self):
        self.assertIn("workflow_dispatch", self.triggers)

    def test_repository_dispatch_is_not_used(self):
        """It needs Contents: write on the PAT -- permission to push code --
        and that token lives at a third-party cron provider. workflow_dispatch
        needs only Actions: write.

        Asserted against the PARSED triggers, not the file text: the comment
        above the trigger explains why repository_dispatch was rejected, and
        the first version of this test matched that explanation and failed on
        its own documentation.
        """
        self.assertNotIn("repository_dispatch", self.triggers)

    def test_concurrent_triggers_queue_rather_than_race(self):
        block = self.wf.split("concurrency:", 1)[1][:200]
        self.assertIn("cancel-in-progress: false", block)


class TestTelemetryRail(unittest.TestCase):
    """
    The rail exists because the feed understated what the tool holds by about
    four orders of magnitude: nine cards on screen, while the same payload
    carried 8,889 entities, 2,876 rules and the status of 43 feeds.

    The constraints pinned here are the ones that keep it from becoming the
    sidebar that was correctly removed from this exact space.
    """

    @classmethod
    def setUpClass(cls):
        cls.js = (PROJECT_ROOT / "js" / "rail.js").read_text(encoding="utf-8")
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")
        cls.css = (PROJECT_ROOT / "style.css").read_text(encoding="utf-8")

    def test_costs_no_extra_request(self):
        """Every figure comes from store.meta, which arrived with the feed. A
        permanent rail is only affordable because of this."""
        self.assertNotIn("fetch(", self.js)

    def test_feed_view_only(self):
        """In LIBRARY or HUNT the content fills the width on its own, and a
        second column there is the old sidebar's mistake."""
        body = self.js.split("function renderRail", 1)[1]
        self.assertIn("store.view === 'feed'", body)

    def test_carries_no_controls(self):
        """Read-only. Every filter stays in the summoned panel.

        Checked by the ELEMENTS created, not by event names. The first
        version also banned addEventListener('change'), as a proxy for a
        checkbox handler — and then matched the matchMedia listener that
        moves blocks between the two gutters, which is layout code and not a
        control. A proxy that fires on unrelated code is a test that has to
        be argued with instead of trusted.
        """
        for element in ("'input'", "'select'", "'textarea'", "'button'"):
            self.assertNotIn(f"el({element}", self.js,
                             f"the rail creates a {element} — it must stay read-only")

    def test_the_control_check_is_not_vacuous(self):
        """It must be looking at code that really does create elements."""
        self.assertIn("el('section'", self.js)
        self.assertIn("el('span'", self.js)

    def test_hidden_below_1280(self):
        block = self.css.split("Telemetry rail", 1)[1]
        self.assertIn("min-width: 1280px", block)
        self.assertIn(".pulse-rail { display: none; }", block)

    def test_no_html_sink(self):
        self.assertNotRegex(self.js, r"\.(innerHTML|outerHTML)\s*=")
        self.assertNotIn("insertAdjacentHTML", self.js)

    def test_third_party_names_go_through_text_content(self):
        """A leak-site group name is attacker-supplied; a breach name comes
        from a third party."""
        body = self.js.split("function railTickerItem", 1)[1].split("\n}", 1)[0]
        self.assertNotIn("innerHTML", body)
        self.assertIn("el('span'", body)

    def test_ticker_stops_when_the_rail_leaves(self):
        """A timer that outlives the element it draws is a leak that only
        shows up later as a mystery."""
        self.assertIn("document.body.contains(stage)", self.js)
        body = self.js.split("function renderRail", 1)[1]
        self.assertIn("clearInterval(railTickerTimer)", body)

    def test_reduced_motion_renders_a_static_list(self):
        """Motion is the enhancement, not the mechanism — nothing may be
        unreachable without it."""
        self.assertIn("prefers-reduced-motion: reduce", self.js)
        self.assertIn("is-static", self.js)

    def test_the_timer_is_cleared_before_either_branch(self):
        """The static branch returns early; clearing inside the rotating
        branch would make cleanup a property of the environment."""
        block = self.js.split("function railRenderTicker", 1)[1]
        clear_at = block.find("clearInterval(railTickerTimer)")
        branch_at = block.find("if (reduced)")
        self.assertGreater(clear_at, 0)
        self.assertLess(clear_at, branch_at)

    def test_claims_are_labelled_as_claims(self):
        """A leak-site listing is the group's assertion, not a confirmed
        breach, and the page has to say so where it shows them."""
        self.assertIn("not a confirmed breach", self.js)

    def test_wired_into_the_render_loop_and_precached(self):
        self.assertIn("renderRail();", self.app)
        self.assertIn('id="pulse-rail"', self.html)
        self.assertIn("js/rail.js", self.html)
        sw = (PROJECT_ROOT / "service-worker.js").read_text(encoding="utf-8")
        self.assertIn("./js/rail.js", sw)


class TestRailPlacementIsCssOnly(unittest.TestCase):
    """
    Which gutter a block sits in is decided by CSS grid placement, not by
    JavaScript reading a media query.

    The first version branched in JS and re-rendered from a `resize`
    listener. It desynchronised: matchMedia reported false at 1450px while
    the DOM still carried the wide-layout class and the world blocks sat in a
    column CSS had already un-gridded. Instrumenting the page showed why —
    under viewport emulation NEITHER `resize` nor matchMedia `change` fires,
    so the re-render never ran.

    Real browsers fire both, so that code would probably have worked in
    production. "Probably, and untestable" is the objection: grid placement
    needs no event, cannot fall out of step with the query that drives it,
    and is verifiable at any width.
    """

    @classmethod
    def setUpClass(cls):
        cls.js = (PROJECT_ROOT / "js" / "rail.js").read_text(encoding="utf-8")
        cls.css = (PROJECT_ROOT / "style.css").read_text(encoding="utf-8")
        cls.html = (PROJECT_ROOT / "index.html").read_text(encoding="utf-8")

    def test_no_width_branching_in_js(self):
        for banned in ("matchMedia('(min-width", 'matchMedia("(min-width',
                       "innerWidth", "has-rail-right",
                       "addEventListener('resize'"):
            self.assertNotIn(banned, self.js,
                             f"rail.js decides layout with {banned}")

    def test_both_rails_exist_in_the_dom(self):
        self.assertIn('id="pulse-rail"', self.html)
        self.assertIn('id="pulse-rail-right"', self.html)

    def test_right_rail_is_after_the_feed_in_source_order(self):
        """Keyboard and screen-reader users reach the content before the
        ambient column, whichever side it is painted on."""
        self.assertGreater(self.html.find('id="pulse-rail-right"'),
                           self.html.find('<section class="feed"'))

    def test_css_places_both_rails_at_each_breakpoint(self):
        block = self.css.split("Second gutter, 1600px and up", 1)[1]
        self.assertIn("min-width: 1280px", block)
        self.assertIn("min-width: 1600px", block)
        # Two columns: the right rail is re-placed UNDER the left one rather
        # than being dropped for want of a third column.
        self.assertIn("#pulse-rail-right { grid-column: 1; grid-row: 2; }", block)
        self.assertIn("#pulse-rail-right { grid-column: 3; grid-row: 1; }", block)

    def test_stacked_rails_are_not_both_sticky(self):
        """Two independently sticky elements in one column slide over each
        other."""
        block = self.css.split("Second gutter, 1600px and up", 1)[1]
        self.assertIn("position: static", block.split("min-width: 1600px")[0])

    def test_the_world_blocks_always_render(self):
        """`right || left` — never conditional on width, so the content
        cannot be stranded in a hidden element."""
        body = self.js.split("function renderRail", 1)[1]
        self.assertIn("const world = right || left;", body)

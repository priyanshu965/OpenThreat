"""
OPENTHREAT — tests/test_workflows.py
====================================
The workflows are shell scripts embedded in YAML, and nothing type-checks
them. These are the failure modes that have actually happened here.

A LITERAL \\n INSIDE A run: BLOCK
---------------------------------
Editing these files with a tool that processes escape sequences turns a shell
line-continuation into the two characters backslash-n. YAML is happy, the
workflow parses, and bash then reads `\\n` as an ordinary word:

    for fn in ... showCredsView \\n    showKevView ...; do

iterates over a token `n`, and the loop body reports
"app.js calls n() but no js/ module defines it". The build fails with an
error message about a function nobody wrote, and the real function list is
never checked. That shipped, and CI caught it only after a push.

A GUARD THAT NO LONGER MATCHES ANYTHING
---------------------------------------
The view-parity check used to scrape `data-view=` out of index.html. When the
nav became generated from app.js the check found nothing and passed
vacuously, for weeks. Every guard here therefore has to prove it still
matches something.
"""

import re
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((PROJECT_ROOT / ".github" / "workflows").glob("*.yml"))


class TestWorkflowShellIsWellFormed(unittest.TestCase):

    def test_there_are_workflows_to_check(self):
        self.assertGreaterEqual(len(WORKFLOWS), 3)

    def test_no_literal_backslash_n_in_any_workflow(self):
        r"""A shell continuation that became the characters \n.

        Excluded: legitimate uses inside a quoted string, such as printf or a
        Python heredoc, where \n is meant literally. The signature of the bug
        is \n followed by run-on indentation rather than by a quote or a
        format specifier.
        """
        for path in WORKFLOWS:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\\n\s{2,}\S", line):
                    self.fail(f"{path.name}:{number} has a literal \\n where a "
                              f"line continuation was intended:\n  {line.strip()[:140]}")

    def test_continuations_are_at_end_of_line(self):
        """A backslash with trailing whitespace after it is not a continuation
        and silently ends the command."""
        for path in WORKFLOWS:
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\\[ \t]+$", line):
                    self.fail(f"{path.name}:{number} has trailing whitespace "
                              f"after a line continuation")


class TestCrossModuleGuardIsIntact(unittest.TestCase):
    """The guard's own function list, checked against reality here so a
    mangled workflow fails locally instead of on a push."""

    @classmethod
    def setUpClass(cls):
        cls.ci = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        cls.js = "\n".join(p.read_text(encoding="utf-8")
                           for p in sorted((PROJECT_ROOT / "js").glob("*.js")))
        cls.app = (PROJECT_ROOT / "app.js").read_text(encoding="utf-8")

    def _names(self, index):
        """The nth `for fn in ...; do` list. Splitting on the marker plus the
        first name would swallow that name — which it did, and the test then
        reported showGraphView as unchecked when the guard checks it first."""
        block = self.ci.split("for fn in ")[index].split("; do", 1)[0]
        return re.findall(
            r"\b(?:show|lib|hunt|render|enter|query|parse|safe|set|close|open"
            r"|empty|write|mode)\w+", block)

    def test_every_js_function_the_guard_names_exists(self):
        names = self._names(1)
        self.assertGreaterEqual(len(names), 25, "guard list did not parse")
        for name in names:
            self.assertRegex(self.js, rf"function {name}\b",
                             f"ci.yml checks for {name}() but no js/ module defines it")

    def test_every_app_function_the_guard_names_exists(self):
        names = self._names(2)
        self.assertGreaterEqual(len(names), 8, "guard list did not parse")
        for name in names:
            self.assertRegex(self.app, rf"function {name}\b",
                             f"ci.yml checks for {name}() but app.js does not define it")

    def test_the_guard_covers_every_view_function(self):
        """A view whose entry point is not in the guard is a view the guard
        cannot protect. This is what keeps the list honest as views are added."""
        defined = set(re.findall(r"function (show\w+View)\b", self.js))
        listed = set(self._names(1))
        missing = defined - listed
        self.assertEqual(missing, set(),
                         f"js/ defines these but ci.yml does not check them: "
                         f"{sorted(missing)}")




class TestScheduleIsNotOnTheHour(unittest.TestCase):
    """
    `schedule` is best-effort on a shared queue, and minute 0 is the most
    congested minute on the platform because it is every repository's default.

    Measured over 44 scheduled runs of update.yml with `cron: '0 */1 * * *'`:
    not one started on time. Earliest 11 minutes late, median 31, worst 51 --
    and when the delay exceeds the interval the event is DROPPED, not
    postponed. The observed cadence decayed from ~1.0h to 2.7h, 5h, 11h, 10h.
    The job runs in 1-6 minutes, so this was never duration or concurrency.

    This pins the mitigation so a later edit cannot quietly restore the
    default and reintroduce a 10-hour-stale dashboard.
    """

    @classmethod
    def setUpClass(cls):
        import yaml
        cls.crons = {}
        for path in WORKFLOWS:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            # PyYAML parses the bare key `on` as the boolean True.
            triggers = data.get("on") or data.get(True) or {}
            schedule = (triggers or {}).get("schedule") or []
            entries = [s.get("cron", "") for s in schedule if isinstance(s, dict)]
            if entries:
                cls.crons[path.name] = entries

    def test_there_is_a_schedule_to_check(self):
        self.assertIn("update.yml", self.crons)

    def test_no_schedule_fires_on_minute_zero(self):
        for name, entries in self.crons.items():
            for cron in entries:
                minute = cron.split()[0]
                self.assertNotIn("0", minute.split(","),
                                 f"{name}: cron '{cron}' fires at minute 0, the "
                                 f"most contended minute on the platform")
                self.assertNotEqual(minute, "*",
                                    f"{name}: cron '{cron}' fires every minute")

    def test_the_intel_update_has_a_spare_attempt_each_hour(self):
        """One attempt an hour means one dropped event is a missed hour."""
        entries = self.crons["update.yml"]
        minutes = [m for cron in entries for m in cron.split()[0].split(",")]
        self.assertGreaterEqual(len(minutes), 2,
                                "update.yml should attempt more than once an hour")


if __name__ == "__main__":
    unittest.main()

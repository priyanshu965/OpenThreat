"""
OPENTHREAT — atomics.py
========================
Atomic Red Team tests, indexed by ATT&CK technique.

A Sigma rule tells you what to look for. An atomic test tells you how to make
it happen on a lab box, which is the only honest way to find out whether your
detection actually fires. Shipping the rule without the test is shipping half a
hunt: every detection engineer has a folder of rules that have never once
matched anything and nobody knows whether that is good news.

Red Canary publishes the whole corpus as one index — ~1.4 MB of YAML covering
roughly 1,700 tests over 300-odd techniques — so this costs one weekly fetch.

SAFETY, EXPLICITLY
------------------
These are executable attack commands. This module INDEXES them and shows them
next to the technique they exercise; it never runs one, and the UI presents
them as a lab procedure with the prerequisites and the cleanup command
attached. Elevation requirements and destructive steps are surfaced rather than
buried, because the failure mode here is somebody pasting a command into the
wrong terminal.

YAML
----
PyYAML is used when present and the module degrades to "no atomics" when it is
not. The alternative — the tolerant regex parser sigma_rules.py uses — is fine
for Sigma's flat rule headers and would be genuinely unsafe here: atomic tests
carry multi-line block scalars full of shell and PowerShell, and a parser that
guesses at those would mangle commands that a human is then invited to run.
"""

from __future__ import annotations

from fetchlib import CONFIG, cached_derive, http_text, log, now_utc

_INDEX_URL = ("https://raw.githubusercontent.com/redcanaryco/atomic-red-team/"
              "master/atomics/Indexes/index.yaml")
_ATOMIC_BASE = "https://github.com/redcanaryco/atomic-red-team/blob/master/atomics"
_CACHE = "atomic_red_team.json"

# Commands whose whole point is destruction. Flagged, not removed: an atomic
# that encrypts a directory is a legitimate ransomware simulation and a lab
# needs it — but the reader should be told before they scroll past it.
_DESTRUCTIVE_HINTS = (
    "vssadmin delete", "shadowcopy delete", "cipher /w", "format ",
    "rm -rf /", "del /f /s /q c:", "bcdedit", "wevtutil cl", "clear-eventlog",
    "diskpart", "mkfs", "shutdown", "reg delete hklm",
)

_PLATFORM_LABELS = {
    "windows": "Windows", "linux": "Linux", "macos": "macOS", "office-365": "Office 365",
    "azure-ad": "Entra ID", "google-workspace": "Google Workspace", "iaas": "IaaS",
    "containers": "Containers", "iaas:aws": "AWS", "iaas:azure": "Azure",
    "iaas:gcp": "GCP",
}


def _yaml():
    try:
        import yaml  # noqa: PLC0415 - optional dependency, probed on purpose
        return yaml
    except ImportError:
        return None


def _clean(value, limit: int) -> str:
    return " ".join(str(value or "").split())[:limit]


def _is_destructive(test: dict) -> bool:
    blob = " ".join([
        str((test.get("executor") or {}).get("command") or ""),
        str((test.get("executor") or {}).get("cleanup_command") or ""),
    ]).lower()
    return any(hint in blob for hint in _DESTRUCTIVE_HINTS)


def _reduce_test(test: dict) -> dict | None:
    if not isinstance(test, dict):
        return None
    name = _clean(test.get("name"), 160)
    if not name:
        return None
    executor = test.get("executor") or {}
    if not isinstance(executor, dict):
        executor = {}
    command = str(executor.get("command") or "")
    if len(command) > 4000:
        command = command[:4000] + "\n# … truncated"

    platforms = [_PLATFORM_LABELS.get(str(p).lower(), str(p))
                 for p in (test.get("supported_platforms") or [])][:8]

    # input_arguments carry the placeholders a command needs (#{file_path});
    # without them the command is not runnable and the reader cannot tell why.
    args = []
    for key, spec in (test.get("input_arguments") or {}).items():
        if not isinstance(spec, dict):
            continue
        args.append({
            "name": str(key)[:60],
            "description": _clean(spec.get("description"), 160),
            "default": _clean(spec.get("default"), 200),
            "type": _clean(spec.get("type"), 20),
        })

    return {
        "name": name,
        "guid": _clean(test.get("auto_generated_guid"), 40),
        "description": _clean(test.get("description"), 700),
        "platforms": platforms,
        "executor": _clean(executor.get("name"), 40) or "manual",
        "elevation_required": bool(executor.get("elevation_required")),
        "command": command,
        "cleanup": str(executor.get("cleanup_command") or "")[:2000],
        "prereqs": [_clean((p or {}).get("description"), 200)
                    for p in (test.get("dependencies") or [])
                    if isinstance(p, dict)][:6],
        "destructive": _is_destructive(test),
        "arguments": args[:8],
    }


def _derive() -> dict | None:
    yaml = _yaml()
    if yaml is None:
        log.warning("  Atomic Red Team skipped: PyYAML is not installed")
        return None

    log.info("  Building Atomic Red Team index (1.4 MB, weekly)...")
    text, err = http_text(_INDEX_URL, timeout=max(90, CONFIG.request_timeout))
    if not text:
        log.warning(f"  Atomic Red Team index unavailable: {err}")
        return None

    try:
        raw = yaml.safe_load(text)
    except Exception as e:  # noqa: BLE001
        log.warning(f"  Atomic Red Team index did not parse: {e}")
        return None
    if not isinstance(raw, dict):
        return None

    # index.yaml is {tactic: {technique_id: {technique: {...}, atomic_tests: [...]}}}
    by_technique: dict[str, dict] = {}
    total_tests = 0
    for tactic, techniques in raw.items():
        if not isinstance(techniques, dict):
            continue
        for tid, block in techniques.items():
            if not isinstance(block, dict):
                continue
            tests = []
            for test in block.get("atomic_tests") or []:
                reduced = _reduce_test(test)
                if reduced:
                    tests.append(reduced)
            if not tests:
                continue
            total_tests += len(tests)
            technique_meta = block.get("technique") or {}
            existing = by_technique.get(tid)
            entry = {
                "technique": tid,
                "name": _clean(technique_meta.get("name"), 160),
                "tactics": [str(tactic)],
                "tests": tests,
                "url": f"{_ATOMIC_BASE}/{tid}/{tid}.md",
            }
            if existing:
                # A technique legitimately sits under several tactics.
                existing["tactics"] = sorted(set(existing["tactics"]) | {str(tactic)})
            else:
                by_technique[tid] = entry

    if not by_technique:
        return None

    destructive = sum(1 for e in by_technique.values()
                      for t in e["tests"] if t["destructive"])
    log.info(f"  Atomic Red Team: {total_tests} tests across {len(by_technique)} "
             f"techniques ({destructive} flagged destructive)")
    return {"built": now_utc(), "source": _INDEX_URL,
            "test_count": total_tests, "techniques": by_technique}


def load_atomics(force: bool = False) -> dict:
    """technique id -> {tests: [...]}. {} when disabled or PyYAML is missing."""
    if not CONFIG.enable_atomics:
        return {}
    ttl = 0 if force else CONFIG.atomics_ttl_hours
    data = cached_derive(_CACHE, ttl, _derive)
    return (data or {}).get("techniques", {})


def tests_for(technique_id: str, table: dict, limit: int = 4) -> list[dict]:
    """
    Atomic tests for a technique, falling back to the parent.

    Unlike the countermeasure lookups, this fallback is NOT free: a test for
    T1059 (Command and Scripting Interpreter) may exercise bash when you asked
    about T1059.001 (PowerShell). The inherited flag is set so the UI can say
    "these exercise the parent technique" rather than implying an exact match.
    """
    if not technique_id:
        return []
    entry = table.get(technique_id)
    if entry:
        return entry.get("tests", [])[:limit]
    if "." in technique_id:
        parent = technique_id.split(".")[0]
        parent_entry = table.get(parent)
        if parent_entry:
            return [dict(t, inherited=parent)
                    for t in parent_entry.get("tests", [])[:limit]]
    return []

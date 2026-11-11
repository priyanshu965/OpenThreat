"""
OPENTHREAT — ai_enrich.py
=======================
Model-written summaries and the daily brief, with the cross-run cache
that stops the same item being sent to a model every hour.

Moved out of fetch_intel.py unchanged; fetch_intel re-exports every name here,
so `fetch_intel._ENRICH_ITEM_SCHEMA` and the like keep working.
"""

import hashlib
import json
import os
import time


from fetchlib import (
    CONFIG,
    log,
    SESSION as _SESSION,
    cache_path as _cache_path,
)
from classify import infer_category, infer_severity, valid_cve_id
from dedup import item_key
from feedutil import now_utc

AI_BATCH_SIZE = CONFIG.ai_batch_size
AI_ENRICH_LIMIT = CONFIG.ai_enrich_limit
GEMINI_API_KEY = CONFIG.gemini_api_key
GEMINI_MODEL = CONFIG.gemini_model
GROQ_API_KEY = CONFIG.groq_api_key
GROQ_MODEL_FALLBACK = CONFIG.groq_model_fallback
GROQ_MODEL_PRIMARY = CONFIG.groq_model_primary
REQUEST_TIMEOUT = CONFIG.request_timeout


# ── AI Enrichment ─────────────────────────────────────────────────────────────
# Design notes (this replaced a per-item, sequential, free-text-JSON design):
#
#  * BATCHED. One request carries AI_BATCH_SIZE items and returns an array.
#    The old loop made one call per item with an unconditional sleep between
#    them: ~90s to enrich 10 items. This does ~40 items in a handful of calls,
#    which is what makes AI_ENRICH_LIMIT=40 affordable on a free tier.
#
#  * SCHEMA-CONSTRAINED. The model is given a JSON schema and cannot emit
#    invalid JSON, which deleted a 60-line four-stage "repair the LLM's JSON"
#    recovery ladder (strip fences -> fix trailing commas -> balance braces ->
#    regex-salvage). One try/except is now enough.
#
#  * DIFFERENT JOB. We no longer ask the model to re-summarise a description we
#    already have, or to draw a boilerplate attack diagram. We ask for the two
#    things a model is actually good at and regex is not:
#       - affected vendor/product extraction (feeds "My Stack" matching)
#       - a one-line "why this matters / who should act" judgement

_ENRICH_ITEM_SCHEMA = {
    "type": "object",
    "properties": {
        "index":       {"type": "integer", "description": "The item index given in the prompt"},
        "summary":     {"type": "string",  "description": "3-4 sentence technical analysis: mechanism, affected versions, impact, remediation"},
        "why_it_matters": {"type": "string", "description": "One sentence: who should act and how urgently"},
        "vendors":     {"type": "array", "items": {"type": "string"}, "description": "Affected vendor names, lowercase"},
        "products":    {"type": "array", "items": {"type": "string"}, "description": "Affected product names, lowercase"},
        "confidence":  {"type": "number", "description": "0.0-1.0 confidence in this analysis"},
    },
    "required": ["index", "summary", "why_it_matters", "vendors", "products", "confidence"],
}

_ENRICH_BATCH_SCHEMA = {
    "type": "object",
    "properties": {"results": {"type": "array", "items": _ENRICH_ITEM_SCHEMA}},
    "required": ["results"],
}

_BRIEF_SCHEMA = {
    "type": "object",
    "properties": {
        "headline": {"type": "string", "description": "One sentence summarising today's threat landscape"},
        "top_items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index":  {"type": "integer"},
                    "reason": {"type": "string", "description": "Why this one matters today, one sentence"},
                },
                "required": ["index", "reason"],
            },
        },
    },
    "required": ["headline", "top_items"],
}


def build_batch_prompt(items: list[dict]) -> str:
    """One prompt covering a batch of items. Indices are how results map back."""
    lines = [
        "You are a senior threat intelligence analyst. Analyse each numbered "
        "threat item below and return one result object per item.",
        "",
        "Rules:",
        "- summary: 3-4 sentences. Technical and specific. Mechanism, affected "
        "versions, real impact, concrete remediation. Do not pad.",
        "- why_it_matters: ONE sentence naming who should act and how fast.",
        "- vendors/products: lowercase names extracted from the text (e.g. "
        '"fortinet", "fortios"). Empty arrays if none are identifiable. Do not guess.',
        "- confidence: 0.0-1.0. Be honest; low confidence on thin source text.",
        "",
        "ITEMS:",
    ]
    for idx, item in enumerate(items):
        ttps = ", ".join(f"{t['id']}" for t in (item.get("ttps") or [])[:6]) or "none"
        lines.append(
            f"\n[{idx}] title: {(item.get('title') or '')[:220]}"
            f"\n    description: {(item.get('description') or '')[:600]}"
            f"\n    cve: {item.get('cve_id') or 'N/A'} | cvss: {item.get('cvss_score') or 'N/A'}"
            f" | kev: {bool(item.get('cisa_kev'))} | poc: {bool(item.get('has_poc'))}"
            f"\n    ttps: {ttps}"
        )
    return "\n".join(lines)


def _call_gemini_json(prompt: str, schema: dict, model: str | None = None) -> dict | None:
    """Structured-output Gemini call. Returns a parsed dict or None.

    Tries the current `google-genai` SDK first and falls back to the legacy
    `google-generativeai` package so this keeps working during migration.
    """
    if not GEMINI_API_KEY:
        return None
    model = model or GEMINI_MODEL

    # Preferred: google-genai (current SDK).
    try:
        from google import genai  # type: ignore
        client = genai.Client(api_key=GEMINI_API_KEY)
        resp = client.models.generate_content(
            model=model,
            contents=prompt,
            config={"response_mime_type": "application/json", "response_schema": schema},
        )
        return json.loads(resp.text)
    except ImportError:
        pass
    except Exception as e:
        log.warning(f"Gemini ({model}) structured call failed: {e}")
        return None

    # Fallback: legacy google-generativeai.
    try:
        import google.generativeai as genai_legacy  # type: ignore
        genai_legacy.configure(api_key=GEMINI_API_KEY)
        gm = genai_legacy.GenerativeModel(model)
        resp = gm.generate_content(
            prompt,
            generation_config={"response_mime_type": "application/json",
                               "response_schema": schema},
        )
        return json.loads(resp.text)
    except Exception as e:
        log.warning(f"Gemini legacy ({model}) call failed: {e}")
        return None


_GROQ_SHAPE = (
    'Reply with a single JSON object and nothing else, in exactly this form: '
    '{"results": [{"index": 0, "summary": "...", "why_it_matters": "...", '
    '"vendors": ["..."], "products": ["..."], "confidence": 0.0}]} '
    'with one entry per numbered item, "index" being the item\'s number.'
)


def batch_results(parsed) -> list[dict]:
    """The per-item results in a model reply, whatever shape it came back in.

    A model that ignores the requested layout must cost its own batch, not
    the run: one reply shaped as a bare list used to raise out of
    enrich_with_ai and discard every batch after it.
    """
    if isinstance(parsed, dict):
        parsed = parsed.get("results")
    if not isinstance(parsed, list):
        return []
    return [r for r in parsed if isinstance(r, dict)]


def _call_groq_json(prompt: str) -> dict | None:
    """Groq fallback. Groq's free tier is small (100-2,000 req/day), so this is
    a failover for a handful of calls, not a primary path."""
    if not GROQ_API_KEY:
        return None
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    for model in (GROQ_MODEL_PRIMARY, GROQ_MODEL_FALLBACK):
        try:
            resp = _SESSION.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers, timeout=REQUEST_TIMEOUT,
                json={"model": model,
                      # Gemini is handed a schema; Groq's JSON mode has only
                      # the prompt to go on. Without the shape spelled out it
                      # is refused outright (the word "json" must appear), and
                      # with only "reply in JSON" it invents its own layout.
                      "messages": [
                          {"role": "system", "content": _GROQ_SHAPE},
                          {"role": "user", "content": prompt}],
                      "temperature": 0.1, "max_tokens": 4000,
                      "response_format": {"type": "json_object"}})
            if resp.status_code == 429:
                log.warning(f"Groq rate limited on {model}")
                continue
            if resp.status_code >= 400:
                # The status alone explains nothing. A retired model is a 404
                # and a request the model rejects is a 400 whose reason is in
                # the body, so log the body - and on a 404, the ids this key
                # CAN use, which turns "summaries stopped" into a one-line fix.
                detail = " ".join(resp.text.split())[:300]
                log.warning(f"Groq error ({model}): HTTP {resp.status_code} {detail}")
                if resp.status_code == 404:
                    _log_groq_models(headers)
                continue
            return json.loads(resp.json()["choices"][0]["message"]["content"])
        except Exception as e:
            log.warning(f"Groq error ({model}): {e}")
    return None


_GROQ_MODELS_LOGGED = False


def _log_groq_models(headers: dict) -> None:
    """Log the model ids available to this key, once per run."""
    global _GROQ_MODELS_LOGGED
    if _GROQ_MODELS_LOGGED:
        return
    _GROQ_MODELS_LOGGED = True
    try:
        resp = _SESSION.get("https://api.groq.com/openai/v1/models",
                            headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        ids = sorted(str(m.get("id")) for m in resp.json().get("data", []))
        log.warning(f"Groq models available to this key: {', '.join(ids)[:1500]}")
    except Exception as e:
        log.warning(f"Could not list Groq models: {e}")


def apply_enrichment(item: dict, result: dict) -> None:
    """Write one model result onto an item."""
    summary = str(result.get("summary", "")).strip()
    if summary:
        item["ai_summary"] = summary[:1200]
    why = str(result.get("why_it_matters", "")).strip()
    if why:
        item["why_it_matters"] = why[:400]

    # Lists only. A model that answers "fortinet" instead of ["fortinet"] would
    # otherwise be iterated a character at a time into eight one-letter vendors.
    def _names(value) -> list[str]:
        return [str(v).strip().lower() for v in value if str(v).strip()] \
            if isinstance(value, list) else []

    vendors, products = _names(result.get("vendors")), _names(result.get("products"))
    if vendors:
        item["vendors"] = sorted(set(vendors))[:8]
    if products:
        item["products"] = sorted(set(products))[:8]

    try:
        item["ai_confidence"] = round(max(0.0, min(1.0, float(result.get("confidence", 0.5)))), 2)
    except (TypeError, ValueError):
        item["ai_confidence"] = 0.5


def rule_based_enrich(item: dict) -> None:
    """Zero-cost defaults for every item.

    Deliberately does NOT set `ai_summary`: 246 of 248 rule summaries were a
    prefix of `description`, which is already in the same JSON object, so
    shipping both wasted 58 KB per payload for zero information. The frontend
    derives a display summary from `description` when `ai_summary` is absent.
    """
    text = f"{item.get('title', '')} {item.get('description', '')}"
    item["severity"]    = infer_severity(text, item.get("severity") or "medium")
    item["category"]    = infer_category(text, item.get("category") or "news")
    item["ai_provider"] = "rule"


# ── Cross-run enrichment cache ────────────────────────────────────────────────
# A model result is a property of the ITEM, not of the run. The feed turns over
# slowly — most of what ranks in the top N this hour ranked there last hour too
# — so without a cache the same items were re-sent to Gemini on all 24 daily
# runs. Keyed by item_key() (CVE, else canonical URL, else title fingerprint),
# which is the same identity mark_new_since_last() diffs on.

_AI_CACHE_NAME = "ai_enrich.json"
_AI_CACHE_FIELDS = ("ai_summary", "why_it_matters", "vendors", "products",
                    "ai_confidence", "ai_provider", "ai_model")


def _load_ai_cache() -> dict:
    """Cached enrichments, with expired entries dropped."""
    path = _cache_path(_AI_CACHE_NAME)
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning(f"AI cache unreadable, starting fresh: {e}")
        return {}
    if not isinstance(raw, dict):
        return {}
    cutoff = time.time() - CONFIG.ai_cache_ttl_days * 86400
    return {k: v for k, v in raw.items()
            if isinstance(v, dict) and float(v.get("cached_at") or 0) >= cutoff}


def _save_ai_cache(cache: dict) -> None:
    """Atomically persist the cache, newest entries first, size-capped."""
    if not cache:
        return
    entries = sorted(cache.items(), key=lambda kv: -float(kv[1].get("cached_at") or 0))
    trimmed = dict(entries[:CONFIG.ai_cache_max_entries])
    try:
        path = _cache_path(_AI_CACHE_NAME)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps(trimmed, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
    except Exception as e:
        log.warning(f"Could not write AI cache: {e}")


def _cache_enrichment(cache: dict, item: dict) -> None:
    entry = {f: item[f] for f in _AI_CACHE_FIELDS if item.get(f) is not None}
    if entry.get("ai_provider") in (None, "rule"):
        return                      # nothing a model produced; not worth storing
    entry["cached_at"] = time.time()
    cache[item_key(item)] = entry


def _apply_cached_enrichment(item: dict, entry: dict) -> bool:
    """Replay a cached model result onto an item. True if anything was applied."""
    applied = False
    for field in _AI_CACHE_FIELDS:
        if entry.get(field) is not None:
            item[field] = entry[field]
            applied = True
    return applied


_UNSCORED_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def select_enrichment_candidates(items: list[dict]) -> list[dict]:
    """Pick which items get a model call.

    Two budgets, because ranking everything by ``priority_score`` sent the
    whole allowance to CVEs — the items that need a model least, since they
    already carry CVSS, EPSS, KEV and SSVC. Incidents and news carry none of
    that structure and never got enriched at all.
    """
    scored   = [i for i in items if i.get("priority_score") is not None]
    unscored = [i for i in items if i.get("priority_score") is None]

    scored.sort(key=lambda i: i.get("priority_score") or 0, reverse=True)
    unscored.sort(key=lambda i: (_UNSCORED_SEVERITY_RANK.get(i.get("severity"), 0),
                                 i.get("published") or ""), reverse=True)

    return (scored[:AI_ENRICH_LIMIT]
            + unscored[:CONFIG.ai_enrich_unscored_limit])


def enrich_with_ai(items: list[dict]) -> list[dict]:
    """Rule-based defaults for everything, cached results where we have them,
    then batched model calls for whatever is left in budget."""
    for item in items:
        rule_based_enrich(item)
    log.info(f"Rule-based defaults applied to {len(items)} items")

    if not GEMINI_API_KEY and not GROQ_API_KEY:
        log.info("No AI keys set — skipping AI enrichment")
        return items

    cache = _load_ai_cache()
    reused = 0
    for item in items:
        entry = cache.get(item_key(item))
        if entry and _apply_cached_enrichment(item, entry):
            reused += 1
    if reused:
        log.info(f"AI cache: reused {reused} enrichment(s), {len(cache)} entries on disk")

    # Only spend calls on items the cache could not answer.
    to_enrich = [i for i in select_enrichment_candidates(items)
                 if i.get("ai_provider") in (None, "rule")]
    if not to_enrich:
        log.info("AI enrichment: nothing new to enrich this run")
        _save_ai_cache(cache)
        return items

    batches = [to_enrich[i:i + AI_BATCH_SIZE] for i in range(0, len(to_enrich), AI_BATCH_SIZE)]
    log.info(f"AI enrichment: {len(to_enrich)} items in {len(batches)} batch(es) of <= {AI_BATCH_SIZE}")

    enriched = 0
    for bnum, batch in enumerate(batches, 1):
        prompt = build_batch_prompt(batch)
        parsed = _call_gemini_json(prompt, _ENRICH_BATCH_SCHEMA)
        provider, model = "gemini", GEMINI_MODEL
        if not parsed:
            parsed = _call_groq_json(prompt)
            provider, model = "groq", GROQ_MODEL_PRIMARY
        if not parsed:
            log.warning(f"  batch {bnum}/{len(batches)}: no AI result, keeping rule defaults")
            continue

        results = batch_results(parsed)
        for result in results:
            try:
                idx = int(result.get("index", -1))
            except (TypeError, ValueError):
                continue
            if not (0 <= idx < len(batch)):
                continue
            item = batch[idx]
            apply_enrichment(item, result)
            item["ai_provider"] = provider
            item["ai_model"] = model
            _cache_enrichment(cache, item)
            enriched += 1
        log.info(f"  batch {bnum}/{len(batches)}: {len(results)} results ({provider})")

    _save_ai_cache(cache)
    log.info(f"AI enrichment complete: {enriched} new, {reused} from cache")
    return items


def build_daily_brief(items: list[dict]) -> dict | None:
    """One call per run: 'of these N items, which few actually matter today?'

    This is the highest-value use of a model in the pipeline — a judgement over
    the whole feed, which is exactly what no amount of regex can produce.
    """
    if not CONFIG.enable_ai_brief or not GEMINI_API_KEY:
        return None

    ranked = sorted(items, key=lambda i: i.get("priority_score") or 0, reverse=True)[:40]
    if not ranked:
        return None

    # Reuse the last brief unless it has aged out or the urgent picture moved.
    # Regenerating hourly cost 24 calls a day to answer the same question with
    # the same inputs; keying on the urgent set means a new KEV entry still
    # forces a fresh brief within the hour.
    signature = _brief_signature(items)
    cached = _load_cached_brief()
    if cached and cached.get("signature") == signature:
        age_h = (time.time() - float(cached.get("cached_at") or 0)) / 3600.0
        if age_h < CONFIG.brief_max_age_hours:
            log.info(f"Daily brief: reusing cached brief ({age_h:.1f}h old, urgent set unchanged)")
            return cached["brief"]

    lines = ["Below are today's top threat-intel items. Pick the 3-5 that a "
             "defender should act on FIRST and say why in one sentence each. "
             "Prefer confirmed exploitation, public PoC, and wide blast radius "
             "over interesting-but-theoretical. Also write a single headline "
             "sentence summarising the day.", "", "ITEMS:"]
    for idx, item in enumerate(ranked):
        lines.append(
            f"[{idx}] {(item.get('title') or '')[:180]} "
            f"(src={item.get('source')}, sev={item.get('severity')}, "
            f"P={item.get('priority_score')}, kev={bool(item.get('cisa_kev'))}, "
            f"poc={bool(item.get('has_poc'))}, ssvc={item.get('ssvc_exploitation') or 'n/a'})")

    parsed = _call_gemini_json("\n".join(lines), _BRIEF_SCHEMA, model=CONFIG.gemini_brief_model)
    if not parsed:
        return None

    picks = []
    for entry in parsed.get("top_items", [])[:5]:
        try:
            idx = int(entry.get("index", -1))
        except (TypeError, ValueError):
            continue
        if 0 <= idx < len(ranked):
            item = ranked[idx]
            picks.append({
                "title":  item.get("title"),
                "url":    item.get("url"),
                "cve_id": valid_cve_id(item.get("cve_id")),
                "key":    item_key(item),
                "reason": str(entry.get("reason", ""))[:300],
            })
    if not picks:
        return None
    brief = {"headline": str(parsed.get("headline", ""))[:300],
             "items": picks,
             "model": CONFIG.gemini_brief_model,
             "generated": now_utc()}
    _save_cached_brief(brief, signature)
    return brief


_BRIEF_CACHE_NAME = "daily_brief.json"


def _brief_signature(items: list[dict]) -> str:
    """Identity of the current urgent picture. Changes only when the set of
    items a defender must act on changes — which is exactly when the brief
    needs rewriting."""
    urgent = sorted(item_key(i) for i in items
                    if i.get("priority_label") in ("urgent", "elevated"))
    return hashlib.sha256("|".join(urgent).encode("utf-8")).hexdigest()[:32]


def _load_cached_brief() -> dict | None:
    path = _cache_path(_BRIEF_CACHE_NAME)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) and data.get("brief") else None
    except Exception:
        return None


def _save_cached_brief(brief: dict, signature: str) -> None:
    try:
        path = _cache_path(_BRIEF_CACHE_NAME)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"brief": brief, "signature": signature,
                                   "cached_at": time.time()}, ensure_ascii=False),
                       encoding="utf-8")
        tmp.replace(path)
    except Exception as e:
        log.warning(f"Could not cache daily brief: {e}")

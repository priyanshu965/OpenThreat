"""
OPENTHREAT — scoring.py
=====================
The priority score: how urgently an item needs acting on, and why.

Moved out of fetch_intel.py unchanged; fetch_intel re-exports every name here,
so `fetch_intel.cvss_to_severity` and the like keep working.
"""



from fetchlib import (
    CONFIG,
)


# ── Intel Inference Helpers ───────────────────────────────────────────────────

def cvss_to_severity(score) -> str:
    if score is None: return "medium"
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"

# ── CVE Prioritization Score ──────────────────────────────────────────────────

# SSVC (CISA Vulnrichment) contributions to the blended score.
_SSVC_EXPLOITATION_WEIGHT = {"active": 1.0, "poc": 0.45, "none": 0.0}

# Score -> what a defender should actually do. This is the point of the whole
# pipeline: a decision, not a number.
_ACTION_BY_LABEL = {
    "urgent":   ("Patch now",        "Confirmed exploitation or trivially weaponisable — act within 24h"),
    "elevated": ("Patch this week",  "Exploitation is plausible and impact is high"),
    "moderate": ("Next patch cycle", "Worth scheduling, not worth paging anyone"),
    "low":      ("Monitor",          "Track it; no action required today"),
}


def compute_priority(item: dict) -> dict | None:
    """
    Blend CVSS (impact), EPSS (probability), CISA KEV (confirmed exploitation),
    public PoC availability and SSVC decision points into one 0-100 "act on
    this first" score, plus a plain-language action.

        score = cvss_weight * (cvss/10)
              + epss_weight * epss
              + ssvc_active_bonus * exploitation_weight
              + ssvc_auto_bonus     (if Automatable)
              + ssvc_total_bonus    (if Technical Impact == total)
              + poc_bonus / kev_bonus

    KEV and SSVC-active items are floored at 90 — something confirmed to be
    exploited in the wild should sort to the top regardless of its CVSS.
    """
    cvss = item.get("cvss_score")
    epss = item.get("epss_score")
    kev  = bool(item.get("cisa_kev"))
    poc  = bool(item.get("has_poc"))
    exploitation = (item.get("ssvc_exploitation") or "").lower()
    automatable  = (item.get("ssvc_automatable") or "").lower() == "yes"
    total_impact = (item.get("ssvc_technical_impact") or "").lower() == "total"

    if cvss is None and epss is None and not kev and not poc and not exploitation:
        return None

    try:
        cvss_val = max(0.0, min(10.0, float(cvss))) if cvss is not None else 0.0
    except (TypeError, ValueError):
        cvss_val = 0.0
    try:
        epss_val = max(0.0, min(1.0, float(epss))) if epss is not None else 0.0
    except (TypeError, ValueError):
        epss_val = 0.0

    # Every term is recorded as it is added. The dashboard lets a reader click
    # the score open and see the arithmetic, and reconstructing it in
    # JavaScript from the weights would be a second implementation of this
    # function that could drift from it silently.
    components: list[dict] = []

    def _add(label: str, points: float, detail: str = "") -> None:
        if points:
            components.append({"label": label, "points": round(points, 1),
                               "detail": detail})

    cvss_points = CONFIG.priority_cvss_weight * (cvss_val / 10.0)
    epss_points = CONFIG.priority_epss_weight * epss_val
    score = cvss_points + epss_points
    if cvss is not None:
        _add("Impact (CVSS)", cvss_points,
             f"{cvss_val:.1f}/10 x {CONFIG.priority_cvss_weight:g} weight")
    if epss is not None:
        _add("Exploit probability (EPSS)", epss_points,
             f"{epss_val * 100:.1f}% x {CONFIG.priority_epss_weight:g} weight")

    if exploitation in _SSVC_EXPLOITATION_WEIGHT:
        bonus = CONFIG.priority_ssvc_active_bonus * _SSVC_EXPLOITATION_WEIGHT[exploitation]
        score += bonus
        _add(f"SSVC exploitation: {exploitation}", bonus,
             f"{CONFIG.priority_ssvc_active_bonus:g} x "
             f"{_SSVC_EXPLOITATION_WEIGHT[exploitation]:g}")
    if automatable:
        score += CONFIG.priority_ssvc_auto_bonus
        _add("SSVC automatable", CONFIG.priority_ssvc_auto_bonus,
             "exploitable at scale, unattended")
    if total_impact:
        score += CONFIG.priority_ssvc_total_bonus
        _add("SSVC total technical impact", CONFIG.priority_ssvc_total_bonus)
    if item.get("epss_rising"):
        score += CONFIG.priority_epss_rising_bonus
        _add("EPSS rising", CONFIG.priority_epss_rising_bonus,
             f"up {float(item.get('epss_delta') or 0) * 100:.1f} points in "
             f"{CONFIG.epss_trend_days} days")
    if poc:
        # Bonus only — no floor. Flooring every PoC item at 70 pushed it into
        # "Patch this week" regardless of impact, and PoC-in-GitHub indexes a
        # lot of empty or scaffold repos. It also flattened the ordering: every
        # low-CVSS item with a PoC tied at exactly the same score, so the list
        # stopped ranking. A PoC raises urgency; it does not by itself make a
        # CVSS 3.1 information leak a weekly-patch item.
        score += CONFIG.priority_poc_bonus
        _add("Public PoC on GitHub", CONFIG.priority_poc_bonus,
             "raises urgency; deliberately does not floor the score")
    if kev or exploitation == "active":
        score += CONFIG.priority_kev_bonus
        _add("CISA KEV listing" if kev else "Active exploitation (SSVC)",
             CONFIG.priority_kev_bonus, "confirmed exploitation in the wild")
        if score < 90.0:
            components.append({
                "label": "Confirmed-exploitation floor", "points": round(90.0 - score, 1),
                "detail": "a CVSS 6.5 exploited today outranks a theoretical 9.8",
            })
            score = 90.0

    raw_total = score
    score = round(max(0.0, min(100.0, score)), 1)
    if raw_total > 100.0:
        components.append({"label": "Capped at 100",
                           "points": round(100.0 - raw_total, 1),
                           "detail": f"raw total was {raw_total:.1f}"})

    if score >= 90:   label = "urgent"
    elif score >= 70: label = "elevated"
    elif score >= 40: label = "moderate"
    else:             label = "low"

    reasons = []
    if kev:
        reasons.append("CISA KEV (actively exploited)")
    if exploitation == "active" and not kev:
        reasons.append("SSVC: active exploitation")
    elif exploitation == "poc":
        reasons.append("SSVC: public PoC")
    if automatable:
        reasons.append("SSVC: automatable")
    if total_impact:
        reasons.append("SSVC: total impact")
    if poc:
        reasons.append("Public PoC on GitHub")
    if item.get("epss_rising"):
        reasons.append("EPSS rising")
    if epss is not None:
        reasons.append(f"EPSS {epss_val * 100:.1f}%")
    if cvss is not None:
        reasons.append(f"CVSS {cvss_val:.1f}")

    action, action_detail = _ACTION_BY_LABEL[label]
    return {"score": score, "label": label, "rationale": " · ".join(reasons),
            "action": action, "action_detail": action_detail,
            "components": components}

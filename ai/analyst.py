"""
AI analyst — turns the engine's structured findings into exploitation guidance.

Everything here is GROUNDED in the deterministic engine's own output (the finding
dict, the app metadata, the endpoint map). The model is told to use only that
data, to stay in an authorized-testing frame, and to say when something can't be
determined statically — so it augments the report without inventing facts.
"""

import json

from . import provider as P
from .config import load_config

_SYSTEM = (
    "You are a senior mobile application penetration tester assisting with an "
    "AUTHORIZED assessment (the operator has scope/permission). You are given "
    "structured static-analysis output from a tool called ShieldScope. Produce "
    "precise, practical, defensive-and-offensive guidance for a professional "
    "tester. Rules: use ONLY the facts provided; never invent endpoints, keys, "
    "class names, or values; when something cannot be confirmed by static "
    "analysis, say so and give the dynamic test that would confirm it. Prefer "
    "concrete commands (adb, frida, curl, Burp steps) using the real package "
    "name / values provided. Keep it tight and skimmable with short headers."
)


def _slim_finding(f):
    keep = ("id", "title", "severity", "category", "location", "evidence",
            "description", "risk", "reproduce", "mitigation", "masvs", "name",
            "why", "tests", "payload", "tool", "value", "category_name")
    return {k: f[k] for k in keep if k in f}


def _app_ctx(meta):
    meta = meta or {}
    return {k: meta.get(k) for k in ("package", "bundle_id", "version_name",
                                     "version", "min_sdk", "target_sdk") if meta.get(k)}


def analyze_finding(finding, app_meta=None, cfg=None):
    """Return {ok, markdown} with exploit/PoC/risk/mitigation for one finding."""
    cfg = cfg or load_config()
    if not cfg.enabled:
        return {"ok": False, "enabled": False, "error": "AI disabled"}
    prompt = (
        "APP CONTEXT:\n" + json.dumps(_app_ctx(app_meta), indent=1) +
        "\n\nFINDING:\n" + json.dumps(_slim_finding(finding), indent=1) +
        "\n\nWrite, in markdown with these sections:\n"
        "### What this is\n### How to exploit (step by step)\n"
        "### Proof-of-concept (concrete commands / payloads)\n"
        "### Impact / risk\n### How to reproduce\n### Remediation\n"
        "Be specific to THIS finding and app. If the finding is a lead that needs "
        "dynamic confirmation, say exactly what to run to confirm."
    )
    try:
        md = P.chat(_SYSTEM, prompt, cfg=cfg, max_tokens=1600)
        return {"ok": True, "markdown": md, "provider": cfg.provider, "model": cfg.model}
    except P.AIError as e:
        return {"ok": False, "enabled": True, "error": str(e)}


def _plan_context(result):
    """A compact summary of the whole result for the planner (token-bounded)."""
    extra = result.get("extra", []) or []
    sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings = sorted(
        ({"title": f.get("title"), "severity": f.get("severity"),
          "category": f.get("category"), "location": f.get("location"),
          "id": f.get("id")} for f in extra),
        key=lambda f: sev_rank.get(f["severity"], 9))[:40]
    api = result.get("api", {}) or {}
    sens_eps = [{"value": e["value"], "category": e.get("category_name"),
                 "severity": e.get("severity")}
                for e in api.get("endpoints", [])
                if e.get("severity") in ("high", "medium") and e.get("category") != "third-party"][:30]
    return {
        "meta": _app_ctx(result.get("meta")),
        "score": result.get("score"), "rating": result.get("rating"),
        "root": {"layers": result.get("root", {}).get("layers")},
        "ssl": {"layers": result.get("ssl", {}).get("layers")},
        "frameworks": [f.get("name") for f in result.get("frameworks", [])],
        "findings": findings,
        "sensitive_endpoints": sens_eps,
    }


def pentest_plan(result, cfg=None):
    """Return {ok, markdown} — a prioritised, app-specific test plan."""
    cfg = cfg or load_config()
    if not cfg.enabled:
        return {"ok": False, "enabled": False, "error": "AI disabled"}
    prompt = (
        "STATIC ANALYSIS SUMMARY:\n" + json.dumps(_plan_context(result), indent=1) +
        "\n\nProduce a prioritised penetration-test plan for this app in markdown: "
        "an ordered attack path (most promising first) tying findings together "
        "(e.g. guest/anonymous access + IDOR-prone endpoints), the specific requests/"
        "actions to run for each, what would confirm the bug, and a quick-wins list. "
        "Reference the real findings and endpoints above. Be concise and actionable."
    )
    try:
        md = P.chat(_SYSTEM, prompt, cfg=cfg, max_tokens=2200)
        return {"ok": True, "markdown": md, "provider": cfg.provider, "model": cfg.model}
    except P.AIError as e:
        return {"ok": False, "enabled": True, "error": str(e)}

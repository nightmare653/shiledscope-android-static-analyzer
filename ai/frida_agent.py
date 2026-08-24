"""
AI Frida bypass agent.

The deterministic generated script stays the baseline. When it isn't enough
(obfuscated app, native/Flutter pinning), this agent iterates:

    run script on device  ->  read console/errors  ->  ask the model for an
    improved script (grounded in the app's detected mechanisms + discovered
    class names + the observed output)  ->  run again ...  (bounded)

Flutter is the hard case (BoringSSL statically linked in libflutter.so, Java
hooks don't apply), so the agent is primed with Flutter-specific strategies and
is free to try different function patterns/offsets across iterations.

Everything is grounded in the engine's own output and the real device feedback;
the model never invents package/class names — they are supplied.
"""

import re

from . import provider as P
from . import frida_runner
from .config import load_config

_SYSTEM = (
    "You are an expert Frida script author helping with an AUTHORIZED mobile "
    "assessment. You write COMPLETE, runnable Frida JavaScript that bypasses the "
    "protection described, targeting the REAL class/library names provided. After "
    "a one-paragraph plan, output the full script in a single ```javascript code "
    "block. Rules: use only the provided package/class/framework facts; make the "
    "script defensive (wrap hooks in try/catch, log each installed hook with "
    "'[+] ...'); when given the previous script and its console/errors, FIX what "
    "failed rather than starting over. Prefer robust, version-agnostic techniques."
)

_FLUTTER_STRATEGY = (
    "\n\nTHIS APP USES FLUTTER. Java/OkHttp/TrustManager hooks will NOT work — "
    "Flutter statically links BoringSSL inside libflutter.so and ignores the "
    "system/user CA store. Use NATIVE strategies and try progressively:\n"
    "1. Module.getBaseAddress('libflutter.so'); Memory.scan for the "
    "ssl_verify byte pattern for the target arch (arm64/arm/x86_64) and "
    "Interceptor.replace/attach it to force success (return 1 / OK).\n"
    "2. Hook 'ssl_crypto_x509_session_verify_cert_chain' or the custom-verify "
    "callback registered via SSL_CTX_set_custom_verify / SSL_set_custom_verify; "
    "force the callback result to ssl_verify_ok (0).\n"
    "3. If pattern scanning, provide multiple candidate patterns and pick the "
    "one that resolves; log the resolved address.\n"
    "4. Mention reFlutter as a fallback if hooks fail.\n"
    "Adapt offsets/patterns across iterations based on what the console shows."
)


def _extract_js(text):
    """Pull the JS out of the model reply (fenced block preferred)."""
    m = re.search(r"```(?:javascript|js)?\s*(.*?)```", text, re.S)
    if m:
        return m.group(1).strip()
    return text.strip()


def _context(result, goal):
    meta = result.get("meta") or {}
    fw = [f.get("id") for f in result.get("frameworks", [])]
    disc = result.get("discovered") or {}
    mechs = []
    for b in ("root", "ssl"):
        for mch in result.get(b, {}).get("mechanisms", []):
            mechs.append({"id": mch.get("id"), "name": mch.get("name"),
                          "layer": mch.get("layer")})
    return {
        "package": meta.get("package"),
        "goal": goal,
        "frameworks": fw,
        "flutter": "flutter" in fw,
        "detected_mechanisms": mechs,
        "app_trustmanager_classes": (disc.get("custom_tm", []) + disc.get("trust_all", []))[:20],
        "obfuscation": (result.get("obfuscation") or {}).get("level"),
    }


def _judge(run):
    """Best-effort success signal: script loaded, hooks installed, no errors."""
    if not run.get("ok"):
        return False, "errors: " + "; ".join(run.get("errors", [])[:3])
    if run.get("markers"):
        return True, "%d hook(s) installed: %s" % (len(run["markers"]), " | ".join(run["markers"][:4]))
    return False, "loaded but no '[+]' hook markers seen — refine"


def bypass(result, package, goal="ssl", device_id=None, cfg=None,
           max_iters=4, collect_seconds=6, runner=None):
    """
    Run the iterative agent. `runner` is injectable for testing; defaults to the
    real frida device bridge. Returns a transcript dict.
    """
    cfg = cfg or load_config()
    if not cfg.enabled:
        return {"ok": False, "enabled": False, "error": "AI disabled"}
    runner = runner or frida_runner
    ctx = _context(result, goal)
    flutter = ctx["flutter"]

    system = _SYSTEM + (_FLUTTER_STRATEGY if flutter else "")
    # baseline: the deterministic script, unless Flutter (Java script is useless there)
    current = (result.get("frida") or {}).get("script") or ""
    if flutter or not current:
        current = None  # let the AI write the first script for Flutter/empty

    iterations = []
    confirmed = False
    import json as _json
    for i in range(max_iters):
        if current is None:
            # ask the AI to author a script from context + last feedback
            fb = ""
            if iterations:
                last = iterations[-1]
                fb = ("\n\nPREVIOUS SCRIPT:\n```javascript\n%s\n```\nITS CONSOLE:\n%s\nITS ERRORS:\n%s"
                      % (last["script"][:4000], "\n".join(last["run"].get("console", [])[:30]),
                         "\n".join(last["run"].get("errors", [])[:10])))
            prompt = ("TARGET (authorized):\n" + _json.dumps(ctx, indent=1) +
                      "\nWrite a Frida script to bypass the '%s' protection for package '%s'. "
                      "Use the real class names above." % (goal, package) + fb)
            try:
                reply = P.chat(system, prompt, cfg=cfg, max_tokens=1800)
            except P.AIError as e:
                return {"ok": False, "enabled": True, "error": "AI: %s" % e,
                        "iterations": iterations}
            current = _extract_js(reply)
            ai_notes = reply[:400]
        else:
            ai_notes = "deterministic baseline script"

        run = runner.run_script(package, current, device_id=device_id,
                                spawn=True, collect_seconds=collect_seconds)
        ok, why = _judge(run)
        iterations.append({"iter": i + 1, "script": current, "run": run,
                           "verdict": why, "ai_notes": ai_notes})
        if ok:
            confirmed = True
            break
        current = None  # force an AI refinement next round

    return {
        "ok": True, "enabled": True, "confirmed": confirmed,
        "flutter": flutter, "iterations": iterations,
        "final_script": iterations[-1]["script"] if iterations else None,
        "note": ("Script loads and installs hooks; confirm the actual bypass by "
                 "proxying the app's traffic (Burp/mitmproxy) while exercising it."),
    }

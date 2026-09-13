"""
Opt-in secret liveness validation.

When a hardcoded vendor credential is found, we can optionally confirm whether
it is actually LIVE by making a single, READ-ONLY probe to the vendor's API
(e.g. GitHub `GET /user`, Stripe `GET /v1/balance`, Telegram `getMe`). A live
key is upgraded to a confirmed, high-severity finding; a dead one is marked so
the tester can deprioritise it. This turns "likely secret" into "confirmed live
credential" and removes guesswork.

STRICTLY OPT-IN and network-gated (SHIELDSCOPE_VALIDATE_SECRETS=1 or the CLI
`--validate-secrets` flag): it sends the discovered key to its own vendor over
TLS, nothing else, and only for AUTHORISED testing. Every probe is read-only
(no writes, no state change), short-timeout, and best-effort — any error leaves
the finding untouched.
"""

import json
import os
import urllib.error
import urllib.request

_TIMEOUT = int(os.environ.get("SHIELDSCOPE_VALIDATE_TIMEOUT", "8"))
_MAX_PROBES = int(os.environ.get("SHIELDSCOPE_VALIDATE_MAX", "40"))
_UA = "ShieldScope-validator/1.0"


def _req(method, url, headers=None, data=None):
    """Return (status_code, body_text). status 0 == could not connect."""
    req = urllib.request.Request(url, method=method, data=data,
                                 headers={"User-Agent": _UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            return r.getcode(), r.read(8192).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            body = e.read(8192).decode("utf-8", "replace")
        except Exception:
            body = ""
        return e.code, body
    except Exception:
        return 0, ""


# ---------------------------------------------------------------------------
#  per-vendor probes: rule id -> function(value) -> "live" | "invalid" | "unknown"
#  every request is read-only.
# ---------------------------------------------------------------------------
def _github(v):
    c, _ = _req("GET", "https://api.github.com/user", {"Authorization": "Bearer " + v})
    return "live" if c == 200 else "invalid" if c == 401 else "unknown"


def _gitlab(v):
    c, _ = _req("GET", "https://gitlab.com/api/v4/user", {"PRIVATE-TOKEN": v})
    return "live" if c == 200 else "invalid" if c == 401 else "unknown"


def _stripe(v):
    c, _ = _req("GET", "https://api.stripe.com/v1/balance", {"Authorization": "Bearer " + v})
    return "live" if c == 200 else "invalid" if c in (401,) else "unknown"


def _sendgrid(v):
    c, _ = _req("GET", "https://api.sendgrid.com/v3/scopes", {"Authorization": "Bearer " + v})
    return "live" if c == 200 else "invalid" if c == 401 else "unknown"


def _slack(v):
    c, b = _req("POST", "https://slack.com/api/auth.test", {"Authorization": "Bearer " + v})
    if c == 200:
        try:
            return "live" if json.loads(b).get("ok") else "invalid"
        except Exception:
            return "unknown"
    return "unknown"


def _telegram(v):
    c, b = _req("GET", "https://api.telegram.org/bot%s/getMe" % v)
    if c == 200:
        try:
            return "live" if json.loads(b).get("ok") else "invalid"
        except Exception:
            return "unknown"
    return "invalid" if c in (401, 404) else "unknown"


def _npm(v):
    c, _ = _req("GET", "https://registry.npmjs.org/-/whoami", {"Authorization": "Bearer " + v})
    return "live" if c == 200 else "invalid" if c == 401 else "unknown"


def _huggingface(v):
    c, _ = _req("GET", "https://huggingface.co/api/whoami-v2", {"Authorization": "Bearer " + v})
    return "live" if c == 200 else "invalid" if c == 401 else "unknown"


def _openai(v):
    c, _ = _req("GET", "https://api.openai.com/v1/models", {"Authorization": "Bearer " + v})
    return "live" if c == 200 else "invalid" if c == 401 else "unknown"


def _google_api(v):
    c, b = _req("GET",
                "https://maps.googleapis.com/maps/api/geocode/json?address=NY&key=" + v)
    if c == 200:
        try:
            st = json.loads(b).get("status", "")
        except Exception:
            return "unknown"
        if st in ("OK", "ZERO_RESULTS", "OVER_QUERY_LIMIT"):
            return "live"                 # key accepted (even if quota/empty)
        if st == "REQUEST_DENIED":
            return "invalid"              # bad or wrong-API-restricted key
    return "unknown"


_VALIDATORS = {
    "github-pat": _github, "github-fine-pat": _github,
    "gitlab-pat": _gitlab,
    "stripe-secret": _stripe,
    "sendgrid-key": _sendgrid,
    "slack-token": _slack,
    "telegram-bot": _telegram,
    "npm-token": _npm,
    "huggingface-token": _huggingface,
    "openai-key": _openai,
    "google-api-key": _google_api,
}


def validators_for():
    return sorted(_VALIDATORS.keys())


def validate_result(result):
    """Probe every validatable secret in result['extra'] and annotate it in place.

    Adds `validated` ("live"|"invalid"|"unknown") to each secret finding it can
    check; a LIVE key is promoted to high severity with a CONFIRMED prefix. Adds
    a `secret_validation` summary block to the result. Best-effort and bounded.
    """
    extra = result.get("extra") or []
    checked = {}                          # (rule,value) -> verdict (dedupe probes)
    live = invalid = unknown = 0
    probes = 0
    for f in extra:
        if f.get("category") != "secret":
            continue
        rule = f.get("rule")
        fn = _VALIDATORS.get(rule)
        if not fn:
            continue
        value = f.get("evidence")
        if not value:
            continue
        key = (rule, value)
        if key in checked:
            verdict = checked[key]
        else:
            if probes >= _MAX_PROBES:
                break
            probes += 1
            try:
                verdict = fn(value)
            except Exception:
                verdict = "unknown"
            checked[key] = verdict
        f["validated"] = verdict
        if verdict == "live":
            live += 1
            f["severity"] = "high"
            if not str(f.get("title", "")).startswith("CONFIRMED LIVE"):
                f["title"] = "CONFIRMED LIVE — " + f.get("title", "secret")
            f["risk"] = "CONFIRMED LIVE by a read-only probe to the vendor. " + f.get("risk", "")
        elif verdict == "invalid":
            invalid += 1
        else:
            unknown += 1
    result["secret_validation"] = {
        "ran": True, "probes": probes,
        "live": live, "invalid": invalid, "unknown": unknown,
    }
    # re-sort so confirmed-live rises to the top
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    extra.sort(key=lambda x: (0 if x.get("validated") == "live" else 1,
                              order.get(x.get("severity"), 9)))
    return result

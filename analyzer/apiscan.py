"""
API / endpoint enumeration + sensitivity classification + pentest playbooks.

Answers "show me every API call, even the hidden ones, and tell me which are
worth attacking and how."

Endpoints (absolute URLs AND relative `/api/...` paths — including ones built at
runtime from a base URL + a path constant) live in the dex string pool, the RN
JS bundle, and resources. We harvest those (a handful of files, fast — no full
tree walk), then:

  * classify each by SENSITIVITY (auth, user-data/IDOR, financial, admin, file,
    graphql, otp ...), and
  * attach a concrete TEST PLAYBOOK — what the likely weakness is, the request
    to try, the payload/technique, and the tool — so the report hands the tester
    the next action, not just a URL.

Static analysis can't prove a server-side bug; these are prioritised leads to
verify with an intercepting proxy.
"""

import os
import re

from . import deepscan

_URL_RE = re.compile(rb"[a-z]{2,6}://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{4,200}")
# quoted path-like strings: "/segment/segment..."
_PATH_RE = re.compile(rb"""["'](/[A-Za-z0-9_][A-Za-z0-9_\-/.{}$:]{2,120})["']""")

# hosts that are boilerplate, never real API targets
_NOISE_HOST = ("schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org",
               "java.sun.com", "goo.gl", "ns.adobe.com", "specs.openid.net",
               "purl.org", "iptc.org", "whatwg.org", "example.com", "w3.org",
               "github.com", "gstatic.com", "googleapis.com/auth", "fonts.google")
# path prefixes that are android resource/asset noise, not API endpoints
_NOISE_PATH = ("/res/", "/assets/", "/META-INF/", "/system/", "/data/", "/dev/",
               "/proc/", "/sdcard/", "/android/", "/kotlin/", "/androidx/",
               "/com/", "/org/", "/java/", "/javax/")
# a path must look API-ish (either a versioned/rest marker or a sensitive noun)
_APIISH = re.compile(
    r"(?i)(/api/|/rest/|/graphql|/v[0-9]/|/oauth|/auth|/login|/logout|/register|"
    r"/signup|/signin|/token|/session|/user|/users|/account|/profile|/customer|"
    r"/otp|/verify|/password|/reset|/payment|/pay|/order|/cart|/checkout|/wallet|"
    r"/balance|/transaction|/transfer|/subscription|/invoice|/card|/admin|/internal|"
    r"/upload|/download|/file|/document|/device|/consumer|/me\b|/lookup|/search)")


# ---------------------------------------------------------------------------
#  sensitivity classification + playbook knowledge base
#  (matched top-down; first match wins)
# ---------------------------------------------------------------------------
_CLASSES = [
    ("auth", "Authentication", "high",
     re.compile(r"(?i)(/login|/logout|/signin|/signup|/register|/oauth|/token|"
                r"/auth\b|/session|/password|/reset|/credential|/refresh)"),
     "Auth endpoints gate the whole app. Weaknesses here (default/guest creds, "
     "auth bypass, weak/again-usable OTP, JWT flaws, user enumeration) are high impact.",
     ["Try the guest/default account and weak/common credentials.",
      "Test user enumeration: compare responses for valid vs invalid usernames.",
      "If a JWT is returned, check alg=none, weak secret, and missing signature checks.",
      "Replay/brute the login & OTP verify (is there rate limiting / lockout?)."],
     "e.g. username=' OR '1'='1 ; JWT alg swap ; reuse an old/again valid OTP",
     "Burp Repeater/Intruder, jwt_tool"),
    ("financial", "Financial / transaction", "high",
     re.compile(r"(?i)(/payment|/pay\b|/order|/checkout|/cart|/wallet|/balance|"
                r"/transaction|/transfer|/topup|/recharge|/invoice|/refund|/billing|/card)"),
     "Money-moving endpoints. Look for parameter tampering (amount/price/currency), "
     "IDOR on order/transaction ids, and replay of signed requests.",
     ["Intercept a purchase and tamper amount/price/quantity/currency.",
      "Change order/transaction/invoice id to another user's (IDOR).",
      "Replay a completed payment request; test for missing idempotency.",
      "Test negative/overflow amounts and coupon/promo abuse."],
     "amount=0.01 / quantity=-1 / other user's orderId",
     "Burp Repeater"),
    ("idor", "User data (IDOR-prone)", "high",
     re.compile(r"(?i)(/user|/users|/account|/profile|/customer|/me\b|/consumer|"
                r"/contact|/address|/device|\{id\}|\{userid\}|/id/|/msisdn|/subscriber)"),
     "Endpoints scoped to a user/account/device id are the classic IDOR / broken-"
     "object-level-authorization target — especially reachable from a guest session.",
     ["Capture the request authenticated (or as guest) and note the id parameter.",
      "Replace the id with another user's value and check for their data (horizontal privesc).",
      "Remove/rotate the auth token and see if the object is still returned.",
      "Fuzz numeric/sequential ids; try id in path, query, and body."],
     "userId=<victim_id> / msisdn=<other_number> / accountId++",
     "Burp Repeater/Intruder, Autorize"),
    ("admin", "Admin / internal", "high",
     re.compile(r"(?i)(/admin|/internal|/manage|/config|/debug|/console|/actuator|/sys)"),
     "Administrative/internal endpoints shipped in a consumer app. Test whether a "
     "normal or guest user can reach them (vertical privilege escalation).",
     ["Call the endpoint with a normal/guest session; is it authorized?",
      "Look for missing role checks and forced-browsing to admin actions.",
      "Check for verbose/debug info disclosure."],
     "access with low-priv token; force-browse the admin path",
     "Burp"),
    ("file", "File / upload / download", "medium",
     re.compile(r"(?i)(/upload|/download|/file|/files|/document|/attachment|/image|/media|/export|/import)"),
     "File endpoints are prone to path traversal, unrestricted upload (webshell), "
     "and SSRF when they fetch a user-supplied URL.",
     ["Test path traversal in the filename/path param (../../).",
      "Upload disallowed types (.html/.svg/.php) and probe content-type checks.",
      "If it fetches a URL, point it at internal/metadata hosts (SSRF)."],
     "file=../../../../etc/passwd / url=http://169.254.169.254/",
     "Burp"),
    ("graphql", "GraphQL", "medium",
     re.compile(r"(?i)(/graphql|/gql)"),
     "GraphQL surface: check introspection, query batching/aliasing abuse, and "
     "object-level authorization on nested fields.",
     ["Run introspection ({__schema{types{name}}}); is it enabled in prod?",
      "Batch/alias queries to bypass rate limits and pull other users' objects.",
      "Test authorization on each mutation and nested resolver."],
     "introspection query; aliased batch of node(id:) lookups",
     "Burp, GraphQL-Cop / clairvoyance"),
    ("otp", "OTP / verification", "high",
     re.compile(r"(?i)(/otp|/verify|/verification|/2fa|/mfa|/confirm)"),
     "OTP/verification flows: check for brute force (no rate limit), OTP leakage in "
     "the response, and client-side-only verification.",
     ["Brute the OTP (is it rate-limited / lockout after N tries?).",
      "Inspect the verify response — is the OTP or a success flag leaked client-side?",
      "Try reusing a consumed OTP and skipping the verify step entirely."],
     "brute 0000-9999; replay used OTP; tamper verified=true in response",
     "Burp Intruder"),
    ("search", "Search / lookup", "medium",
     re.compile(r"(?i)(/search|/lookup|/query|/find|/autocomplete|/suggest)"),
     "Search/lookup endpoints can leak other users' records and are injection-prone.",
     ["Test injection (SQL/NoSQL) and wildcard queries that return everything.",
      "Check whether results are scoped to the caller or leak all records."],
     "q=* / q=' OR 1=1-- / overbroad wildcard",
     "Burp"),
]
_GENERIC = ("api", "API endpoint", "low",
            "A backend API call. Verify authorization scoping and input validation.",
            ["Replay authenticated and unauthenticated; check access control.",
             "Fuzz parameters for injection and mass-assignment."],
            "standard param fuzzing", "Burp")

# well-known third-party hosts: still inventoried, but not attack targets for
# THIS app's backend, so never flagged sensitive (avoids "admin/idor" FPs on
# Google/Firebase/analytics/SDK endpoints).
_THIRD_PARTY = (
    "google.com", "googleapis.com", "gstatic.com", "google-analytics", "firebase",
    "firebaseio", "crashlytics", "googletagmanager", "tagmanager.google",
    "doubleclick", "hicloud.com", "hicloud.ru", "huawei", "facebook.com",
    "fbcdn", "appsflyer", "adjust.com", "branch.io", "sentry.io", "datadoghq",
    "newrelic", "appdynamics", "mixpanel", "amplitude", "segment.io", "braze",
    "cloudflare", "cloudfront", "akamai", "medialize.github.io", "github.io",
    "microsoft.com", "windows.net", "office.com", "apple.com", "cdn.jsdelivr",
    "unpkg.com", "jquery.com", "bootstrapcdn",
    "developer.android.com", "docs.mapbox.com", "mapbox.com", "bloomreach.com",
    "documentation.bloomreach", "exponea.com", "cdn.exponea",
)
_STATIC_EXT = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg",
               ".webp", ".woff", ".woff2", ".ttf", ".otf", ".html", ".htm", ".ico")
_HOST_RE = re.compile(r"^[a-z]+://([^/:?#]+)", re.I)


def _host(url):
    m = _HOST_RE.match(url)
    return (m.group(1).lower() if m else "")


def _third_party(name="Third-party / SDK"):
    return {"category": "third-party", "category_name": name, "severity": "info",
            "why": "A third-party / SDK / analytics endpoint, not this app's backend. "
                   "Inventoried for completeness; not an access-control target here.",
            "tests": [], "payload": "", "tool": ""}


def _classify(value, is_url):
    if is_url and any(tp in _host(value) for tp in _THIRD_PARTY):
        return _third_party()
    for cid, name, sev, rx, why, tests, payload, tool in _CLASSES:
        if rx.search(value):
            return {"category": cid, "category_name": name, "severity": sev,
                    "why": why, "tests": tests, "payload": payload, "tool": tool}
    cid, name, sev, why, tests, payload, tool = _GENERIC
    return {"category": cid, "category_name": name, "severity": sev,
            "why": why, "tests": tests, "payload": payload, "tool": tool}


# ---------------------------------------------------------------------------
#  harvesting
# ---------------------------------------------------------------------------
def _iter_source_files(unpacked):
    """Yield bytes of the few files that hold endpoint literals."""
    base = deepscan._op(unpacked.raw_dir)
    for dp, _dn, fs in os.walk(base):
        for fn in fs:
            low = fn.lower()
            take = (low.startswith("classes") and low.endswith(".dex")) \
                or low.endswith((".bundle", ".js", ".json", ".jsbundle"))
            if not take:
                continue
            try:
                with open(os.path.join(dp, fn), "rb") as f:
                    yield f.read(96 * 1024 * 1024)
            except OSError:
                continue
    # decoded resource strings
    if unpacked.res_dir:
        for dp, _dn, fs in os.walk(deepscan._op(unpacked.res_dir)):
            for fn in fs:
                if fn.endswith(".xml") and "values" in dp.lower():
                    try:
                        with open(os.path.join(dp, fn), "rb") as f:
                            yield f.read(4 * 1024 * 1024)
                    except OSError:
                        continue


def harvest(unpacked, cap=500):
    urls, paths = set(), set()
    for data in _iter_source_files(unpacked):
        for m in _URL_RE.finditer(data):
            v = m.group(0).decode("utf-8", "replace").rstrip('".,)\\\'')
            if any(n in v for n in _NOISE_HOST):
                continue
            if v.startswith(("http", "ws")):
                urls.add(v[:200])
        if len(urls) < cap * 3:
            for m in _PATH_RE.finditer(data):
                p = m.group(1).decode("utf-8", "replace")
                if any(p.startswith(n) or n in p for n in _NOISE_PATH):
                    continue
                if p.lower().rsplit("?", 1)[0].endswith(_STATIC_EXT):
                    continue  # static asset, not an API path
                if _APIISH.search(p):
                    paths.add(p[:160])
        if len(urls) + len(paths) > cap * 6:
            break

    endpoints = []
    for v in sorted(urls):
        if v.lower().rsplit("?", 1)[0].endswith(_STATIC_EXT):
            continue
        c = _classify(v, True)
        if c["category"] == "api" and not _APIISH.search(v):
            # drop absolute URLs that aren't clearly an API host (CDN/doc noise)
            if not re.search(r"(?i)(/api|/v[0-9]/|api\.|\.lan|-sit|-uat|dev\.|stg\.|staging)", v):
                continue
        endpoints.append(dict(value=v, kind="url", **c))
    for p in sorted(paths):
        endpoints.append(dict(value=p, kind="path", **_classify(p, False)))

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    endpoints.sort(key=lambda e: (order.get(e["severity"], 9), e["category"], e["value"]))
    endpoints = endpoints[:cap]

    from collections import Counter
    counts = Counter(e["category_name"] for e in endpoints)
    sensitive = sum(1 for e in endpoints if e["severity"] in ("high", "medium")
                    and e["category"] != "third-party")
    return {"endpoints": endpoints,
            "counts": {"total": len(endpoints), "sensitive": sensitive,
                       "urls": len(urls), "paths": len(paths),
                       "by_category": dict(counts)}}

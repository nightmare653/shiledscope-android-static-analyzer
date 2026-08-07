"""
Extra static security checks (#4) — OWASP-MASVS-style triage.

Every finding is DESCRIPTIVE and LOCATED. Schema:

  {
    id, title, severity, category,
    location    : where it lives (file + element/offset)
    evidence    : the actual value / snippet (secrets shown in FULL)
    description : what it is
    risk        : why it matters / impact
    reproduce   : list[str] concrete steps to reproduce / verify
    mitigation  : how to fix
  }

The scanners (scan_secrets / scan_crypto) are called once per file during the
analyzers' single pass, so each hit carries the file it came from. The build_*
helpers then group hits and attach the knowledge-base prose.
"""

import re

# ===========================================================================
#  SECRETS
# ===========================================================================
# (label, regex, severity, needs_verify)
_SECRET_PATTERNS = [
    ("AWS access key id",     re.compile(rb"AKIA[0-9A-Z]{16}"), "high", False),
    ("AWS secret access key", re.compile(rb"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"), "high", True),
    ("Google API key",        re.compile(rb"AIza[0-9A-Za-z\-_]{35}"), "high", False),
    ("Google OAuth client",   re.compile(rb"[0-9]+-[0-9a-z]{20,}\.apps\.googleusercontent\.com"), "low", False),
    ("Firebase database URL", re.compile(rb"[a-z0-9.-]+\.firebaseio\.com"), "medium", False),
    ("Firebase (google) app id", re.compile(rb"1:[0-9]{8,}:android:[0-9a-f]{8,}"), "low", False),
    ("Slack token",           re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,}"), "high", False),
    ("Stripe live secret key",re.compile(rb"sk_live_[0-9a-zA-Z]{24}"), "high", False),
    ("Stripe publishable key",re.compile(rb"pk_live_[0-9a-zA-Z]{24}"), "medium", False),
    ("Private key block",     re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high", False),
    ("JSON Web Token",        re.compile(rb"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}"), "medium", False),
    ("GitHub token",          re.compile(rb"gh[pousr]_[0-9A-Za-z]{36}"), "high", False),
    ("Mapbox token",          re.compile(rb"(?:sk|pk)\.eyJ[0-9A-Za-z_-]{20,}"), "low", False),
    ("Generic API key/secret",re.compile(rb"(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"]([0-9a-zA-Z\-_./+]{12,})['\"]"), "medium", True),
]

# obvious non-secret values that pattern-based rules tend to catch
_PLACEHOLDER_RE = re.compile(r"(?i)(example|placeholder|your[_-]?|changeme|dummy|sample|redacted|xxxx|<|\{\{|test[_-]?(key|token|secret))")


def _looks_placeholder(value):
    v = value.strip()
    if len(v) < 10:
        return True
    if _PLACEHOLDER_RE.search(v):
        return True
    # real keys/tokens almost always contain a digit; a purely-alphabetic value
    # from a noisy "key=..." match is far more likely a field name / placeholder.
    if v.isalpha():
        return True
    return False


def _valid_private_key(block):
    """Reject empty/placeholder PEM blocks — require a real base64 body."""
    body = block
    for marker in ("-----BEGIN", "-----END", "PRIVATE KEY", "RSA", "EC", "DSA", "OPENSSH", "PGP", "-"):
        body = body.replace(marker, "")
    body = "".join(body.split())
    return len(body) >= 64

# characters that may belong to a token when we expand a match to its full value
_TOK = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-/+=:")


def _expand(data, s, e, cap=200):
    """Grow [s,e) left/right over token chars to recover the full secret value."""
    while s > 0 and data[s - 1] in _TOK and (e - s) < cap:
        s -= 1
    while e < len(data) and data[e] in _TOK and (e - s) < cap:
        e += 1
    return data[s:e]


def scan_secrets(data, location, cap_per_pattern=5):
    """Return raw hits [{label, value, location, severity, verify}] for one file's bytes."""
    hits = []
    for label, rx, sev, verify in _SECRET_PATTERNS:
        seen = 0
        for m in rx.finditer(data):
            if label == "Private key block":
                # capture the whole PEM block through its END marker
                end = data.find(b"-----END", m.start())
                blob = data[m.start(): end + 40] if end != -1 else data[m.start(): m.start() + 4000]
                val = blob.decode("utf-8", "replace").strip()
                if not _valid_private_key(val):
                    continue  # empty/placeholder PEM template — skip
            elif m.groups():
                # pattern captured the value explicitly (generic/auth-token rules)
                val = m.group(1).decode("utf-8", "replace")
                if verify and _looks_placeholder(val):
                    continue
            else:
                # the regex already matches the full token — no expansion needed
                val = m.group(0).decode("utf-8", "replace")
                if verify and _looks_placeholder(val):
                    continue
            hits.append({"label": label, "value": val, "location": location,
                         "severity": sev, "verify": verify})
            seen += 1
            if seen >= cap_per_pattern:
                break
    return hits


# ---- knowledge base: secret prose (generic, tuned per family) ----
def _secret_prose(label, verify):
    base_risk = ("APKs/IPAs are trivial to unpack (`unzip` / `apktool d`), so anything embedded is "
                 "readable by anyone. A hardcoded credential can be abused directly and cannot be "
                 "rotated without shipping an app update — assume it is already compromised.")
    repro = [
        "Unpack the app: `apktool d app.apk` (Android) or `unzip app.ipa` (iOS).",
        "Search for the value: `grep -rF '<value>' .` (or `strings <binary> | grep`).",
        "Use the credential against its service to confirm it is live (in scope only).",
    ]
    mit = ("Remove the secret from the client. Proxy privileged calls through your backend so the key "
           "never ships; if a token must live on-device, issue short-lived, per-user tokens. "
           "Rotate/revoke the exposed key now.")
    specific = {
        "Private key block": ("A private key (RSA/EC/OpenSSH/PGP) is embedded in the app.",
            "Whoever extracts it can impersonate the app/server, forge signatures, or decrypt "
            "traffic/data protected by the corresponding key. " + base_risk),
        "AWS access key id": ("An AWS access key id is embedded.",
            "Paired with its secret it grants direct access to your AWS account/resources (S3, etc.). " + base_risk),
        "Google API key": ("A Google API key is embedded.",
            "Depending on key restrictions it can be used to run up billing, access Maps/Firebase/other "
            "Google APIs, or read data. " + base_risk),
        "Stripe live secret key": ("A live Stripe secret key is embedded.",
            "It allows full server-side control of your Stripe account — creating charges, refunds and "
            "reading customer data. " + base_risk),
        "JSON Web Token": ("A JWT is embedded in the app.",
            "If still valid it may grant authenticated access as its subject; its claims also leak "
            "internal structure. " + base_risk),
    }
    desc, risk = specific.get(label, ("A hardcoded %s was found in the app package." % label, base_risk))
    if verify:
        desc += " (Pattern-based match — verify it is a real, active credential and not test/placeholder data.)"
    return desc, risk, repro, mit


def build_secret_findings(raw_hits):
    """Group raw secret hits by (label,value) and attach prose + all locations."""
    grouped = {}
    for h in raw_hits:
        key = (h["label"], h["value"])
        g = grouped.setdefault(key, {"sev": h["severity"], "verify": h["verify"], "locs": []})
        if h["location"] not in g["locs"]:
            g["locs"].append(h["location"])
    findings = []
    for (label, value), g in grouped.items():
        desc, risk, repro, mit = _secret_prose(label, g["verify"])
        locs = g["locs"]
        loc = locs[0] + (" (+%d more file%s)" % (len(locs) - 1, "s" if len(locs) > 2 else "")
                         if len(locs) > 1 else "")
        findings.append({
            "id": "secret-" + re.sub(r"\W+", "-", (label + value[:8]).lower()),
            "title": "Hardcoded secret: " + label,
            "severity": g["sev"], "category": "secret",
            "location": loc, "evidence": value,
            "description": desc, "risk": risk, "reproduce": repro, "mitigation": mit,
        })
    return findings


# ===========================================================================
#  PII  (used by bundled-DB parsing and the extracted-data analyzer)
# ===========================================================================
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{10,}")


def _luhn_ok(num):
    digits = [int(c) for c in num if c.isdigit()]
    if not (13 <= len(digits) <= 19):
        return False
    s, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0


def scan_pii(text, location, cap=8):
    """Return [{kind, value, location}] for likely-PII in a string."""
    out = []
    for m in _EMAIL_RE.finditer(text):
        out.append({"kind": "email", "value": m.group(0), "location": location})
        if len(out) >= cap:
            return out
    for m in _CARD_RE.finditer(text):
        raw = m.group(0)
        if _luhn_ok(raw):
            out.append({"kind": "credit card (Luhn ok)", "value": raw.strip(), "location": location})
    for m in _BEARER_RE.finditer(text):
        out.append({"kind": "bearer token", "value": m.group(0)[:60], "location": location})
    return out[:cap]


# ===========================================================================
#  WEAK CRYPTO
# ===========================================================================
_WEAK_CRYPTO = [
    (re.compile(rb"AES/ECB"), "AES in ECB mode",
     "The app uses AES in ECB mode.",
     "ECB encrypts identical plaintext blocks to identical ciphertext blocks, so it leaks data "
     "patterns and provides no semantic security (the classic 'ECB penguin').",
     ["Decompile and locate `Cipher.getInstance(\"AES/ECB/...\")`.",
      "Encrypt input with repeating 16-byte blocks and observe repeating ciphertext blocks."],
     "Use an authenticated mode: AES-GCM (or AES-CBC + HMAC) with a random IV/nonce per message."),
    (re.compile(rb"\bDES/|DESede|/DES\b|\"DES\""), "DES / 3DES",
     "The app uses DES or Triple-DES.",
     "DES has a 56-bit key (brute-forceable); 3DES is slow, deprecated, and vulnerable to Sweet32.",
     ["Locate `Cipher.getInstance(\"DES...\")` / `DESede` in the decompiled code."],
     "Migrate to AES-GCM with 128/256-bit keys."),
    (re.compile(rb"\bRC4\b|ARCFOUR"), "RC4 stream cipher",
     "The app uses the RC4 stream cipher.",
     "RC4 has known biases and is broken; it must not be used for confidentiality.",
     ["Locate RC4/ARCFOUR usage in the decompiled code or TLS config."],
     "Use AES-GCM; for TLS, disable RC4 cipher suites."),
    (re.compile(rb"getInstance\(\"MD5\"\)|\"MD5\"|MessageDigest.{0,6}MD5"), "MD5 hashing",
     "The app uses MD5.",
     "MD5 is collision-broken; unsafe for integrity, signatures, or password hashing.",
     ["Locate `MessageDigest.getInstance(\"MD5\")` in the decompiled code."],
     "Use SHA-256+ for integrity; for passwords use bcrypt/scrypt/Argon2."),
    (re.compile(rb"getInstance\(\"SHA-?1\"\)|\"SHA1\"|SHA-1 with"), "SHA-1 hashing",
     "The app uses SHA-1.",
     "SHA-1 is collision-broken (SHAttered); unsafe for signatures/certificates.",
     ["Locate `MessageDigest.getInstance(\"SHA-1\")` usage."],
     "Use SHA-256 or SHA-3."),
]


def scan_crypto(data, location):
    hits = []
    for rx, name, desc, risk, repro, mit in _WEAK_CRYPTO:
        if rx.search(data):
            hits.append({"name": name, "location": location, "desc": desc,
                         "risk": risk, "repro": repro, "mit": mit})
    return hits


def build_crypto_findings(raw_hits):
    grouped = {}
    for h in raw_hits:
        g = grouped.setdefault(h["name"], h.copy())
        g.setdefault("locs", [])
        if h["location"] not in g["locs"]:
            g["locs"].append(h["location"])
    findings = []
    for name, g in grouped.items():
        locs = g["locs"]
        loc = locs[0] + (" (+%d more)" % (len(locs) - 1) if len(locs) > 1 else "")
        findings.append({
            "id": "crypto-" + re.sub(r"\W+", "-", name.lower()),
            "title": "Weak cryptography: " + name,
            "severity": "low", "category": "crypto",
            "location": loc, "evidence": name,
            "description": g["desc"], "risk": g["risk"],
            "reproduce": g["repro"], "mitigation": g["mit"],
        })
    return findings


# ===========================================================================
#  ANDROID MANIFEST / CONFIG
# ===========================================================================
def android_config(a, pkg=None):
    findings = []
    if a is None:
        return findings
    pkg = pkg or "com.pkg"

    def attr(tag, name):
        try:
            v = a.get_element(tag, name)
            return None if v is None else str(v).lower()
        except Exception:
            return None

    ab = attr("application", "allowBackup")
    if ab == "true" or ab is None:
        findings.append({
            "id": "allow-backup", "title": "adb backup enabled (allowBackup)",
            "severity": "medium", "category": "config",
            "location": "AndroidManifest.xml -> <application android:allowBackup=%s>"
                        % ("\"true\"" if ab == "true" else "unset (defaults true)"),
            "evidence": "android:allowBackup=%s" % ("true" if ab == "true" else "(unset, defaults true)"),
            "description": "Android auto/adb backup is enabled, so the app's private data directory can be "
                           "copied off the device without root.",
            "risk": "Anyone with USB/ADB access (or malware holding BACKUP) can pull the app sandbox — "
                    "databases, shared-prefs, auth tokens, cached PII — and read it offline.",
            "reproduce": [
                "Enable USB debugging and connect the device.",
                "`adb backup -f data.ab -noapk %s`" % pkg,
                "Convert to tar: `java -jar abe.jar unpack data.ab data.tar` (android-backup-extractor).",
                "`tar xvf data.tar` and inspect `apps/%s/` for secrets." % pkg,
            ],
            "mitigation": "Set android:allowBackup=\"false\", or ship dataExtractionRules / "
                          "fullBackupContent that exclude sensitive files. Never store secrets in "
                          "backup-eligible storage in cleartext.",
        })

    if attr("application", "debuggable") == "true":
        findings.append({
            "id": "debuggable", "title": "App is debuggable in release",
            "severity": "high", "category": "config",
            "location": "AndroidManifest.xml → <application android:debuggable=\"true\">",
            "evidence": "android:debuggable=true",
            "description": "The shipped app has the debuggable flag set.",
            "risk": "Anyone can attach a debugger, run code in the app's context via `run-as`, dump "
                    "memory and read runtime secrets — even on a non-rooted device.",
            "reproduce": [
                "`adb shell run-as %s ls files` — you get a shell inside the app sandbox." % pkg,
                "Attach a JDWP debugger: `adb forward tcp:8000 jdwp:<pid>` then connect jdb.",
            ],
            "mitigation": "Ensure the release build sets debuggable=false (default for release "
                          "buildTypes). Never ship a debug build to production.",
        })

    if attr("application", "usescleartexttraffic") == "true":
        findings.append({
            "id": "cleartext", "title": "Cleartext (HTTP) traffic permitted",
            "severity": "medium", "category": "config",
            "location": "AndroidManifest.xml → <application android:usesCleartextTraffic=\"true\">",
            "evidence": "android:usesCleartextTraffic=true",
            "description": "The app is allowed to send non-TLS HTTP traffic.",
            "risk": "A network attacker (rogue Wi-Fi, ARP/DNS spoofing) can read and modify plaintext "
                    "traffic — capturing credentials/session data or injecting content.",
            "reproduce": [
                "Set the device HTTP proxy to Burp/mitmproxy.",
                "Exercise the app and watch for `http://` requests appearing in cleartext.",
            ],
            "mitigation": "Set usesCleartextTraffic=false and enforce HTTPS. Use a Network Security "
                          "Config that forbids cleartext per-domain.",
        })

    # exported components without a permission guard
    try:
        root = a.get_android_manifest_xml()
        ns = "{http://schemas.android.com/apk/res/android}"
        rows = []
        for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in root.iter(tag):
                exp = el.get(ns + "exported")
                perm = el.get(ns + "permission")
                has_filter = el.find("intent-filter") is not None
                name = (el.get(ns + "name") or "?")
                is_exp = (exp == "true") or (exp is None and has_filter)
                if is_exp and not perm:
                    rows.append((tag, name))
        if rows:
            listing = ", ".join("%s %s" % (t, n.split(".")[-1]) for t, n in rows[:12])
            example_act = next((n for t, n in rows if t in ("activity", "activity-alias")), None)
            repro = ["Enumerate: `adb shell dumpsys package %s | grep -A2 -i exported`." % pkg]
            if example_act:
                repro.append("Launch directly: `adb shell am start -n %s/%s`." % (pkg, example_act))
            repro.append("For providers: `adb shell content query --uri content://<authority>`.")
            findings.append({
                "id": "exported-components",
                "title": "Exported components without permission (%d)" % len(rows),
                "severity": "medium", "category": "config",
                "location": "AndroidManifest.xml → " + listing + ("…" if len(rows) > 12 else ""),
                "evidence": "%d exported component(s): %s" % (len(rows), listing),
                "description": "These components are reachable by any other app on the device "
                               "(exported=true, or implicitly exported via an intent-filter) and are "
                               "not protected by a permission.",
                "risk": "Other apps can start activities/services, send broadcasts, or query providers "
                        "directly — potentially bypassing auth screens, leaking data, triggering "
                        "privileged actions, or exploiting intent-redirection / provider SQLi.",
                "reproduce": repro,
                "mitigation": "Set android:exported=\"false\" on components not meant for external use; "
                              "protect the rest with a signature-level android:permission and validate "
                              "every incoming Intent/URI.",
            })
    except Exception:
        pass

    return findings


# ===========================================================================
#  iOS Info.plist / config
# ===========================================================================
def ios_config(info_plist):
    findings = []
    ats = (info_plist or {}).get("NSAppTransportSecurity") or {}
    if isinstance(ats, dict) and ats.get("NSAllowsArbitraryLoads") is True:
        findings.append({
            "id": "ats-disabled", "title": "App Transport Security disabled",
            "severity": "high", "category": "config",
            "location": "Info.plist → NSAppTransportSecurity.NSAllowsArbitraryLoads = true",
            "evidence": "NSAllowsArbitraryLoads = true",
            "description": "ATS is globally disabled, so the app may use plain HTTP and weak TLS.",
            "risk": "Network attackers can intercept/modify traffic; the OS no longer enforces TLS 1.2+, "
                    "forward secrecy, or strong ciphers.",
            "reproduce": ["`plutil -p Info.plist | grep -A3 AppTransportSecurity`.",
                          "Proxy the device through Burp and observe cleartext/weak-TLS requests."],
            "mitigation": "Remove NSAllowsArbitraryLoads; if specific domains truly need exceptions, "
                          "scope them narrowly under NSExceptionDomains and keep TLS requirements on.",
        })
    dom = ats.get("NSExceptionDomains") if isinstance(ats, dict) else None
    if isinstance(dom, dict) and dom:
        findings.append({
            "id": "ats-exceptions", "title": "ATS per-domain exceptions (%d)" % len(dom),
            "severity": "low", "category": "config",
            "location": "Info.plist → NSAppTransportSecurity.NSExceptionDomains",
            "evidence": ", ".join(list(dom.keys())[:10]),
            "description": "Specific domains have relaxed transport-security requirements.",
            "risk": "Each exception (e.g. NSExceptionAllowsInsecureHTTPLoads, lowered TLS) is a weak "
                    "point an attacker can target for that host.",
            "reproduce": ["`plutil -p Info.plist` and review each NSExceptionDomains entry."],
            "mitigation": "Remove exceptions you don't need; keep TLS 1.2+ and forward secrecy on for the rest.",
        })
    return findings

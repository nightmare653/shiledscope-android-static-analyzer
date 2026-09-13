"""
Deep secret scanner — walks the ENTIRE unpacked tree (no extension allowlist),
including nested-archive contents, decoded resources, and jadx-reconstructed
Java. This is the fix for "not going in depth to find hardcoded secrets".

For each file:
  * text  -> decode and run vendor rules + gated entropy, with line numbers.
  * binary-> extract ASCII/UTF-16 strings first, then run the same rules.

Source-aware selection keeps it fast and non-redundant:
  * when jadx Java is available, secrets are read from Java (best string
    reconstruction) + resources + packaged non-dex files; smali is skipped
    (it derives from the same dex). If jadx failed, smali becomes the fallback
    source so we still see reconstructed constants.

Hits are de-duplicated by (rule, value) and every location is kept.
"""

import bisect
import os
import re

from . import secret_rules as R

_IS_WIN = os.name == "nt"


def _op(path):
    """
    Windows MAX_PATH (260) guard: jadx emits deeply-nested paths that exceed it,
    and a plain open() then fails with FileNotFoundError. The \\?\ extended-length
    prefix bypasses the limit so we don't silently skip (and miss secrets in)
    deep files. No-op on POSIX.
    """
    if _IS_WIN:
        ap = os.path.abspath(path)
        if not ap.startswith("\\\\?\\"):
            return "\\\\?\\" + ap
        return ap
    return path

_TEXT_EXT = {
    ".java", ".kt", ".smali", ".xml", ".json", ".js", ".jsx", ".ts", ".html",
    ".htm", ".css", ".properties", ".txt", ".md", ".yaml", ".yml", ".cfg",
    ".conf", ".ini", ".env", ".gradle", ".pro", ".sql", ".graphql", ".proto",
    ".plist", ".strings", ".csv", ".sh", ".bat", ".ps1", ".py", ".rb", ".php",
    ".c", ".cc", ".cpp", ".h", ".m", ".mm", ".swift", ".go", ".pem", ".key",
    ".crt", ".cer", ".pub", ".jwt", ".toml", ".tsv", ".map", ".dart", ".hasm",
}
# never worth scanning (pure media / fonts) — saves time, no secrets live here
_SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".ttf", ".otf",
    ".woff", ".woff2", ".mp3", ".mp4", ".wav", ".ogg", ".m4a", ".aac", ".svg",
    ".jar", ".zip", ".apk", ".aar", ".tar", ".gz", ".tgz",   # already expanded
}
# file types where a high-entropy opaque string is plausibly a real secret
# (structured config), as opposed to code / compiled resources where entropy is
# mostly noise (resource ids, hashes, icon blobs, proguard artefacts).
_ENTROPY_EXT = {
    ".json", ".xml", ".properties", ".env", ".yml", ".yaml", ".plist", ".toml",
}
# code where a keyword-adjacent high-entropy token can still be a real secret,
# but which is noisier than config — scanned with the STRICT entropy bars. Raw
# .dex is deliberately EXCLUDED: smali is its disassembly and carries the same
# const-string literals, so scanning both would double the (costly) entropy pass
# on the largest input for no extra coverage. When smali is present it wins; if
# apktool failed, dex still gets vendor-rule + generic-secret coverage.
_CODE_ENTROPY_EXT = {
    ".java", ".kt", ".smali", ".js", ".jsx", ".ts",
}
# strict code-entropy is the most expensive pass on big smali trees; allow opting
# out (config-file entropy is unaffected).
_CODE_ENTROPY_ON = os.environ.get("SHIELDSCOPE_CODE_ENTROPY", "1") != "0"
_TEXT_READ_CAP = 24 * 1024 * 1024
_BIN_READ_CAP = 64 * 1024 * 1024
_STRINGS_MIN = 5
_PER_RULE_CAP = 40


# ---------------------------------------------------------------------------
#  binary string extraction (like `strings`, ASCII + UTF-16LE)
# ---------------------------------------------------------------------------
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % _STRINGS_MIN)
_UTF16_RUN = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % _STRINGS_MIN))


def _extract_strings(data):
    out = []
    for m in _ASCII_RUN.finditer(data):
        out.append(m.group(0).decode("ascii", "replace"))
    for m in _UTF16_RUN.finditer(data):
        out.append(m.group(0).decode("utf-16-le", "replace"))
    return "\n".join(out)


def _is_text_name(rel):
    ext = os.path.splitext(rel)[1].lower()
    if ext in _TEXT_EXT:
        return True
    if ext in _SKIP_EXT:
        return None  # skip entirely
    return False     # unknown -> treat as binary (strings pass)


def _sniff_text(head):
    if b"\x00" in head:
        return False
    nonprint = sum(1 for b in head if b < 9 or (13 < b < 32))
    return nonprint <= len(head) * 0.30


# ---------------------------------------------------------------------------
#  per-file scan
# ---------------------------------------------------------------------------
def _newline_index(text):
    """Offsets of all '\\n' — built once per file so line lookup is O(log n).

    The old per-hit text.count('\\n', 0, pos) was O(n) per hit, which turns
    quadratic on huge minified files (e.g. React Native index.android.bundle:
    megabytes of text, few newlines, thousands of keyword hits)."""
    nl, i = [], text.find("\n")
    while i != -1:
        nl.append(i)
        i = text.find("\n", i + 1)
    return nl


def _line_at(nl, pos):
    return bisect.bisect_right(nl, pos) + 1


def _scan_text(text, rel, add, entropy_ok=False, entropy_strict=False):
    """
    Anchor-dispatch scan: one cheap prefilter pass; each anchor hit runs only the
    specific rule(s) it implies, in a small window. Guarantees no missed match
    (every rule's true hit contains one of its anchors) at a fraction of the cost
    of matching every rule everywhere.

    `entropy_ok` enables the (noisy) high-entropy heuristic — only for config /
    resource files, since decompiled Java/smali is full of high-entropy strings
    (resource ids, hashes, proguard artefacts) that are not secrets.
    """
    per_rule = {}
    nl = None  # newline index, built lazily on first hit
    for am in R.PREFILTER.finditer(text):
        anchor = am.group(0).lower()
        rids = R.ANCHOR_TO_RULES.get(anchor)
        if not rids:
            continue
        if nl is None:
            nl = _newline_index(text)
        # back-window must cover values whose anchor sits at the END of the match
        # (e.g. https://<sub>.firebaseio.com — anchor "firebaseio" is near the tail)
        ws = max(0, am.start() - 128)
        we = min(len(text), am.end() + 220)
        window = text[ws:we]
        for rid in rids:
            if per_rule.get(rid, 0) >= _PER_RULE_CAP:
                continue
            name, sev, grp, kw_req = R.RULE_META[rid]
            m = R.COMPILED[rid].search(window)
            if not m:
                continue
            val = m.group(grp) if grp else m.group(0)
            if not val:
                continue
            val = val.strip()
            if rid == "private-key-block":
                end = text.find("-----END", ws + m.start())
                body = text[ws + m.start():end] if end != -1 else window
                if len(re.sub(r"[^A-Za-z0-9+/=]", "", body)) < 64:
                    continue
            elif R.looks_placeholder(val):
                continue
            if rid == "generic-secret" and R.reject_generic(val):
                continue
            if kw_req and not R.keyword_near(window, m.start(), m.end()):
                continue
            add(rid, name, sev, val, rel, _line_at(nl, ws + m.start()))
            per_rule[rid] = per_rule.get(rid, 0) + 1
        # entropy in the same window (only for generic keyword anchors, and only
        # in config/resource files — code is too noisy)
        if entropy_ok and anchor in R.ENTROPY_ANCHORS and per_rule.get("high-entropy", 0) < 20:
            er = R.entropy_in_window(window, strict=entropy_strict)
            if er:
                v, off, kind = er
                if not R.looks_placeholder(v):
                    add("high-entropy",
                        "High-entropy %s string (near a secret keyword)" % kind,
                        "low", v, rel, _line_at(nl, ws + off))
                    per_rule["high-entropy"] = per_rule.get("high-entropy", 0) + 1


def _should_scan_source(source, java_available, java_fallback=False):
    # smali is normally redundant once jadx Java exists, so it's skipped — BUT
    # when the Java came from the dex2jar+CFR fallback (java_fallback) it may be
    # incomplete, so smali is kept as well.
    if source == "smali":
        return (not java_available) or java_fallback
    return True


_SRC_TAG = {"java": "", "smali": " [smali]", "resource": " [res]", "package": "",
            "native": " [native]", "fwsrc": " [fw]"}


def _read_text(ap, kind):
    """Read a file as scannable text (decode, or strings-extract if binary)."""
    op = _op(ap)
    try:
        if kind is True:
            with open(op, "rb") as f:
                return f.read(_TEXT_READ_CAP).decode("utf-8", "replace")
        with open(op, "rb") as f:
            head = f.read(4096)
        if _sniff_text(head):
            with open(op, "rb") as f:
                return f.read(_TEXT_READ_CAP).decode("utf-8", "replace")
        with open(op, "rb") as f:
            data = f.read(_BIN_READ_CAP)
        return _extract_strings(data)
    except (OSError, MemoryError):
        return None


def _scan_one(job):
    """Worker: scan a batch of files, return (raw_hits, scanned_count).

    Runs in a separate process (module-level so it is picklable on Windows).
    Read + regex are both parallelised this way — the read latency is dominated
    by on-access AV scanning of thousands of files, which threads/processes hide.
    """
    local = {}

    def add(rid, name, sev, value, rel, line):
        key = (rid, value)
        g = local.get(key)
        loc = "%s:%d" % (rel, line) if line else rel
        if g is None:
            local[key] = {"rule": rid, "name": name, "severity": sev,
                          "value": value, "locations": [loc]}
        elif loc not in g["locations"] and len(g["locations"]) < 25:
            g["locations"].append(loc)

    scanned = 0
    for ap, rel, kind, tag in job:
        text = _read_text(ap, kind)
        if text:
            ext = os.path.splitext(rel)[1].lower()
            if ext in _ENTROPY_EXT:
                _scan_text(text, rel + tag, add, entropy_ok=True, entropy_strict=False)
            elif ext in _CODE_ENTROPY_EXT and _CODE_ENTROPY_ON:
                _scan_text(text, rel + tag, add, entropy_ok=True, entropy_strict=True)
            else:
                _scan_text(text, rel + tag, add, entropy_ok=False)
            scanned += 1
    return list(local.values()), scanned


def _class_stem(rel):
    """`com/foo/Bar$Inner.smali` -> `com/foo/bar` (top-level class, lowercased)."""
    r = rel.replace("\\", "/").lower()
    r = r.rsplit(".", 1)[0]              # drop extension
    return r.split("$", 1)[0]           # collapse nested/anon classes


def _plan(unpacked):
    """Build the list of (abs_path, rel, kind, tag) files to scan."""
    java_available = bool(unpacked.java_dir)
    java_fallback = getattr(unpacked, "java_is_fallback", False)
    entries = list(unpacked.iter_files())

    # In fallback mode we scan smali AND CFR-Java. Avoid scanning both copies of
    # the same class: build the set of classes CFR actually recovered, and scan
    # smali ONLY for classes CFR missed. This is the perf fix for the doubled
    # corpus (smali + Java) without losing coverage on CFR's failures.
    cfr_classes = set()
    if java_fallback:
        for _ap, rel, source in entries:
            if source == "java" and rel.lower().endswith(".java"):
                cfr_classes.add(_class_stem(rel))

    jobs = []
    for ap, rel, source in entries:
        if not _should_scan_source(source, java_available, java_fallback):
            continue
        if source == "smali" and java_fallback and rel.lower().endswith(".smali")                 and _class_stem(rel) in cfr_classes:
            continue                    # CFR already decompiled this class to Java
        kind = _is_text_name(rel)
        if kind is None:
            continue
        # dex strings are redundant with authoritative jadx Java, but NOT with
        # the CFR fallback (which can miss classes) — keep dex then.
        if source == "package" and java_available and not java_fallback                 and rel.lower().endswith(".dex"):
            continue
        jobs.append((ap, rel, kind, _SRC_TAG.get(source, "")))
    return jobs


def _merge(grouped, per_rule_distinct, hits, cap=300):
    for h in hits:
        key = (h["rule"], h["value"])
        g = grouped.get(key)
        if g is None:
            if per_rule_distinct.get(h["rule"], 0) >= cap:
                continue
            per_rule_distinct[h["rule"]] = per_rule_distinct.get(h["rule"], 0) + 1
            grouped[key] = h
        else:
            for loc in h["locations"]:
                if loc not in g["locations"] and len(g["locations"]) < 25:
                    g["locations"].append(loc)


def scan(unpacked, workers=None):
    """Return (raw_hits, files_scanned). Parallelised across processes."""
    jobs = _plan(unpacked)
    grouped, per_rule_distinct = {}, {}
    scanned = 0

    if workers is None:
        try:
            workers = max(2, min(8, (os.cpu_count() or 4)))
        except Exception:
            workers = 4

    chunk = max(64, (len(jobs) // (workers * 8)) or 1)
    batches = [jobs[i:i + chunk] for i in range(0, len(jobs), chunk)]

    # ProcessPool for real parallelism — the work is CPU-bound regex, which
    # threads can't parallelise under the GIL. Falls back to serial if a pool
    # can't be created (returns wrong-count-safe results either way).
    used_pool = False
    if workers > 1 and len(jobs) > 500:
        try:
            from concurrent.futures import ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=workers) as ex:
                for hits, n in ex.map(_scan_one, batches):
                    _merge(grouped, per_rule_distinct, hits)
                    scanned += n
            used_pool = True
        except Exception:
            used_pool = False

    if not used_pool:  # serial fallback
        for b in batches:
            hits, n = _scan_one(b)
            _merge(grouped, per_rule_distinct, hits)
            scanned += n

    return list(grouped.values()), scanned


# ---------------------------------------------------------------------------
#  raw hits -> rich, located findings (schema consumed by the UI/report)
# ---------------------------------------------------------------------------
_BASE_RISK = ("APKs are trivial to unpack (`apktool d` / `unzip`), so anything embedded is "
              "readable by anyone. A hardcoded credential can be used directly and cannot be "
              "rotated without shipping an app update — assume it is already compromised.")
_REPRO = [
    "Unpack the app: `apktool d app.apk` (or `unzip app.apk`).",
    "Search for the value: `grep -rF '<value>' .` in the shown file.",
    "Use the credential against its service to confirm it is live (authorized scope only).",
]
_MIT = ("Remove the secret from the client — proxy privileged calls through your backend so the "
        "key never ships; if a token must live on-device, issue short-lived per-user tokens. "
        "Rotate/revoke the exposed credential now.")

# rule id -> MASVS id
_MASVS = {"private-key-block": "MASVS-CRYPTO-1", "jwt": "MASVS-AUTH-1",
          "high-entropy": "MASVS-STORAGE-1", "basic-auth-url": "MASVS-NETWORK-1"}


def _prose(rule, name):
    desc = "A hardcoded %s was found in the app package." % name.lower()
    risk = _BASE_RISK
    if rule.startswith(("aws", "gcp")):
        risk = "Grants direct access to cloud resources (S3, compute, data). " + _BASE_RISK
    elif rule.startswith(("stripe", "square", "braintree", "paypal")):
        risk = "Allows server-side control of the payment account (charges, refunds, customer data). " + _BASE_RISK
    elif rule.endswith("-uri") or rule == "basic-auth-url":
        risk = "Embeds live database/service credentials — direct data access if the host is reachable. " + _BASE_RISK
    elif rule == "private-key-block":
        desc = "A private key (RSA/EC/OpenSSH/PGP) is embedded in the app."
        risk = "Whoever extracts it can impersonate the app/server, forge signatures, or decrypt protected data. " + _BASE_RISK
    elif rule == "jwt":
        risk = "If still valid the token may grant authenticated access; its claims also leak internal structure. " + _BASE_RISK
    elif rule == "high-entropy":
        desc = "A high-entropy opaque string sits next to a secret-like keyword — a likely credential."
        risk = "If this is a live key/token it is extractable by anyone who unpacks the app. Verify it is real, not a hash/id. " + _BASE_RISK
    return desc, risk


def build_findings(raw_hits):
    """Convert deduped raw hits into rich findings sorted by severity."""
    from . import jwtscan
    out = []
    for h in raw_hits:
        rule, name, sev = h["rule"], h["name"], h["severity"]
        locs = h["locations"]
        loc = locs[0] + (" (+%d more)" % (len(locs) - 1) if len(locs) > 1 else "")
        desc, risk = _prose(rule, name)
        finding = {
            "id": "secret-" + re.sub(r"\W+", "-", (rule + "-" + h["value"][:8]).lower()),
            "rule": rule,
            "title": ("Likely secret: " if rule == "high-entropy" else "Hardcoded secret: ") + name,
            "severity": sev, "category": "secret",
            "location": loc, "evidence": h["value"],
            "description": desc, "risk": risk, "reproduce": _REPRO, "mitigation": _MIT,
            "masvs": _MASVS.get(rule, "MASVS-STORAGE-1"),
        }
        # decode JWTs and fold the analysis into the finding
        if rule == "jwt":
            decoded = jwtscan.decode_jwt(h["value"])
            if decoded:
                finding["jwt"] = decoded
                if decoded["issues"]:
                    finding["risk"] = "Decoded — " + " ".join(decoded["issues"]) + " " + finding["risk"]
                if decoded.get("sensitive_claims"):
                    finding["description"] += (" Carries claims: %s."
                                               % ", ".join(decoded["sensitive_claims"]))
        out.append(finding)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    out.sort(key=lambda f: order.get(f["severity"], 9))
    return out

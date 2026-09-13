"""
Secret-detection ruleset + entropy heuristics for the deep scanner.

Two detection strategies, combined:

  1. VENDOR RULES — ~60 precise regexes for well-known credential formats
     (cloud, payment, VCS, messaging, AI, DB URIs, private keys...). These are
     high-precision: a hit is almost always a real credential of that type.

  2. ENTROPY — for prefix-less secrets (random API keys with no vendor marker),
     a Shannon-entropy test over long base64/hex tokens, gated by a nearby
     sensitive keyword to keep false positives down.

Each rule: (id, name, severity, compiled_regex, group, keyword_required).
`group` = which regex group holds the value (0 = whole match).
`keyword_required` = only accept if a sensitive word sits near the match.

All matching is done on text (files are decoded utf-8/replace; binaries are
run through a strings pass first), so rules are plain `str` regexes.
"""

import math
import re

# ---------------------------------------------------------------------------
#  vendor rules
# ---------------------------------------------------------------------------
# Each rule: (id, name, severity, pattern_str, ignorecase, group, kw_required)
#   group        = capture group holding the value (0 = whole match)
#   kw_required  = only accept if a sensitive keyword sits near the match
# Quantifiers are bounded to avoid catastrophic backtracking on large files.
# All rules are compiled individually AND fused into one MASTER regex so a file
# is scanned in a single pass instead of once per rule (huge speedup).
_RULE_DEFS = [
    # ---- AWS ----
    ("aws-access-key", "AWS access key id", "high",
     r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16}\b", False, 0, False),
    ("aws-secret-key", "AWS secret access key", "high",
     r"aws[^\n]{0,40}?['\"]([A-Za-z0-9/+]{40})['\"]", True, 1, False),
    ("aws-mws-token", "Amazon MWS auth token", "high",
     r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", False, 0, False),

    # ---- Google / Firebase / GCP ----
    ("google-api-key", "Google API key", "high",
     r"\bAIza[0-9A-Za-z_\-]{35}\b", False, 0, False),
    ("google-oauth-token", "Google OAuth access token", "high",
     r"\bya29\.[0-9A-Za-z_\-]{20,}", False, 0, False),
    ("gcp-sa-private-key", "GCP service-account key (JSON private_key)", "high",
     r'"private_key"\s*:\s*"-----BEGIN', False, 0, False),
    ("firebase-db-url", "Firebase database URL", "medium",
     r"https?://[a-z0-9.\-]+\.firebaseio\.com", False, 0, False),
    ("firebase-fcm-key", "Firebase Cloud Messaging server key", "high",
     r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{130,}", False, 0, False),

    # ---- payment ----
    ("stripe-secret", "Stripe secret key", "high",
     r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b", False, 0, False),
    ("stripe-publishable", "Stripe publishable key", "low",
     r"\bpk_live_[0-9a-zA-Z]{20,}\b", False, 0, False),
    ("square-access", "Square access token", "high",
     r"\bsq0atp-[0-9A-Za-z_\-]{22}\b", False, 0, False),
    ("square-oauth", "Square OAuth secret", "high",
     r"\bsq0csp-[0-9A-Za-z_\-]{43}\b", False, 0, False),
    ("braintree-token", "Braintree production access token", "high",
     r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}", False, 0, False),
    ("paypal-client", "PayPal/Braintree client token", "medium",
     r"\bA21AA[0-9A-Za-z_\-]{20,}", False, 0, False),

    # ---- VCS / CI ----
    ("github-pat", "GitHub personal access token", "high",
     r"\bgh[pousr]_[0-9A-Za-z]{36}\b", False, 0, False),
    ("github-fine-pat", "GitHub fine-grained PAT", "high",
     r"\bgithub_pat_[0-9A-Za-z_]{60,}\b", False, 0, False),
    ("gitlab-pat", "GitLab personal access token", "high",
     r"\bglpat-[0-9A-Za-z_\-]{20}\b", False, 0, False),
    ("npm-token", "npm access token", "high",
     r"\bnpm_[0-9A-Za-z]{36}\b", False, 0, False),
    ("pypi-token", "PyPI upload token", "high",
     r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,}", False, 0, False),

    # ---- messaging / comms ----
    ("slack-token", "Slack token", "high",
     r"\bxox[baprs]-[0-9A-Za-z\-]{10,}", False, 0, False),
    ("slack-webhook", "Slack incoming webhook", "high",
     r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+", False, 0, False),
    ("twilio-key", "Twilio API key SID", "high",
     r"\bSK[0-9a-fA-F]{32}\b", False, 0, True),
    ("sendgrid-key", "SendGrid API key", "high",
     r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b", False, 0, False),
    ("mailgun-key", "Mailgun API key", "high",
     r"\bkey-[0-9a-f]{32}\b", False, 0, True),
    ("mailchimp-key", "Mailchimp API key", "high",
     r"\b[0-9a-f]{32}-us[0-9]{1,2}\b", False, 0, False),
    ("facebook-token", "Facebook access token", "high",
     r"\bEAA[0-9A-Za-z]{80,}", False, 0, False),
    ("discord-bot", "Discord bot token", "high",
     r"\b[MNO][A-Za-z0-9_\-]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}", False, 0, False),
    ("discord-webhook", "Discord webhook URL", "medium",
     r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[0-9A-Za-z_\-]+", False, 0, False),
    ("telegram-bot", "Telegram bot token", "high",
     r"\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{32,}\b", False, 0, False),

    # ---- AI providers ----
    ("openai-key", "OpenAI API key", "high",
     r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20}T3BlbkFJ[A-Za-z0-9_\-]{20,}", False, 0, False),
    ("anthropic-key", "Anthropic API key", "high",
     r"\bsk-ant-[A-Za-z0-9\-_]{80,}", False, 0, False),
    ("huggingface-token", "Hugging Face access token", "high",
     r"\bhf_[A-Za-z0-9]{34}\b", False, 0, False),

    # ---- maps / misc SaaS ----
    ("mapbox-token", "Mapbox token", "low",
     r"\b(?:sk|pk)\.eyJ[0-9A-Za-z_\-]{20,}\.[0-9A-Za-z_\-]{20,}", False, 0, False),
    ("algolia-admin", "Algolia admin API key", "high",
     r"algolia[^\n]{0,40}?['\"]([0-9a-f]{32})['\"]", True, 1, False),
    ("cloudinary-url", "Cloudinary URL (with secret)", "high",
     r"cloudinary://[0-9]{10,}:[0-9A-Za-z_\-]+@[0-9A-Za-z_\-]+", False, 0, False),
    ("heroku-key", "Heroku API key", "high",
     r"heroku[^\n]{0,30}?['\"]([0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12})['\"]", True, 1, False),

    # ---- Azure ----
    ("azure-storage-conn", "Azure Storage connection string", "high",
     r"DefaultEndpointsProtocol=https?;AccountName=[0-9a-z]+;AccountKey=[0-9A-Za-z+/=]{80,}", False, 0, False),
    ("azure-sql-conn", "SQL connection string with password", "high",
     r"(?:Server|Data Source)=[^\n;]+;[^\n]{0,200}?Password=[^\n;]{6,}", True, 0, False),

    # ---- database URIs with embedded creds ----
    ("mongodb-uri", "MongoDB URI with credentials", "high",
     r"mongodb(?:\+srv)?://[^\s:@/]+:[^\s:@/]{3,}@[0-9A-Za-z.\-]+", False, 0, False),
    ("postgres-uri", "Postgres URI with credentials", "high",
     r"postgres(?:ql)?://[^\s:@/]+:[^\s:@/]{3,}@[0-9A-Za-z.\-]+", False, 0, False),
    ("mysql-uri", "MySQL URI with credentials", "high",
     r"mysql://[^\s:@/]+:[^\s:@/]{3,}@[0-9A-Za-z.\-]+", False, 0, False),
    ("redis-uri", "Redis URI with credentials", "high",
     r"redis://[^\s:@/]*:[^\s:@/]{3,}@[0-9A-Za-z.\-]+", False, 0, False),
    ("amqp-uri", "AMQP/RabbitMQ URI with credentials", "high",
     r"amqps?://[^\s:@/]+:[^\s:@/]{3,}@[0-9A-Za-z.\-]+", False, 0, False),
    ("basic-auth-url", "HTTP URL with basic-auth credentials", "high",
     r"https?://[^\s:@/]{1,40}:[^\s:@/]{3,40}@[0-9A-Za-z.\-]+", False, 0, False),

    # ---- tokens / keys (generic but structured) ----
    ("jwt", "JSON Web Token", "medium",
     r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}", False, 0, False),
    ("bearer-token", "Bearer token in code", "medium",
     r"\bbearer\s+([A-Za-z0-9._\-]{20,})", True, 1, False),
    ("private-key-block", "Private key block (PEM)", "high",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", False, 0, False),

    # ---- generic assignment (needs keyword + verify) ----
    ("generic-secret", "Generic hardcoded secret/password", "medium",
     r"(?:api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?token|"
     r"auth[_-]?token|password|passwd|pwd|private[_-]?key)['\"]?\s*[:=]\s*"
     r"['\"]([0-9A-Za-z._\-/+!@#$%^&*]{8,80})['\"]", True, 1, True),
]

# id -> (name, severity, group, kw_required)
RULE_META = {r[0]: (r[1], r[2], r[5], r[6]) for r in _RULE_DEFS}
# id -> individually compiled regex (used to extract the value from a hit span)
COMPILED = {r[0]: re.compile(r[3], re.IGNORECASE if r[4] else 0) for r in _RULE_DEFS}
RULE_IDS = [r[0] for r in _RULE_DEFS]

# ---------------------------------------------------------------------------
#  anchor dispatch  (the performance core)
# ---------------------------------------------------------------------------
# A 55-way regex over a 160 MB decompiled tree is ~4 minutes in CPython. Instead
# we run ONE cheap "anchor" prefilter; each anchor hit tells us the ONE rule to
# actually evaluate, in a small window around the hit. Every rule's true match
# is guaranteed to contain one of its anchors, so nothing is missed.
#
# ANCHOR_TO_RULES: lowercased anchor substring -> list of rule ids to try.
# ENTROPY_ANCHORS: anchors that also trigger a high-entropy check in the window.
ANCHOR_TO_RULES = {}


def _anch(anchor, *rule_ids):
    ANCHOR_TO_RULES.setdefault(anchor.lower(), []).extend(rule_ids)


# distinctive token literals -> exact rule
for _a in ("AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA"):
    _anch(_a, "aws-access-key")
_anch("amzn.mws.", "aws-mws-token")
_anch("AIza", "google-api-key")
_anch("ya29.", "google-oauth-token")
_anch("firebaseio", "firebase-db-url")
_anch("sk_live_", "stripe-secret"); _anch("rk_live_", "stripe-secret")
_anch("pk_live_", "stripe-publishable")
_anch("sq0atp-", "square-access"); _anch("sq0csp-", "square-oauth")
_anch("access_token$production$", "braintree-token")
_anch("A21AA", "paypal-client")
for _a in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
    _anch(_a, "github-pat")
_anch("github_pat_", "github-fine-pat")
_anch("glpat-", "gitlab-pat")
_anch("npm_", "npm-token")
_anch("pypi-", "pypi-token")
_anch("xox", "slack-token")
_anch("hooks.slack.com", "slack-webhook")
_anch("SG.", "sendgrid-key")
_anch("key-", "mailgun-key")
_anch("EAA", "facebook-token")
_anch("discord", "discord-webhook", "discord-bot")
_anch("T3BlbkFJ", "openai-key")
_anch("sk-ant-", "anthropic-key")
_anch("hf_", "huggingface-token")
_anch("cloudinary://", "cloudinary-url")
_anch("defaultendpointsprotocol", "azure-storage-conn")
_anch("data source=", "azure-sql-conn"); _anch("password=", "azure-sql-conn")
_anch("mongodb", "mongodb-uri")
_anch("postgres", "postgres-uri")
_anch("mysql://", "mysql-uri")
_anch("redis://", "redis-uri")
_anch("amqp", "amqp-uri")
_anch("eyJ", "jwt", "mapbox-token")
_anch("-----begin", "private-key-block", "gcp-sa-private-key")
_anch("AAAA", "firebase-fcm-key")
# rules that previously had NO anchor and so never fired — route them here
_anch("SK", "twilio-key")               # Twilio key SID: SK + 32 hex
_anch("-us", "mailchimp-key")           # Mailchimp: 32-hex-<dc>, e.g. ...-us21
_anch(":AA", "telegram-bot")            # Telegram bot token: <id>:AA...
_anch("://", "basic-auth-url")          # user:pass@host in an http(s) URL
# contextual anchors
_anch("aws", "aws-secret-key")
_anch("algolia", "algolia-admin")
_anch("heroku", "heroku-key")
_anch("bearer", "bearer-token")
# generic secret/password assignment + entropy
_GENERIC_KW = ("api_key", "apikey", "api-key", "secret", "password", "passwd",
               "pwd", "access_token", "auth_token", "authtoken", "client_secret",
               "private_key", "privatekey", "credential", "token", "auth")
for _a in _GENERIC_KW:
    _anch(_a, "generic-secret")

ENTROPY_ANCHORS = set(a.lower() for a in _GENERIC_KW)

# one prefilter regex; longer anchors first so alternation prefers them
_ANCHOR_LIST = sorted(ANCHOR_TO_RULES.keys(), key=len, reverse=True)
PREFILTER = re.compile("|".join(re.escape(a) for a in _ANCHOR_LIST), re.IGNORECASE)

# ---------------------------------------------------------------------------
#  false-positive filter
# ---------------------------------------------------------------------------
# word / marker placeholders — matched as substrings (an "example_key" IS junk)
_PLACEHOLDER = re.compile(
    r"(?i)(example|placeholder|your[_-]?|change[_-]?me|dummy|sample|redacted|"
    r"xxxx+|\.\.\.|<[a-z_]+>|\{\{|\$\{|test[_-]?(key|token|secret|password)|"
    r"insert[_-]?|todo|fixme|lorem|foobar|password123|s3cr3t|notreal|fake)")

# whole-value trivial fillers: the ENTIRE value is a sequential / hex / repeated
# dummy (anchored with fullmatch), so we drop "123456" / "abcdefabcdef" /
# "deadbeef" but keep a real secret that merely CONTAINS such a run
# (e.g. "S3cr3t123456Ab" or a Telegram id like "8093407781:AA…"). Previously
# these were substring-matched, silently discarding real keys/tokens.
_FILLER = re.compile(
    r"(?i)^(?:0x)?(?:1234567890|123456789|1234567|123456|abcdef|deadbeef|"
    r"cafebabe|0+|1+|f+)+$")

# monotonic keyboard/hex sequences ("12345678", "0123456789", "abcdefgh", and
# their reverses) — junk, but not a clean repeat unit, so caught separately.
_SEQ_FWD = "0123456789" * 2 + "abcdefghijklmnopqrstuvwxyz"
_SEQ_REV = _SEQ_FWD[::-1]


def _is_sequential(v):
    lv = v.lower()
    return len(lv) >= 6 and (lv in _SEQ_FWD or lv in _SEQ_REV)

# common non-secret strings that look structured
_KNOWN_JUNK = {
    "androidx", "com.google.android", "http://schemas.android.com",
}

_SENSITIVE_KW = re.compile(
    r"(?i)(secret|token|passw|pwd|api[_-]?key|apikey|auth|credential|private|"
    r"access[_-]?key|client[_-]?secret|bearer|session|signing|encrypt)")


def looks_placeholder(value):
    v = (value or "").strip()
    if len(v) < 8:
        return True
    if _PLACEHOLDER.search(v):
        return True
    # the whole value is a sequential/hex dummy filler (anchored, not incidental)
    if _FILLER.fullmatch(v) or _is_sequential(v):
        return True
    # a value that is a single repeated char, or all identical, is junk
    if len(set(v)) <= 3:
        return True
    # pure lowercase words (no digits, no separators) are usually identifiers
    if v.isalpha() and v.islower():
        return True
    return False


_IDENT_RE = re.compile(r"[A-Za-z][A-Za-z0-9]*")


def reject_generic(v):
    """
    Extra filter for the noisy generic assignment rule: drop values that are
    clearly NOT secrets — endpoint paths, sentences, header names, and code
    identifiers / enum constants (visible-password, oauth_token, newPassword,
    X-Algolia-API-Key, api/forget/v1/password ...). Real secrets carry random
    mixed-case+digits and don't look like clean identifiers or paths.
    """
    if "/" in v or " " in v or "." in v:
        return True                       # path / endpoint / sentence / dotted name
    if "-" in v and not any(c.isdigit() for c in v):
        return True                       # hyphenated words: visible-password, X-Algolia-API-Key
    if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", v):
        if "_" in v:
            return True                   # snake/const identifier: oauth_token, NEED_PASSWORD
        if v.isalpha():
            return True                   # camel/word: newPassword, PASSWORD, onSessionNeed
    return False


def keyword_near(text, start, end, window=48):
    lo = max(0, start - window)
    hi = min(len(text), end + window)
    return bool(_SENSITIVE_KW.search(text[lo:hi]))


# ---------------------------------------------------------------------------
#  entropy
# ---------------------------------------------------------------------------
# Deliberately EXCLUDES '_' and '-': snake_case / Word_Word identifiers (i18n
# keys, code symbols) are the main entropy false-positive source, and dropping
# those separators makes such identifiers split below the length threshold while
# leaving real base64/hex tokens intact.
_NEAR_TOKEN = re.compile(r"['\"=:\s]([A-Za-z0-9+/]{20,120})['\"]?")


def shannon(s):
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def entropy_in_window(window, strict=False):
    """
    Return (value, offset, kind) for the first high-entropy token in a window
    around a sensitive keyword, else None. Called once per keyword anchor hit.

    `strict` raises the length / entropy / digit bars. It is used when scanning
    CODE (decompiled Java, smali, dex strings, JS), which is full of high-entropy
    non-secrets (resource ids, hashes, proguard artefacts); config/resource files
    use the looser bars. Both paths stay keyword-gated by the anchor dispatch.
    """
    m = _NEAR_TOKEN.search(window)
    if not m:
        return None
    v = m.group(1)
    if len(v) < 20:
        return None
    is_hex = all(c in "0123456789abcdefABCDEF" for c in v)
    if is_hex:
        min_len, min_ent = (48, 3.3) if strict else (40, 3.0)
        if len(v) >= min_len and shannon(v) >= min_ent:
            return v, m.start(1), "hex"
    else:
        # a real random base64 key almost always carries a few digits; an
        # all-alpha CamelCase blob is far more likely a word/identifier
        digits = sum(c.isdigit() for c in v)
        min_len, min_ent, min_dig = (32, 4.3, 3) if strict else (20, 4.0, 2)
        if len(v) >= min_len and shannon(v) >= min_ent and digits >= min_dig:
            return v, m.start(1), "base64"
    return None

"""Unit tests for the secret detection core (no APK / tools needed)."""

from analyzer import secret_rules as R
from analyzer import deepscan


def _scan(text, entropy_ok=False):
    """Run the anchor-dispatch scan over a string, return {rule: [values]}."""
    hits = {}

    def add(rid, name, sev, value, rel, line):
        hits.setdefault(rid, []).append(value)

    deepscan._scan_text(text, "x.java", add, entropy_ok=entropy_ok)
    return hits


# ---- reject_generic: the false-positive filter ----
import pytest


@pytest.mark.parametrize("val", [
    "visible-password", "oauth_token", "password-new", "newPassword", "PASSWORD",
    "ZoomVideoSDKError_Session_Need_Password", "onSessionNeedPassword",
    "X-Algolia-API-Key", "api/forget/v1/password", "mobilybe/rest/myprofile/password",
])
def test_reject_generic_drops_identifiers_and_paths(val):
    assert R.reject_generic(val) is True


@pytest.mark.parametrize("val", [
    "P@ssw0rd123!", "aB3xY9kLm2Qr7", "47cb3659b55da73d6ca4a87ba4ba981",
])
def test_reject_generic_keeps_real_secrets(val):
    assert R.reject_generic(val) is False


# ---- vendor rules fire on real tokens ----
def test_detects_google_api_key():
    gkey = "AIza" + ("A1b2C3d4" * 5)[:35]   # AIza + exactly 35 chars
    hits = _scan('String k = "%s";' % gkey)
    assert "google-api-key" in hits


def test_detects_aws_access_key():
    akey = "AKIA" + ("A1B2C3D4" * 2)[:16]   # AKIA + exactly 16 upper/digit
    hits = _scan('final id = "%s";' % akey)
    assert "aws-access-key" in hits


def test_detects_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + ("MIIB" + "a" * 200) + "\n-----END RSA PRIVATE KEY-----"
    hits = _scan(pem)
    assert "private-key-block" in hits


def test_detects_generic_password_assignment():
    hits = _scan('password = "Sup3rSecret!value"')
    assert "generic-secret" in hits


def test_generic_ignores_identifier_value():
    # value is a clean identifier -> filtered, no generic-secret hit
    hits = _scan('password = "newPassword"')
    assert "generic-secret" not in hits


def test_placeholder_is_skipped():
    hits = _scan('apiKey = "YOUR_API_KEY_HERE"')
    assert "generic-secret" not in hits


# ---- entropy is gated to config files only ----
def test_entropy_only_when_enabled():
    text = 'token = "aZ3xK9mQ2wE7rT1yU4iO6pS8dF0gH5j"'
    assert "high-entropy" not in _scan(text, entropy_ok=False)


# ---- placeholder helper ----
def test_looks_placeholder():
    assert R.looks_placeholder("changeme")
    assert R.looks_placeholder("xxxxxxxx")
    assert not R.looks_placeholder("aB3xY9kLm2Qr7")


def _scan_code(text):
    """Run the scan with STRICT code-entropy enabled (as _scan_one does for code)."""
    hits = {}

    def add(rid, name, sev, value, rel, line):
        hits.setdefault(rid, []).append(value)

    deepscan._scan_text(text, "x.java", add, entropy_ok=True, entropy_strict=True)
    return hits


# ---- false-negative filter fixes ----
def test_telegram_with_sequential_id_not_placeholder():
    # a real bot id containing "123456" must no longer be dropped as a placeholder
    assert not R.looks_placeholder("8091234567:AAF9zQ2wxE7rT1yU4iO6pS8dF0gH5jK3lM9n")


def test_whole_value_fillers_still_rejected():
    for v in ("123456", "12345678", "abcdefabcdef", "deadbeef", "00000000", "ffffffff"):
        assert R.looks_placeholder(v), v


def test_real_key_containing_filler_run_kept():
    # contains "123456" and "abcdef" as substrings but is a real-looking key
    assert not R.looks_placeholder("Kp9x123456AbCdQmZ7wT")


# ---- previously-dead rules now reachable ----
def test_basic_auth_url_detected():
    hits = _scan('String u = "https://admin:S3cretPass@internal.corp.acme-corp.io/db";')
    assert "basic-auth-url" in hits


def test_every_rule_reachable_by_anchor():
    routed = set()
    for rids in R.ANCHOR_TO_RULES.values():
        routed.update(rids)
    assert set(R.RULE_IDS) <= routed, "unroutable rules: %s" % (set(R.RULE_IDS) - routed)


# ---- keyword-gated entropy now runs on code (strict) ----
def test_code_entropy_strict_fires_near_keyword():
    hits = _scan_code('String secret = "aZ3xK9mQ2wE7rT1yU4iO6pS8dF0gH5jB2nC4v";')
    assert "high-entropy" in hits

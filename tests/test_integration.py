"""
Integration tests — run the REAL engine end to end on sample APKs and assert on
known-true facts. Slow (minutes) and require jadx/apktool + the APKs, so they are
marked `integration` and auto-skip when prerequisites are missing.

Run with:  pytest -m integration
"""

import pytest

from analyzer import analyze_file
from analyzer import tools as T


def _require_tools():
    t = T.get_tools()
    if not (t.have_apktool and t.have_jadx):
        pytest.skip("jadx/apktool not available")


def _findings(result):
    return result.get("extra", []) or []


@pytest.mark.integration
def test_roboform_end_to_end(robo_apk):
    _require_tools()
    r = analyze_file(robo_apk, original_name="RoboForm.apk")
    assert r["ok"] and r["platform"] == "android"
    # a real, known secret is recovered
    secrets = [f["evidence"] for f in _findings(r) if f["category"] == "secret"]
    assert any(v.startswith("AIzaSy") for v in secrets), "Google API key should be found"
    # detection is obfuscation-resilient: multiple root layers present
    assert r["root"]["layers"] >= 3
    # SSL mechanisms are collapsed, not inflated
    assert r["ssl"]["layers"] <= 6


@pytest.mark.integration
def test_mobily_end_to_end(mobily_apk):
    _require_tools()
    r = analyze_file(mobily_apk, original_name="Mobily.apk")
    assert r["ok"]
    f = _findings(r)
    # the guest/unauthenticated access path (the previously-missed critical)
    assert any(x["id"] == "auth-guest-access" for x in f), "guest access path should be flagged"
    # a trust-all TrustManager is reported as a vulnerability
    assert any(str(x.get("id", "")).startswith("trustall-") for x in f)
    # SSL layers collapsed (regression guard against the '34 layers' bug)
    assert r["ssl"]["layers"] <= 6
    # API surface harvested with at least one sensitive endpoint
    assert r.get("api", {}).get("counts", {}).get("sensitive", 0) >= 1
    # a real embedded secret is found
    secrets = [x["evidence"] for x in f if x["category"] == "secret"]
    assert any(v.startswith("AIzaSy") for v in secrets)

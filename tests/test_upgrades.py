"""Tests for the newer upgrades: secret validation, fallback dedupe, result
cache, iOS entitlements, Hermes detection."""

import io
import json
import os
import zipfile

import plistlib

from analyzer import validate as V
from analyzer import deepscan
from analyzer import report
from analyzer import ipa
from analyzer import unpack


# ---- secret liveness validation ----
def test_validators_cover_expected_rules():
    got = set(V.validators_for())
    assert {"github-pat", "stripe-secret", "telegram-bot", "google-api-key"} <= got


def test_validate_promotes_live_and_marks_invalid(monkeypatch):
    def fake_req(method, url, headers=None, data=None):
        if "api.github.com" in url:
            return (200, "")
        if "gitlab.com" in url:
            return (401, "")
        return (0, "")
    monkeypatch.setattr(V, "_req", fake_req)
    result = {"extra": [
        {"category": "secret", "rule": "github-pat", "evidence": "ghp_x",
         "title": "Hardcoded secret: GitHub PAT", "severity": "high", "risk": "r"},
        {"category": "secret", "rule": "gitlab-pat", "evidence": "glpat-x",
         "title": "Hardcoded secret: GitLab PAT", "severity": "high", "risk": "r"},
    ]}
    V.validate_result(result)
    gh = [f for f in result["extra"] if f["rule"] == "github-pat"][0]
    gl = [f for f in result["extra"] if f["rule"] == "gitlab-pat"][0]
    assert gh["validated"] == "live" and gh["title"].startswith("CONFIRMED LIVE")
    assert gl["validated"] == "invalid"
    assert result["secret_validation"]["live"] == 1


# ---- fallback dedupe (smali classes CFR already recovered are skipped) ----
def test_class_stem_collapses_nested_and_ext():
    assert deepscan._class_stem("com/foo/Bar$Inner.smali") == "com/foo/bar"
    assert deepscan._class_stem("com/foo/Bar.java") == "com/foo/bar"


def test_plan_skips_smali_covered_by_cfr(tmp_path):
    # build a fake unpacked with one smali dir and one CFR java dir sharing a class
    up = unpack.Unpacked(str(tmp_path))
    os.makedirs(up.raw_dir, exist_ok=True)
    sd = tmp_path / "smali"
    (sd / "com" / "foo").mkdir(parents=True)
    (sd / "com" / "foo" / "Bar.smali").write_text(".class Lcom/foo/Bar;", encoding="utf-8")
    (sd / "com" / "foo" / "Baz.smali").write_text(".class Lcom/foo/Baz;", encoding="utf-8")
    jd = tmp_path / "java"
    (jd / "com" / "foo").mkdir(parents=True)
    (jd / "com" / "foo" / "Bar.java").write_text("class Bar {}", encoding="utf-8")
    up.smali_dirs = [str(sd)]
    up.java_dir = str(jd)
    up.java_is_fallback = True
    rels = {rel for _ap, rel, _kind, _tag in deepscan._plan(up)}
    # Bar.smali is covered by Bar.java -> skipped; Baz.smali kept; Bar.java scanned
    assert "com/foo/Baz.smali" in rels
    assert "com/foo/Bar.smali" not in rels
    assert "com/foo/Bar.java" in rels


# ---- result cache ----
def test_cache_roundtrip_and_engine_invalidation(tmp_path, monkeypatch):
    monkeypatch.setenv("SHIELDSCOPE_CACHE_DIR", str(tmp_path))
    sha = "a" * 64
    report._cache_store(sha, {"ok": True, "score": 42})
    got = report._cache_load(sha)
    assert got and got["score"] == 42
    # a file written under a different engine version must be ignored
    with open(tmp_path / (("b" * 64) + ".json"), "w", encoding="utf-8") as f:
        json.dump({"engine": "OLD", "result": {"score": 1}}, f)
    assert report._cache_load("b" * 64) is None


# ---- iOS entitlements ----
def test_ios_get_task_allow_flagged():
    pl = {"Entitlements": {"get-task-allow": True,
                           "application-identifier": "ABCDE.com.x.*"}}
    body = b"0\x82cms-wrapper" + plistlib.dumps(pl) + b"trailer"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Payload/X.app/embedded.mobileprovision", body)
    buf.seek(0)
    with zipfile.ZipFile(buf) as z:
        F = ipa._entitlements_findings(z, "Payload/X.app", z.namelist())
    ids = {f["id"] for f in F}
    assert "ios-get-task-allow" in ids
    assert "ios-wildcard-appid" in ids


# ---- Hermes bundle detection ----
def test_hermes_magic_detection(tmp_path):
    raw = tmp_path / "raw"
    (raw / "assets").mkdir(parents=True)
    good = raw / "assets" / "index.android.bundle"
    good.write_bytes(unpack._HERMES_MAGIC + b"\x00" * 64)
    plain = raw / "assets" / "plain.bundle"
    plain.write_bytes(b"// just javascript\n")
    found = unpack._find_hermes_bundles(str(raw))
    assert str(good) in found and str(plain) not in found

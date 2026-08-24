"""Unit tests for the AI Frida bypass agent (mocked model + mocked device)."""

import pytest

from ai import frida_agent as FA
from ai.config import AIConfig


class MockRunner:
    """Fails (no hook markers) on the first N runs, then succeeds."""
    def __init__(self, succeed_on=2):
        self.calls = 0
        self.succeed_on = succeed_on

    def run_script(self, package, js, **kw):
        self.calls += 1
        if self.calls >= self.succeed_on:
            return {"ok": True, "loaded": True, "console": ["[+] bypassed"],
                    "errors": [], "markers": ["[+] bypassed"]}
        return {"ok": True, "loaded": True, "console": ["loaded"], "errors": [], "markers": []}


def _cfg():
    return AIConfig(provider="ollama", base_url="http://x/v1", model="m")


def _fake_chat(system, user, cfg=None, **kw):
    return "Plan.\n```javascript\nconsole.log('[+] bypassed');\n```"


def test_flutter_uses_ai_first_and_iterates(monkeypatch):
    monkeypatch.setattr("ai.provider.chat", _fake_chat)
    res = {"meta": {"package": "com.f.app"},
           "frameworks": [{"id": "flutter", "name": "Flutter"}],
           "discovered": {"custom_tm": [], "trust_all": []},
           "root": {"mechanisms": []}, "ssl": {"mechanisms": []},
           "frida": {"script": "// java baseline"}}
    out = FA.bypass(res, "com.f.app", goal="ssl", cfg=_cfg(),
                    runner=MockRunner(succeed_on=2), max_iters=4, collect_seconds=0)
    assert out["flutter"] is True
    assert out["confirmed"] is True
    assert len(out["iterations"]) == 2               # failed once, succeeded on refine
    assert out["iterations"][0]["ai_notes"] != "deterministic baseline script"


def test_native_starts_from_deterministic_baseline(monkeypatch):
    monkeypatch.setattr("ai.provider.chat", _fake_chat)
    res = {"meta": {"package": "com.n.app"}, "frameworks": [],
           "discovered": {"custom_tm": ["dj.d"], "trust_all": []},
           "root": {"mechanisms": []},
           "ssl": {"mechanisms": [{"id": "okhttp-pinner", "name": "OkHttp", "layer": "java"}]},
           "frida": {"script": "console.log('baseline')"}}
    out = FA.bypass(res, "com.n.app", goal="ssl", cfg=_cfg(),
                    runner=MockRunner(succeed_on=2), max_iters=4, collect_seconds=0)
    # first iteration uses the deterministic script, not AI
    assert out["iterations"][0]["ai_notes"] == "deterministic baseline script"
    assert out["confirmed"] is True


def test_disabled_ai_is_noop():
    res = {"meta": {}, "frameworks": [], "frida": {"script": "x"}}
    out = FA.bypass(res, "com.x", cfg=AIConfig(provider="off"))
    assert out["ok"] is False and out["enabled"] is False


def test_extract_js_prefers_code_block():
    assert FA._extract_js("blah ```javascript\nX=1;\n``` end") == "X=1;"
    assert FA._extract_js("no fence here") == "no fence here"

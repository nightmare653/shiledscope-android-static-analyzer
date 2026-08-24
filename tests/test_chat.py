"""Unit tests for the AI chatbot (mocked model)."""

from ai import chatbot as chat
from ai.config import AIConfig


def _cfg():
    return AIConfig(provider="ollama", base_url="http://x/v1", model="m")


def test_chat_returns_reply(monkeypatch):
    captured = {}

    def fake_chat(system, user, cfg=None, messages=None, **kw):
        captured["system"] = system
        captured["messages"] = messages
        return "Here is the answer."

    monkeypatch.setattr("ai.provider.chat", fake_chat)
    r = chat.ask([{"role": "user", "content": "what is the top risk?"}],
                 result={"meta": {"package": "com.x"}, "extra": [], "api": {}}, cfg=_cfg())
    assert r["ok"] and r["reply"] == "Here is the answer."
    # the app analysis is injected into the system prompt for grounding
    assert "CURRENT APP ANALYSIS" in captured["system"]
    # history is forwarded as messages
    assert captured["messages"][-1]["content"] == "what is the top risk?"


def test_chat_disabled():
    r = chat.ask([{"role": "user", "content": "hi"}], cfg=AIConfig(provider="off"))
    assert r["ok"] is False and r["enabled"] is False


def test_chat_empty_messages():
    r = chat.ask([], cfg=_cfg())
    assert r["ok"] is False

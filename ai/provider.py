"""
Provider-agnostic chat client (dependency-free: stdlib HTTP only).

One `chat()` call works against:
  * Anthropic  (Messages API)
  * OpenAI / any OpenAI-compatible server / Ollama / LM Studio (chat/completions)

Using raw HTTP (urllib) keeps it identical for a LOCAL model and a cloud one —
no SDK/version coupling — which is what makes "bring your own AI, even offline"
work. The anthropic/openai SDKs, if installed, are not required.
"""

import json
import urllib.error
import urllib.request

from .config import OPENAI_LIKE, load_config

_ANTHROPIC_VERSION = "2023-06-01"


class AIError(Exception):
    pass


def _post(url, headers, payload, timeout):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")[:500]
        raise AIError("HTTP %s from %s: %s" % (e.code, url, body))
    except urllib.error.URLError as e:
        raise AIError("cannot reach %s: %s" % (url, getattr(e, "reason", e)))
    except Exception as e:
        raise AIError("request to %s failed: %s" % (url, e))


def _get(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
#  chat
# ---------------------------------------------------------------------------
def chat(system, user, cfg=None, messages=None, max_tokens=None, temperature=None):
    """
    Send a single-turn (or `messages` multi-turn) request; return the text reply.
    Raises AIError on any failure (never returns a partial/garbage string).
    """
    cfg = cfg or load_config()
    if not cfg.enabled:
        raise AIError("AI is disabled (provider = off).")
    max_tokens = max_tokens or cfg.max_tokens
    temperature = cfg.temperature if temperature is None else temperature

    if cfg.provider == "anthropic":
        return _chat_anthropic(cfg, system, user, messages, max_tokens, temperature)
    if cfg.provider in OPENAI_LIKE:
        return _chat_openai(cfg, system, user, messages, max_tokens, temperature)
    raise AIError("unknown provider: %s" % cfg.provider)


def _chat_anthropic(cfg, system, user, messages, max_tokens, temperature):
    url = cfg.base_url.rstrip("/") + "/v1/messages"
    msgs = messages or [{"role": "user", "content": user}]
    payload = {"model": cfg.model, "max_tokens": max_tokens,
               "temperature": temperature, "messages": msgs}
    if system:
        payload["system"] = system
    headers = {"content-type": "application/json",
               "x-api-key": cfg.api_key, "anthropic-version": _ANTHROPIC_VERSION}
    data = _post(url, headers, payload, cfg.timeout)
    try:
        parts = data.get("content", [])
        return "".join(p.get("text", "") for p in parts if p.get("type") == "text").strip()
    except Exception:
        raise AIError("unexpected Anthropic response shape")


def _chat_openai(cfg, system, user, messages, max_tokens, temperature):
    url = cfg.base_url.rstrip("/") + "/chat/completions"
    msgs = list(messages) if messages else []
    if not messages:
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": user})
    elif system and not any(m.get("role") == "system" for m in msgs):
        msgs.insert(0, {"role": "system", "content": system})
    payload = {"model": cfg.model, "messages": msgs,
               "temperature": temperature, "max_tokens": max_tokens}
    headers = {"content-type": "application/json"}
    if cfg.api_key and cfg.api_key != "not-needed":
        headers["Authorization"] = "Bearer " + cfg.api_key
    data = _post(url, headers, payload, cfg.timeout)
    try:
        return (data["choices"][0]["message"]["content"] or "").strip()
    except Exception:
        raise AIError("unexpected OpenAI-compatible response shape")


# ---------------------------------------------------------------------------
#  probe (cheap reachability / auth check)
# ---------------------------------------------------------------------------
def probe(cfg):
    try:
        if cfg.provider == "anthropic":
            url = cfg.base_url.rstrip("/") + "/v1/models"
            _get(url, {"x-api-key": cfg.api_key,
                       "anthropic-version": _ANTHROPIC_VERSION}, min(cfg.timeout, 15))
            return {"ok": True, "enabled": True, "provider": cfg.provider,
                    "model": cfg.model, "detail": "reachable"}
        # openai-like: GET /models
        url = cfg.base_url.rstrip("/") + "/models"
        headers = {}
        if cfg.api_key and cfg.api_key != "not-needed":
            headers["Authorization"] = "Bearer " + cfg.api_key
        data = _get(url, headers, min(cfg.timeout, 15))
        models = [m.get("id") for m in (data.get("data") or [])][:20]
        return {"ok": True, "enabled": True, "provider": cfg.provider,
                "model": cfg.model, "models": models, "detail": "reachable"}
    except urllib.error.HTTPError as e:
        # auth errors still prove reachability
        code = e.code
        ok = code in (401, 403)  # reachable but needs/av bad key
        return {"ok": False, "enabled": True, "provider": cfg.provider,
                "detail": "HTTP %s (%s)" % (code, "auth" if ok else "error"),
                "reachable": True}
    except Exception as e:
        return {"ok": False, "enabled": True, "provider": cfg.provider,
                "detail": str(e), "reachable": False}

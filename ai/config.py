"""
AI provider configuration — bring-your-own model (local or cloud).

Precedence (first wins):
  1. ai_config.json in the project root (written by the UI / by hand)
  2. environment variables
  3. built-in defaults (provider = "off")

Supported providers
-------------------
  off               AI disabled (default) — the tool runs deterministic-only.
  anthropic         Claude via the Anthropic API (needs api_key).
  openai            OpenAI API (needs api_key).
  openai-compatible any server speaking the OpenAI /chat/completions schema
                    (set base_url; api_key optional).
  ollama            local Ollama (default base_url http://localhost:11434/v1).
  lmstudio          local LM Studio (default base_url http://localhost:1234/v1).

The last three make "run my own local AI" work with no code changes.
"""

import json
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(_ROOT, "ai_config.json")

# sensible default endpoints / models per provider (all user-overridable)
_PROVIDER_DEFAULTS = {
    "anthropic":         {"base_url": "https://api.anthropic.com", "model": "claude-sonnet-5"},
    "openai":            {"base_url": "https://api.openai.com/v1",  "model": "gpt-4o-mini"},
    "openai-compatible": {"base_url": "http://localhost:8000/v1",   "model": ""},
    "ollama":            {"base_url": "http://localhost:11434/v1",  "model": "llama3.1"},
    "lmstudio":          {"base_url": "http://localhost:1234/v1",   "model": "local-model"},
}

# providers that talk the OpenAI chat schema (everything except anthropic)
OPENAI_LIKE = ("openai", "openai-compatible", "ollama", "lmstudio")


class AIConfig:
    def __init__(self, provider="off", base_url="", api_key="", model="",
                 temperature=0.2, max_tokens=2000, timeout=300):
        self.provider = provider
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

    @property
    def enabled(self):
        return self.provider and self.provider != "off"

    def to_dict(self, redact=True):
        return {
            "provider": self.provider, "base_url": self.base_url,
            "api_key": ("***set***" if (redact and self.api_key) else self.api_key),
            "model": self.model, "temperature": self.temperature,
            "max_tokens": self.max_tokens, "timeout": self.timeout,
            "enabled": self.enabled,
        }


def _apply_defaults(cfg):
    d = _PROVIDER_DEFAULTS.get(cfg.provider, {})
    if not cfg.base_url:
        cfg.base_url = d.get("base_url", "")
    if not cfg.model:
        cfg.model = d.get("model", "")
    # local providers commonly need no key
    if cfg.provider in ("ollama", "lmstudio") and not cfg.api_key:
        cfg.api_key = cfg.api_key or "not-needed"
    return cfg


def load_config():
    data = {}
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f) or {}
        except Exception:
            data = {}

    provider = data.get("provider") or os.environ.get("SHIELDSCOPE_AI_PROVIDER") or "off"
    cfg = AIConfig(
        provider=provider,
        base_url=data.get("base_url") or os.environ.get("SHIELDSCOPE_AI_BASE_URL", ""),
        api_key=(data.get("api_key") or os.environ.get("SHIELDSCOPE_AI_API_KEY")
                 or _env_key_for(provider) or ""),
        model=data.get("model") or os.environ.get("SHIELDSCOPE_AI_MODEL", ""),
        temperature=float(data.get("temperature", 0.2)),
        max_tokens=int(data.get("max_tokens", 2000)),
        timeout=int(data.get("timeout", 300)),
    )
    return _apply_defaults(cfg)


def _env_key_for(provider):
    if provider == "anthropic":
        return os.environ.get("ANTHROPIC_API_KEY")
    if provider == "openai":
        return os.environ.get("OPENAI_API_KEY")
    return None


def save_config(data):
    """Persist config from a dict (UI). Never writes a redacted key back."""
    keep = {}
    cur = {}
    if os.path.isfile(CONFIG_PATH):
        try:
            cur = json.load(open(CONFIG_PATH, encoding="utf-8"))
        except Exception:
            cur = {}
    for k in ("provider", "base_url", "model", "temperature", "max_tokens", "timeout"):
        if k in data and data[k] != "":
            keep[k] = data[k]
    # only overwrite api_key when a real (non-redacted) value is supplied
    ak = data.get("api_key")
    if ak and ak != "***set***":
        keep["api_key"] = ak
    elif "api_key" in cur:
        keep["api_key"] = cur["api_key"]
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(keep, f, indent=2)
    return load_config()


def probe(cfg=None):
    """Cheap reachability check for the configured provider. Returns dict."""
    from . import provider as P
    cfg = cfg or load_config()
    if not cfg.enabled:
        return {"ok": False, "enabled": False, "detail": "AI is disabled."}
    try:
        return P.probe(cfg)
    except Exception as e:
        return {"ok": False, "enabled": True, "detail": "probe failed: %s" % e}

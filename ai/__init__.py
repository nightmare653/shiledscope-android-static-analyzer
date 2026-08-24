"""
ShieldScope AI layer (OPTIONAL, additive).

This package never modifies the deterministic engine. It reads the engine's
result JSON and adds enrichment (per-finding exploitation guidance, a prioritised
pentest plan, and — later — an AI-driven Frida bypass agent).

It is off by default and provider-agnostic: point it at a local model
(Ollama / LM Studio) or a cloud key (Anthropic / OpenAI / any OpenAI-compatible
endpoint). If AI is not configured, every entry point degrades to a no-op so the
tool behaves exactly like the AI-free build.
"""

from .config import load_config, save_config, probe  # noqa: F401
from .provider import chat, AIError  # noqa: F401

"""
AI chat — a conversational assistant grounded in the current analysis.

Ask questions about the analyzed app ("what's the most critical issue?", "how do
I exploit the guest access?", "which endpoint should I hit first?") or general
mobile-security questions. When an analysis result is provided, a compact summary
of it is given to the model so answers are specific to the app.
"""

import json

from . import provider as P
from .analyst import _plan_context
from .config import load_config

_SYSTEM = (
    "You are ShieldScope's mobile-security assistant helping with an AUTHORIZED "
    "assessment. Answer the tester's questions clearly and practically. When an "
    "app analysis summary is provided, ground your answers in it (reference the "
    "real findings, endpoints, package). Give concrete commands (adb/frida/curl/"
    "Burp) when useful. Be concise; use short markdown. If something can't be "
    "known from static analysis, say so and give the dynamic check."
)

_MAX_HISTORY = 16


def ask(messages, result=None, cfg=None):
    """
    messages: [{role: 'user'|'assistant', content: str}, ...]
    Returns {ok, reply} or {ok: False, error/enabled}.
    """
    cfg = cfg or load_config()
    if not cfg.enabled:
        return {"ok": False, "enabled": False, "error": "AI disabled"}
    if not messages:
        return {"ok": False, "error": "no message"}

    system = _SYSTEM
    if result:
        try:
            system += ("\n\nCURRENT APP ANALYSIS (use to answer):\n"
                       + json.dumps(_plan_context(result), indent=1))
        except Exception:
            pass

    # keep only role/content and cap history length
    hist = [{"role": ("assistant" if m.get("role") == "assistant" else "user"),
             "content": str(m.get("content", ""))[:6000]}
            for m in messages[-_MAX_HISTORY:] if m.get("content")]
    try:
        reply = P.chat(system, None, cfg=cfg, messages=hist,
                       max_tokens=min(cfg.max_tokens, 1200))
        return {"ok": True, "reply": reply, "provider": cfg.provider, "model": cfg.model}
    except P.AIError as e:
        return {"ok": False, "enabled": True, "error": str(e)}

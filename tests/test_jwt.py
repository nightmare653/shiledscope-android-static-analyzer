"""Unit tests for the JWT decoder."""

import base64
import json
import time

from analyzer import jwtscan


def _mk(header, payload):
    b = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return b(header) + "." + b(payload) + ".sig"


def test_alg_none_flagged():
    d = jwtscan.decode_jwt(_mk({"alg": "none"}, {"sub": "1"}))
    assert d and d["alg"] == "none"
    assert any("alg=none" in i for i in d["issues"])


def test_hs256_and_no_exp_flagged():
    d = jwtscan.decode_jwt(_mk({"alg": "HS256", "typ": "JWT"}, {"role": "admin"}))
    assert any("Symmetric" in i for i in d["issues"])
    assert any("exp" in i for i in d["issues"])
    assert "role" in d["sensitive_claims"]


def test_expired_detected():
    d = jwtscan.decode_jwt(_mk({"alg": "HS256"}, {"exp": int(time.time()) - 10}))
    assert d["expired"] is True


def test_non_jwt_returns_none():
    assert jwtscan.decode_jwt("hello.world") is None
    assert jwtscan.decode_jwt("not-a-token") is None

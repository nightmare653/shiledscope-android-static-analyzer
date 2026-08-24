"""
JWT decoder — enriches a found JSON Web Token with its decoded header/claims and
flags the classic weaknesses (alg:none, symmetric alg = brute-forceable, missing
/ long expiry, sensitive claims). Pure/offline; no signature verification.
"""

import base64
import binascii
import json
import time


def _b64url(seg):
    seg = seg.strip()
    seg += "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg.encode("ascii", "ignore"))
    except (binascii.Error, ValueError):
        return b""


_SENSITIVE_CLAIMS = ("email", "phone", "phone_number", "msisdn", "role", "roles",
                     "admin", "is_admin", "scope", "scopes", "user_id", "uid",
                     "sub", "name", "username", "account", "permissions", "authorities")


def decode_jwt(token):
    """Return {header, claims, alg, expired, issues, ...} or None if not a JWT."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url(parts[0]) or b"{}")
        payload = json.loads(_b64url(parts[1]) or b"{}")
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    # a real JWT header carries alg (and usually typ); reject decode garbage
    if "alg" not in header and "typ" not in header:
        return None

    alg = str(header.get("alg", "")) or "?"
    issues = []
    if alg.lower() == "none":
        issues.append("alg=none - signature can be stripped; forge any token.")
    if alg.upper().startswith("HS"):
        issues.append("Symmetric alg (%s) - if the secret is weak it is brute-forceable "
                      "(jwt_tool / hashcat mode 16500)." % alg)
    if alg.upper().startswith("RS"):
        issues.append("Asymmetric alg - test the alg-confusion attack (RS256->HS256 with the "
                      "public key as the HMAC secret).")

    now = int(time.time())
    exp = payload.get("exp")
    expired = None
    if isinstance(exp, (int, float)):
        expired = exp < now
        iat = payload.get("iat")
        if isinstance(iat, (int, float)) and (exp - iat) > 30 * 86400:
            issues.append("Very long lifetime (>30d) - stolen token stays valid a long time.")
    else:
        issues.append("No 'exp' claim - the token may never expire.")

    present = sorted(k for k in payload.keys() if k.lower() in _SENSITIVE_CLAIMS)
    # keep the claims small/safe for display
    claims = {k: payload[k] for k in list(payload.keys())[:20]}
    return {
        "alg": alg, "typ": header.get("typ"), "kid": header.get("kid"),
        "claims": claims, "sensitive_claims": present,
        "expired": expired, "issues": issues,
    }

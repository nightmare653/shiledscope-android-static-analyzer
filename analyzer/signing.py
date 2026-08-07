"""
APK signing & certificate analysis (#2).

Offline checks via androguard:
  * signature scheme in use (v1/v2/v3) and the JANUS vulnerability
    (v1-only + minSdk < 24  ⇒  CVE-2017-13156, APK can be tampered)
  * signer certificate details (subject/issuer/serial/validity/key)
  * Android DEBUG certificate shipped to production
  * weak signing key (RSA < 2048 / DSA) and weak signature hash (MD5/SHA-1)
  * expired certificate

Returns (meta_dict, findings_list). Findings use the standard rich schema.
"""

import datetime


def _f(fid, title, sev, location, desc, risk, repro, mit, evidence=""):
    return {"id": fid, "title": title, "severity": sev, "category": "signing",
            "location": location, "evidence": evidence, "description": desc,
            "risk": risk, "reproduce": repro, "mitigation": mit}


def analyze(a, min_sdk=None):
    meta = {"schemes": [], "subject": None, "issuer": None, "serial": None,
            "key_algo": None, "key_bits": None, "sig_algo": None, "hash_algo": None,
            "not_before": None, "not_after": None, "self_signed": None, "debug_cert": False}
    findings = []
    if a is None:
        return meta, findings

    try:
        v1, v2, v3 = a.is_signed_v1(), a.is_signed_v2(), a.is_signed_v3()
    except Exception:
        v1 = v2 = v3 = False
    schemes = [s for s, on in (("v1", v1), ("v2", v2), ("v3", v3)) if on]
    meta["schemes"] = schemes

    try:
        min_sdk = int(min_sdk) if min_sdk is not None else None
    except Exception:
        min_sdk = None

    # --- JANUS (v1-only) ---
    if v1 and not (v2 or v3):
        janus = (min_sdk is None) or (min_sdk < 24)
        findings.append(_f(
            "sign-janus", "APK signed with v1 scheme only (Janus-exploitable)",
            "high" if janus else "medium",
            "APK signing block (v1 JAR signature only)",
            "The APK uses only the legacy v1 (JAR) signature scheme — no APK Signature Scheme v2/v3.",
            "v1-only APKs are vulnerable to Janus (CVE-2017-13156) on Android 5.0–8.0: an attacker "
            "can prepend a malicious DEX to the APK without breaking the signature, achieving code "
            "injection into a 'validly signed' app."
            + ("" if janus else " (minSdk ≥ 24 limits real-world exposure, but v2+ is still required.)"),
            ["Confirm scheme: `apksigner verify --verbose app.apk`.",
             "On an Android 5–8 device, craft a Janus payload (prepend DEX) and verify it installs as signed."],
            "Sign with APK Signature Scheme v2/v3 (v3 recommended) in addition to (or instead of) v1; "
            "raise minSdk and re-sign."))

    # --- certificate details ---
    try:
        certs = a.get_certificates() or []
    except Exception:
        certs = []
    if not certs:
        findings.append(_f("sign-unsigned", "No signing certificate found", "high",
            "APK signing block",
            "No signer certificate could be read from the APK.",
            "An unsigned or improperly signed APK cannot be trusted and will not install on modern Android.",
            ["`apksigner verify --verbose app.apk`."],
            "Sign the release APK with a securely stored release key (v2/v3)."))
        return meta, findings

    c = certs[0]
    try:
        subj = c.subject.human_friendly
        iss = c.issuer.human_friendly
        meta.update(subject=subj, issuer=iss, serial=str(c.serial_number),
                    hash_algo=str(c.hash_algo), sig_algo=str(c.signature_algo),
                    self_signed=(subj == iss))
        meta["not_before"] = str(getattr(c, "not_valid_before", ""))
        meta["not_after"] = str(getattr(c, "not_valid_after", ""))
        try:
            pk = c.public_key
            meta["key_algo"] = str(pk.algorithm)
            meta["key_bits"] = int(pk.bit_size)
        except Exception:
            pass
    except Exception:
        return meta, findings

    # --- debug certificate ---
    if "Common Name: Android Debug" in (meta["subject"] or "") or \
       (meta["subject"] or "").strip().upper().startswith("COMMON NAME: ANDROID DEBUG"):
        meta["debug_cert"] = True
        findings.append(_f("sign-debug-cert", "Signed with the Android DEBUG certificate", "high",
            "Signer certificate subject: " + meta["subject"],
            "The app is signed with the well-known public Android debug key (CN=Android Debug).",
            "The debug key is public and shared by every developer — anyone can produce updates that "
            "look 'validly signed' by the same key, and it signals a debug build shipped to production.",
            ["`apksigner verify --print-certs app.apk` and check the subject/CN."],
            "Sign release builds with a private release key kept in a secure keystore/HSM."))

    # --- weak key ---
    ka, kb = (meta["key_algo"] or "").lower(), meta["key_bits"] or 0
    if (ka == "rsa" and kb and kb < 2048) or (ka == "dsa"):
        findings.append(_f("sign-weak-key", "Weak signing key (%s %s-bit)" % (ka.upper(), kb or "?"),
            "medium", "Signer certificate public key",
            "The signing key is %s %s-bit." % (ka.upper(), kb or "unknown"),
            "Short RSA keys / DSA are cryptographically weak; a forged key could let an attacker sign "
            "malicious updates.",
            ["`apksigner verify --print-certs app.apk` and review the key size."],
            "Use RSA ≥ 2048 (or EC P-256); re-key and re-sign."))

    # --- weak signature hash ---
    if (meta["hash_algo"] or "").lower() in ("md5", "sha1"):
        findings.append(_f("sign-weak-hash", "Weak certificate signature hash (%s)" % meta["hash_algo"],
            "medium", "Signer certificate signature algorithm",
            "The certificate uses a %s signature." % meta["hash_algo"],
            "MD5/SHA-1 are collision-broken; a weak signature undermines the integrity guarantee of "
            "the signing chain.",
            ["`apksigner verify --print-certs app.apk` and check the signature algorithm."],
            "Re-issue the signing certificate with a SHA-256 signature."))

    # --- expired ---
    try:
        na = getattr(c, "not_valid_after", None)
        if na and na < datetime.datetime.now(na.tzinfo):
            findings.append(_f("sign-expired", "Signing certificate expired", "low",
                "Signer certificate validity",
                "The signing certificate expired on %s." % meta["not_after"],
                "An expired cert won't block existing installs but prevents key-continuity for updates "
                "and is a hygiene/red-flag issue.",
                ["Check `not after` in `apksigner verify --print-certs app.apk`."],
                "Note: Android certs are typically issued for ~25+ years; re-plan key management."))
    except Exception:
        pass

    return meta, findings

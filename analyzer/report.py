"""
Top-level entry point: detect file type, run the right analyzer, attach the
step-by-step bypass guides that the findings actually reference, and compute a
short summary + protection score.
"""

import hashlib
import os
import shutil
import tempfile
import zipfile

import tarfile

from . import apk_deep
from . import ipa as ipa_mod
from . import guides as guides_mod
from . import frida_gen
from . import datadir as datadir_mod


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# Bump when detection/scanning logic changes so the on-disk cache self-invalidates.
_ENGINE_VERSION = "2026.09-1"


def _cache_dir():
    d = os.environ.get("SHIELDSCOPE_CACHE_DIR") or         os.path.join(os.path.expanduser("~"), ".shieldscope", "cache")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        return None
    return d


def _cache_load(sha):
    """Return a cached static result for this APK hash, or None. Keyed by hash +
    engine version, so a code change invalidates every entry automatically."""
    import json
    d = _cache_dir()
    if not d:
        return None
    fp = os.path.join(d, sha + ".json")
    try:
        with open(fp, "r", encoding="utf-8") as f:
            blob = json.load(f)
        if blob.get("engine") == _ENGINE_VERSION and isinstance(blob.get("result"), dict):
            return blob["result"]
    except Exception:
        return None
    return None


def _cache_store(sha, result):
    import json
    d = _cache_dir()
    if not d:
        return
    try:
        with open(os.path.join(d, sha + ".json"), "w", encoding="utf-8") as f:
            json.dump({"engine": _ENGINE_VERSION, "result": result}, f)
    except Exception:
        pass


def _post_validate(result, flag):
    """Optionally confirm which hardcoded secrets are actually live (network,
    opt-in). Runs on fresh AND cached results so verdicts stay fresh."""
    if not (flag or os.environ.get("SHIELDSCOPE_VALIDATE_SECRETS") == "1"):
        return
    try:
        from . import validate as _val
        _val.validate_result(result)
    except Exception:
        pass


def _detect_type(path):
    """Return 'apk' | 'ipa' | 'datadir' | None using content, not just extension."""
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as f:
        head = f.read(64)

    # extracted-data inputs
    if head.startswith(b"ANDROID BACKUP"):
        return "datadir"
    if head[:16] == b"SQLite format 3\x00":
        return "datadir"
    if ext in (".ab", ".tar", ".gz", ".tgz") or tarfile.is_tarfile(path):
        return "datadir"

    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except zipfile.BadZipFile:
        # a lone xml prefs file, etc.
        if ext == ".xml":
            return "datadir"
        return None

    if any(n == "AndroidManifest.xml" or n.endswith(".dex") for n in names):
        return "apk"
    if any(n.startswith("Payload/") and ".app/" in n for n in names):
        return "ipa"
    # a zip that looks like a pulled data dir
    if any("shared_prefs/" in n or "/databases/" in n or n.endswith((".db", ".sqlite")) for n in names):
        return "datadir"
    if ext == ".apk":
        return "apk"
    if ext == ".ipa":
        return "ipa"
    if ext in (".zip",):
        return "datadir"
    return None


def _collect_guides(result):
    """Gather the full guide objects for every guide id referenced by findings/frameworks."""
    ids = []
    for bucket in ("root", "ssl"):
        for m in result.get(bucket, {}).get("mechanisms", []):
            ids.extend(m.get("guides", []))
    for fw in result.get("frameworks", []):
        ids.extend(fw.get("guides", []))
    seen, ordered = set(), []
    for gid in ids:
        if gid in seen:
            continue
        g = guides_mod.get(gid)
        if g:
            seen.add(gid)
            ordered.append(dict(id=gid, **g))
    return ordered


# OWASP MASVS v2 control mapping (by explicit finding id, then category default)
_MASVS_BY_ID = {
    "allow-backup": "MASVS-STORAGE-2", "debuggable": "MASVS-CODE-2",
    "cleartext": "MASVS-NETWORK-1", "ats-disabled": "MASVS-NETWORK-1",
    "ats-exceptions": "MASVS-NETWORK-1", "exported-components": "MASVS-PLATFORM-1",
    "provider-exposure": "MASVS-PLATFORM-1", "task-hijacking": "MASVS-PLATFORM-1",
    "deeplink-surface": "MASVS-PLATFORM-1", "perm-dangerous": "MASVS-PRIVACY-2",
    "perm-custom-weak": "MASVS-PLATFORM-1", "clipboard-write": "MASVS-PLATFORM-3",
    "ios-pasteboard": "MASVS-PLATFORM-3",
    "sign-janus": "MASVS-RESILIENCE-3", "sign-debug-cert": "MASVS-RESILIENCE-3",
    "sign-unsigned": "MASVS-RESILIENCE-3", "sign-expired": "MASVS-RESILIENCE-3",
    "sign-weak-key": "MASVS-CRYPTO-1", "sign-weak-hash": "MASVS-CRYPTO-1",
}
_MASVS_BY_CAT = {
    "secret": "MASVS-STORAGE-1", "crypto": "MASVS-CRYPTO-2", "pii": "MASVS-PRIVACY-1",
    "config": "MASVS-PLATFORM-1", "permission": "MASVS-PLATFORM-1",
    "storage": "MASVS-STORAGE-1", "signing": "MASVS-RESILIENCE-3",
}


def _masvs_for(f):
    if f.get("id") in _MASVS_BY_ID:
        return _MASVS_BY_ID[f["id"]]
    fid = f.get("id", "")
    if fid.startswith("webview") or fid.startswith("ios-uiwebview"):
        return "MASVS-PLATFORM-2"
    return _MASVS_BY_CAT.get(f.get("category"), "MASVS-CODE-1")


def _map_masvs(result):
    for f in result.get("extra", []) or []:
        f["masvs"] = _masvs_for(f)
    for f in result.get("findings", []) or []:   # datadir
        f["masvs"] = _masvs_for(f)
    for m in result.get("root", {}).get("mechanisms", []):
        m["masvs"] = "MASVS-RESILIENCE-2"
    for m in result.get("ssl", {}).get("mechanisms", []):
        m["masvs"] = "MASVS-NETWORK-2"
    return result


def _refine_confidence(result):
    """
    #3 cross-evidence confidence: reward multiple matched patterns per finding
    and corroboration between co-occurring mechanisms; flag lonely weak hits.
    A finding explicitly debunked by #2 (verified is False) is never boosted.
    """
    for bucket in ("root", "ssl"):
        mechs = result.get(bucket, {}).get("mechanisms", [])
        n = len(mechs)
        for m in mechs:
            ev = m.get("evidence") or ""
            m["signals"] = len([x for x in ev.split(",") if x.strip()])
            if m.get("verified") is False:
                continue
            if m["confidence"] == "medium" and m["signals"] >= 2:
                m["confidence"] = "high"
                m["multi_signal"] = True
        # co-occurrence: several independent checks ⇒ deliberate hardening
        if n >= 3:
            for m in mechs:
                if m.get("verified") is False:
                    continue
                if m["confidence"] == "low":
                    m["confidence"] = "medium"; m["corroborated"] = True
                elif m["confidence"] == "medium":
                    m["confidence"] = "high"; m["corroborated"] = True
        # a single weak, unverified finding — be honest about uncertainty
        if n == 1 and mechs and mechs[0]["confidence"] == "low" \
                and not mechs[0].get("verified"):
            mechs[0]["unverified"] = True
    return result


def _score(result):
    """
    Rough 0-100 'protection strength' heuristic + rating label.
    Weights reward multiple independent layers and hard-to-bypass layers.

    A trust-all TrustManager (disabled TLS validation) is a MITM hole that
    undermines whatever pinning is present, so it CAPS the rating regardless of
    how many controls exist — otherwise the headline reads "Very strong" over a
    live vulnerability.
    """
    weight = {"high": 20, "medium": 12, "low": 6}
    layer_bonus = {"native": 10, "framework": 8, "config": 4, "java": 0, "objc": 0}
    score = 0
    for bucket in ("root", "ssl"):
        for m in result.get(bucket, {}).get("mechanisms", []):
            score += weight.get(m.get("confidence"), 8)
            score += layer_bonus.get(m.get("layer"), 0)
    score = min(score, 100)

    # does any finding disable TLS validation?
    trustall = [f for f in (result.get("extra") or [])
                if str(f.get("id", "")).startswith("trustall-")]
    capped = False
    if trustall and score > 40:
        score = 40
        capped = True

    if score == 0:
        rating = "None detected"
    elif score < 25:
        rating = "Weak"
    elif score < 55:
        rating = "Moderate"
    elif score < 80:
        rating = "Strong"
    else:
        rating = "Very strong"
    if capped:
        rating += " (capped: TLS validation disabled in %d class%s)" % (
            len(trustall), "es" if len(trustall) != 1 else "")
    return score, rating


def _summary(result):
    r = result["root"]; s = result["ssl"]
    parts = []
    parts.append(("Root/JB detection: %d layer(s)" % r["layers"]) if r["implemented"]
                 else "Root/JB detection: none detected")
    parts.append(("SSL pinning: %d layer(s)" % s["layers"]) if s["implemented"]
                 else "SSL pinning: none detected")
    return parts


def analyze_file(path, original_name=None, keep_workdir=False, validate_secrets=False):
    ftype = _detect_type(path)
    if ftype is None:
        return {"ok": False, "error": "Unrecognised file — expected an APK, IPA, or an extracted "
                                       "data dir (.ab / .tar / .zip)."}

    if ftype == "datadir":
        result = datadir_mod.analyze_data(path, original_name)
        if result.get("ok"):
            result["file"] = {"name": original_name or os.path.basename(path),
                              "size": os.path.getsize(path), "sha256": _sha256(path),
                              "type": "datadir"}
            _map_masvs(result)
        return result

    sha = _sha256(path)
    cache_on = (os.environ.get("SHIELDSCOPE_CACHE") == "1") and not keep_workdir
    if cache_on:
        cached = _cache_load(sha)
        if cached is not None:
            cached.setdefault("file", {})["name"] = original_name or os.path.basename(path)
            _post_validate(cached, validate_secrets)
            return cached

    workdir = None
    if ftype == "apk":
        workdir = tempfile.mkdtemp(prefix="ss_work_")
        try:
            result = apk_deep.analyze(path, workdir)
        except Exception as e:
            shutil.rmtree(workdir, ignore_errors=True)
            import traceback
            traceback.print_exc()
            return {"ok": False, "error": "Deep analysis failed: %s" % e, "platform": "android"}
    else:
        result = ipa_mod.analyze(path)

    if result.get("error"):
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)
        return {"ok": False, "error": result["error"], "platform": result.get("platform")}

    # deep engine keeps a scratch workdir; drop it once results are extracted,
    # unless the caller asked to keep the decompiled tree (CLI --keep-decompiled)
    if workdir:
        if keep_workdir:
            result["decompiled_dir"] = workdir
        else:
            result.pop("_workdir", None)
            shutil.rmtree(workdir, ignore_errors=True)

    result["file"] = {
        "name": original_name or os.path.basename(path),
        "size": os.path.getsize(path),
        "sha256": sha,
        "type": ftype,
    }
    result = _refine_confidence(result)
    result = _map_masvs(result)
    result["guides"] = _collect_guides(result)
    result["frida"] = frida_gen.generate(result)
    result.setdefault("extra", [])
    score, rating = _score(result)
    result["score"] = score
    result["rating"] = rating
    result["summary"] = _summary(result)
    result["ok"] = True
    if cache_on:
        _cache_store(sha, result)
    _post_validate(result, validate_secrets)
    return result

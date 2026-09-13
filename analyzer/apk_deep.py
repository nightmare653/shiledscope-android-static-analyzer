"""
Android deep-analysis orchestrator (the new engine).

Pipeline:
  1. cheap metadata + signer cert via androguard APK() (NOT AnalyzeAPK — that is
     the call that used to hang; we never invoke it).
  2. unpack: apktool (smali/res/manifest) + jadx (Java) + nested archives, all
     under hard timeouts.
  3. detect: obfuscation-resilient root/SSL/framework detection over smali+native.
  4. deepscan: exhaustive secret hunt over the whole tree (parallel).
  5. surface / storage / weak-crypto over the raw dex+so bytes (few files, fast).
  6. signing + manifest/config checks + IPC over the (already-parsed) manifest.

Returns the result dict in the schema the UI/report already consume.
"""

import os

from . import apk as apk_mod          # reuse fast _meta (APK(), not AnalyzeAPK)
from . import unpack as unpack_mod
from . import detect as detect_mod
from . import deepscan
from . import apiscan
from . import masvs
from . import surface as surface_mod
from . import storage as storage_mod
from . import signing as signing_mod
from . import manifest_checks
from . import manifest_fallback


def _raw_code_scan(up):
    """Run surface/storage/weak-crypto over the raw classes*.dex + .so bytes.

    These byte-regex scanners are cheap over the handful of dex/so files, and
    keep the deep per-file secret pass focused. Returns (surface_acc,
    storage_presence, crypto_raw, bundled_dbs)."""
    surface_acc, storage_presence, crypto_raw, dbs = {}, {}, [], []
    base = deepscan._op(up.raw_dir)
    for dp, _dn, fs in os.walk(base):
        for fn in fs:
            low = fn.lower()
            ap = os.path.join(dp, fn)
            rel = os.path.relpath(ap, base).replace("\\", "/")
            if low.endswith(".dex") or low.endswith(".so"):
                try:
                    with open(ap, "rb") as f:
                        b = f.read(96 * 1024 * 1024)
                except OSError:
                    continue
                surface_mod.scan(b, surface_acc)
                storage_mod.scan(b, rel, storage_presence)
                crypto_raw += masvs.scan_crypto(b, rel)
            elif low.endswith((".db", ".sqlite", ".sqlite3", ".db3", ".realm")):
                try:
                    with open(ap, "rb") as f:
                        b = f.read(24 * 1024 * 1024)
                except OSError:
                    continue
                f2 = storage_mod.parse_bundled_db(rel, b, masvs.scan_secrets, masvs.scan_pii)
                if f2:
                    dbs.append(f2)
    return surface_acc, storage_presence, crypto_raw, dbs


def _firebase_misconfig(api, secret_findings):
    """If a Firebase RTDB / Storage URL is present, flag it for a public-access test."""
    urls = set()
    for e in (api.get("endpoints") or []):
        v = e.get("value", "")
        if "firebaseio.com" in v or "firebasestorage" in v or "firebasedatabase.app" in v:
            urls.add(v.split("?")[0])
    for f in secret_findings:
        v = f.get("evidence", "")
        if "firebaseio.com" in v:
            urls.add(v.split("?")[0])
    if not urls:
        return []
    u = sorted(urls)[0].rstrip("/")
    return [{
        "id": "firebase-misconfig",
        "title": "Firebase backend - test for public read/write",
        "severity": "medium", "category": "config",
        "location": ", ".join(sorted(urls)[:4]),
        "evidence": u,
        "description": "A Firebase Realtime Database / Storage endpoint is referenced by the app. "
                       "These are frequently left world-readable/writable by lax security rules.",
        "risk": "If the rules allow public access, anyone can read (and sometimes write) the entire "
                "database / bucket without authentication — a common critical data-exposure bug.",
        "reproduce": [
            "Test unauthenticated read: `curl '%s/.json'` (RTDB) — data returned = public read." % u,
            "Test write: `curl -X PUT -d '{\"x\":1}' '%s/ss_test.json'` then delete it." % u,
            "For Storage, try listing/downloading objects without a token.",
        ],
        "mitigation": "Lock down Firebase Security Rules to require auth and scope each record to its "
                      "owner; never rely on obscurity of the database URL.",
        "masvs": "MASVS-NETWORK-1"}]


def analyze(apk_path, workdir):
    meta, a = apk_mod._meta(apk_path)

    # unpack (timeouts configurable via env)
    jt = int(os.environ.get("SHIELDSCOPE_JADX_TIMEOUT", "600"))
    at = int(os.environ.get("SHIELDSCOPE_APKTOOL_TIMEOUT", "300"))
    up = unpack_mod.unpack(apk_path, workdir, jadx_timeout=jt, apktool_timeout=at)

    # If androguard couldn't parse the APK, `a` is None and every manifest-derived
    # check (metadata, permissions, config, IPC) would silently return nothing.
    # apktool has usually decoded a good manifest by now — parse that so the app
    # identity and those findings survive an androguard failure. (Signing still
    # uses the real `a`: the cert can't be read from apktool output.)
    manifest_fallback_used = False
    a_manifest = a
    if a is None:
        shim = manifest_fallback.build(up)
        if shim is not None:
            a_manifest = shim
            meta = manifest_fallback.backfill_meta(meta, shim)
            manifest_fallback_used = True

    workers = max(2, min(8, (os.cpu_count() or 4)))

    # detection (smali/native/manifest)
    det = detect_mod.analyze(up, workers=workers, target_sdk=(meta or {}).get("target_sdk"))

    # exhaustive secrets
    raw_hits, scanned = deepscan.scan(up, workers=workers)
    secret_findings = deepscan.build_findings(raw_hits)

    # surface / storage / weak-crypto / bundled dbs over raw code
    surface_acc, storage_presence, crypto_raw, dbs = _raw_code_scan(up)

    pkg = (meta or {}).get("package")
    sign_meta, sign_findings = signing_mod.analyze(a, (meta or {}).get("min_sdk"))

    if manifest_fallback_used:
        det.setdefault("notes", []).append(
            "androguard could not parse this APK; package/version/permissions and the "
            "manifest/config/IPC findings were recovered from apktool's decoded manifest. "
            "Signing-certificate checks are unavailable for this run.")

    api = apiscan.harvest(up)
    extra = (det.get("vulns", [])
             + det.get("auth", [])
             + det.get("misc", [])
             + _firebase_misconfig(api, secret_findings)
             + sign_findings
             + secret_findings
             + masvs.build_crypto_findings(crypto_raw)
             + masvs.android_config(a_manifest, pkg)
             + manifest_checks.analyze(a_manifest, pkg)
             + storage_mod.build_code_findings(storage_presence)
             + dbs)

    return {
        "platform": "android",
        "meta": meta,
        "signing": sign_meta,
        "api": api,
        "surface": surface_mod.finalize(surface_acc),
        "ipc": surface_mod.ipc(a_manifest, pkg),
        "frameworks": det["frameworks"],
        "extra": extra,
        "root": det["root"],
        "ssl": det["ssl"],
        "notes": det["notes"],
        "obfuscation": det["obfuscation"],
        "discovered": det["discovered"],
        "unpack": up.summary(),
        "stats": {"files_scanned": scanned,
                  "smali_trees": len(up.smali_dirs),
                  "nested_archives": len(up.nested)},
        "_workdir": workdir,
    }


def rescan_dex_dir(dex_dir, workdir):
    """Re-run detection + the secret hunt over runtime-dumped DEX (e.g. from
    frida-dexdump on a packed app). Disassembles each .dex to smali (for the
    obfuscation-resilient detectors) and decompiles to Java (for secrets), then
    runs the SAME engine. Returns the finding subset that static analysis of the
    packed APK could not see. Best-effort: needs dex2jar (+ CFR for Java)."""
    import glob
    import shutil
    from . import tools as T

    up = unpack_mod.Unpacked(workdir)
    os.makedirs(up.raw_dir, exist_ok=True)
    dexes = sorted(glob.glob(os.path.join(dex_dir, "**", "*.dex"), recursive=True))
    if not dexes:
        return {"ok": False, "error": "no .dex files in %s" % dex_dir}

    tools = T.get_tools()
    smali_root = os.path.join(workdir, "smali")
    java_root = os.path.join(workdir, "java")
    os.makedirs(smali_root, exist_ok=True)
    jt = int(os.environ.get("SHIELDSCOPE_JADX_TIMEOUT", "600"))
    for i, dx in enumerate(dexes):
        # keep the raw dex in the tree so the strings/secret pass sees it too
        try:
            shutil.copy2(dx, os.path.join(up.raw_dir, "dumped_%d.dex" % i))
        except OSError:
            pass
        if tools.have_dex2jar:
            sm = os.path.join(smali_root, "smali_%d" % i)
            T.baksmali(dx, sm, timeout=jt, log=up.tool_log)
            if os.path.isdir(sm):
                up.smali_dirs.append(sm)
            if tools.have_cfr:
                jar = os.path.join(workdir, "dumped_%d.jar" % i)
                r = T.dex2jar(dx, jar, timeout=jt, log=up.tool_log)
                if r.ok and os.path.isfile(jar):
                    T.cfr(jar, java_root, timeout=jt, log=up.tool_log)
    if os.path.isdir(java_root) and any(f.endswith(".java")
                                        for _dp, _dn, fs in os.walk(java_root) for f in fs):
        up.java_dir = java_root
        up.java_is_fallback = True

    workers = max(2, min(8, (os.cpu_count() or 4)))
    det = detect_mod.analyze(up, workers=workers)
    raw_hits, scanned = deepscan.scan(up, workers=workers)
    secret_findings = deepscan.build_findings(raw_hits)
    extra = (det.get("vulns", []) + det.get("auth", []) + det.get("misc", [])
             + secret_findings)
    return {
        "ok": True,
        "source": "runtime-dumped-dex",
        "root": det["root"], "ssl": det["ssl"],
        "extra": extra,
        "discovered": det["discovered"],
        "stats": {"dex_dumped": len(dexes), "files_scanned": scanned,
                  "smali_trees": len(up.smali_dirs), "have_java": bool(up.java_dir)},
    }

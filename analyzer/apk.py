"""
APK static analyzer.

Single-pass design: iterate the zip once, and for every dex / native lib /
text-ish resource, (a) accumulate signature pattern matches, (b) detect the app
framework, and (c) run the MASVS secret/weak-crypto scanners so each hit carries
the exact file it came from. Manifest-based config checks use androguard.

Signature matching on raw bytes is robust because dex class names and string
constants are stored as plain (M)UTF-8.
"""

import zipfile
import warnings

from . import signatures as S
from . import masvs
from . import storage
from . import manifest_checks
from . import signing
from . import surface

warnings.filterwarnings("ignore")

_DB_EXT = (".db", ".sqlite", ".sqlite3", ".db3", ".realm")

# Files worth scanning for secrets / weak-crypto strings (by extension).
_SCAN_EXT = (".dex", ".so", ".xml", ".json", ".js", ".properties", ".txt", ".arsc",
             ".pem", ".cer", ".der", ".crt", ".cfg", ".yml", ".yaml", ".env",
             ".sql", ".html", ".kotlin_builtins")
_DEX_CAP = 96 * 1024 * 1024      # per-file read cap
_OTHER_CAP = 16 * 1024 * 1024

# Package prefixes that ship their own TrustManagers legitimately.
_LIB_TM_PREFIXES = (
    "Lokhttp3", "Lokio", "Landroid", "Ljava", "Ljavax", "Lkotlin", "Lcom/android",
    "Lorg/bouncycastle", "Lorg/spongycastle", "Lcom/google", "Lorg/apache",
    "Lretrofit2", "Lcom/squareup", "Lio/grpc", "Lorg/conscrypt", "Lorg/chromium",
    "Lcom/datatheorem", "Ltrustkit", "Lcz/msebera", "Lcom/facebook/react/modules/network",
)


def _meta(apk_path):
    meta = {"package": None, "version_name": None, "version_code": None,
            "min_sdk": None, "target_sdk": None, "nsc_referenced": False,
            "debuggable": None, "permissions_count": None}
    try:
        from androguard.core.apk import APK
        a = APK(apk_path)
        meta["package"] = a.get_package()
        meta["version_name"] = a.get_androidversion_name()
        meta["version_code"] = a.get_androidversion_code()
        meta["min_sdk"] = a.get_min_sdk_version()
        meta["target_sdk"] = a.get_target_sdk_version()
        try:
            meta["permissions_count"] = len(a.get_permissions() or [])
        except Exception:
            pass
        try:
            meta["nsc_referenced"] = bool(a.get_element("application", "networkSecurityConfig"))
            dbg = a.get_element("application", "debuggable")
            meta["debuggable"] = (str(dbg).lower() == "true") if dbg is not None else None
        except Exception:
            pass
        return meta, a
    except Exception as e:
        meta["error"] = f"androguard: {e}"
        return meta, None


def _decode_nsc(a, names):
    if a is None:
        return False, None, None
    candidates = [n for n in names
                  if "network_security_config" in n.lower()
                  or (n.startswith("res/xml/") and n.endswith(".xml"))]
    for n in candidates:
        try:
            raw = a.get_file(n)
        except Exception:
            continue
        text = None
        try:
            from androguard.core.axml import AXMLPrinter
            text = AXMLPrinter(raw).get_buff().decode("utf-8", "replace")
        except Exception:
            try:
                text = raw.decode("utf-8", "replace")
            except Exception:
                text = None
        if text and ("pin-set" in text or "<pin " in text or "cleartextTrafficPermitted" in text):
            has_pin = "pin-set" in text or "<pin " in text
            cleartext = None
            if "cleartextTrafficPermitted=\"true\"" in text:
                cleartext = True
            elif "cleartextTrafficPermitted=\"false\"" in text:
                cleartext = False
            return has_pin, cleartext, text[:600]
    return False, None, None


def _verify_custom_tm(apk_path, dex_len):
    """#2: confirm/deny a *custom* (non-library) TrustManager via class analysis."""
    if dex_len > 25 * 1024 * 1024:
        return None
    try:
        from androguard.misc import AnalyzeAPK
        _, _, dx = AnalyzeAPK(apk_path)
    except Exception:
        return None
    custom, any_tm = False, False
    try:
        for ca in dx.get_classes():
            try:
                impls = ca.implements
                impls = impls() if callable(impls) else impls
                impls = [str(x) for x in (impls or [])]
            except Exception:
                impls = []
            if not any("X509TrustManager" in i or "HostnameVerifier" in i for i in impls):
                continue
            any_tm = True
            name = str(ca.name() if callable(ca.name) else ca.name)
            if not name.startswith(_LIB_TM_PREFIXES):
                custom = True
                break
    except Exception:
        return None
    return "confirmed" if custom else ("library-only" if any_tm else None)


def _fires(sig, matched_set):
    pats = sig.get("patterns", [])
    if not pats:
        return False
    if sig.get("all_required"):
        return len(matched_set) == len(pats)
    return len(matched_set) >= 1


def _mk(sig, matched_set, extra=None):
    ev = ", ".join(sorted(p.decode("utf-8", "replace") for p in matched_set)[:4])
    m = {"id": sig["id"], "name": sig["name"], "category": sig["category"],
         "layer": sig["layer"], "confidence": sig["confidence"],
         "desc": sig["desc"], "evidence": ev, "guides": sig.get("guides", [])}
    if extra:
        m.update(extra)
    return m


def analyze(apk_path):
    meta, a = _meta(apk_path)
    ssl_sigs = [s for s in S.ANDROID_SSL if s["id"] != "network-security-config"]
    all_sigs = S.ANDROID_ROOT + ssl_sigs
    matched = {s["id"]: set() for s in all_sigs}
    fw_found = {}
    secret_raw, crypto_raw = [], []
    storage_presence = {}
    surface_acc = {}
    bundled_dbs = []
    dex_bytes = native_bytes = 0
    names = []

    with zipfile.ZipFile(apk_path) as z:
        for info in z.infolist():
            n = info.filename
            names.append(n)
            low = n.lower()
            # bundled databases shipped in the app (assets/, res/raw, …)
            if low.endswith(_DB_EXT):
                try:
                    with z.open(n) as f:
                        bundled_dbs.append((n, f.read(24 * 1024 * 1024)))
                except Exception:
                    pass
                continue
            if not low.endswith(_SCAN_EXT):
                continue
            is_dex, is_so = low.endswith(".dex"), low.endswith(".so")
            cap = _DEX_CAP if is_dex else _OTHER_CAP
            try:
                if info.file_size > cap:
                    with z.open(n) as f:
                        b = f.read(cap)
                else:
                    b = z.read(n)
            except Exception:
                continue
            if is_dex:
                dex_bytes += len(b)
            elif is_so:
                native_bytes += len(b)

            for sig in all_sigs:
                ms = matched[sig["id"]]
                for p in sig["patterns"]:
                    if p not in ms and p in b:
                        ms.add(p)
            for fw in S.ANDROID_FRAMEWORKS:
                if fw["id"] in fw_found:
                    continue
                for p in fw["patterns"]:
                    if p in b:
                        fw_found[fw["id"]] = fw
                        break

            secret_raw += masvs.scan_secrets(b, n)
            crypto_raw += masvs.scan_crypto(b, n)
            storage.scan(b, n, storage_presence)
            surface.scan(b, surface_acc)

    # framework detection by native lib file name too
    joined = ("\n".join(names)).encode("utf-8", "replace")
    for fw in S.ANDROID_FRAMEWORKS:
        if fw["id"] in fw_found:
            continue
        for p in fw["patterns"]:
            if p in joined:
                fw_found[fw["id"]] = fw
                break

    root_hits = [_mk(s, matched[s["id"]]) for s in S.ANDROID_ROOT if _fires(s, matched[s["id"]])]
    ssl_hits = [_mk(s, matched[s["id"]]) for s in ssl_sigs if _fires(s, matched[s["id"]])]

    # #2 verify noisy custom-TrustManager
    if any(m["id"] == "custom-trustmanager" for m in ssl_hits):
        verdict = _verify_custom_tm(apk_path, dex_bytes)
        for m in ssl_hits:
            if m["id"] != "custom-trustmanager":
                continue
            if verdict == "confirmed":
                m["confidence"] = "high"; m["verified"] = True
                m["desc"] += " (Confirmed: a non-library class implements this.)"
            elif verdict == "library-only":
                m["confidence"] = "low"; m["verified"] = False
                m["desc"] += " (Only library TrustManagers found — likely a false positive.)"
            else:
                m["verified"] = None

    # network security config pin-set
    notes = []
    has_pin, cleartext, snippet = _decode_nsc(a, names)
    if has_pin:
        nsc_sig = next(s for s in S.ANDROID_SSL if s["id"] == "network-security-config")
        ssl_hits.append(_mk(nsc_sig, {b"res/xml/network_security_config.xml <pin-set>"},
                            extra={"config_snippet": snippet}))
    if cleartext is True:
        notes.append("Network Security Config permits cleartext traffic (cleartextTrafficPermitted=true).")

    frameworks = [{"id": fw["id"], "name": fw["name"], "note": fw["note"], "guides": fw.get("guides", [])}
                  for fw in fw_found.values()]
    for fw in frameworks:
        if fw["id"] == "flutter":
            notes.append("Flutter detected: SSL pinning bypass requires reFlutter or a libflutter.so "
                         "native hook — standard Java/objection hooks will NOT work.")
        if fw["id"] in ("xamarin", "unity"):
            notes.append(f"{fw['name']} detected: HTTP stack is native/managed — Java SSL hooks may miss it.")

    pkg = (meta or {}).get("package")
    db_findings = []
    for dbname, dbdata in bundled_dbs:
        f = storage.parse_bundled_db(dbname, dbdata, masvs.scan_secrets, masvs.scan_pii)
        if f:
            db_findings.append(f)
    sign_meta, sign_findings = signing.analyze(a, (meta or {}).get("min_sdk"))
    extra = (sign_findings
             + masvs.build_secret_findings(secret_raw)
             + masvs.build_crypto_findings(crypto_raw)
             + masvs.android_config(a, pkg)
             + manifest_checks.analyze(a, pkg)
             + storage.build_code_findings(storage_presence)
             + db_findings)

    return {
        "platform": "android",
        "meta": meta,
        "signing": sign_meta,
        "surface": surface.finalize(surface_acc),
        "ipc": surface.ipc(a, pkg),
        "frameworks": frameworks,
        "extra": extra,
        "root": {"implemented": len(root_hits) > 0, "layers": len(root_hits), "mechanisms": root_hits},
        "ssl": {"implemented": len(ssl_hits) > 0, "layers": len(ssl_hits), "mechanisms": ssl_hits},
        "notes": notes,
        "stats": {"dex_bytes": dex_bytes, "native_bytes": native_bytes, "entries": len(names)},
    }

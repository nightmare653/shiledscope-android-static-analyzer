"""
IPA static analyzer.

Strategy:
  * Unzip in-memory, find Payload/<App>.app and its Info.plist (CFBundleExecutable).
  * Read the main Mach-O binary + linked frameworks; scan raw bytes for the
    iOS jailbreak & SSL-pinning signatures.
  * Use LIEF (if available) to read the Mach-O: imported symbols (stronger
    signal than a raw scan) and the LC_ENCRYPTION_INFO cryptid (App Store
    FairPlay encryption — which limits static analysis).
  * Note embedded .cer/.der certs (a strong hint of certificate pinning) and
    bundled frameworks (TrustKit.framework, Alamofire, etc.).
"""

import io
import os
import plistlib
import zipfile
import warnings

from . import signatures as S
from . import masvs
from . import storage
from . import surface

warnings.filterwarnings("ignore")

_CERT_EXTS = (".cer", ".der", ".crt", ".pem", ".p12")


def _read_zip(ipa_path):
    z = zipfile.ZipFile(ipa_path)   # kept open; caller closes
    return z, z.namelist()


def _app_root(names):
    for n in names:
        parts = n.split("/")
        if len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app"):
            return f"Payload/{parts[1]}"
    return None


def _info_plist(z, app_root):
    try:
        raw = z.read(f"{app_root}/Info.plist")
        return plistlib.loads(raw)
    except Exception:
        return {}


def _main_binary_name(info, app_root):
    exe = info.get("CFBundleExecutable")
    if exe:
        return f"{app_root}/{exe}"
    return None


def _lief_scan(macho_bytes):
    """Return (symbols:set[str], encrypted:bool|None, arch:str|None, pie:bool|None)."""
    syms, encrypted, arch, pie = set(), None, None, None
    try:
        import lief
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".macho") as tf:
            tf.write(macho_bytes)
            tmp = tf.name
        try:
            fat = lief.MachO.parse(tmp)
            bins = list(fat) if fat is not None else []
            for b in bins:
                try:
                    arch = str(b.header.cpu_type)
                except Exception:
                    pass
                try:
                    for s in b.symbols:
                        syms.add(s.name)
                except Exception:
                    pass
                try:
                    if b.has_encryption_info:
                        encrypted = b.encryption_info.crypt_id != 0
                except Exception:
                    pass
                try:
                    pie = lief.MachO.HEADER_FLAGS.PIE in b.header.flags_list
                except Exception:
                    try:
                        pie = bool(b.is_pie)
                    except Exception:
                        pass
        finally:
            try:
                os.unlink(tmp)
            except Exception:
                pass
    except Exception:
        pass
    return syms, encrypted, arch, pie


def _match(sig, blob, symbols):
    pats = sig.get("patterns", [])
    if not pats:
        return False, None
    require_all = sig.get("all_required", False)
    hits = []
    sym_join = ("\n".join(symbols)).encode("utf-8", "replace") if symbols else b""
    for p in pats:
        found = (p in blob) or (p in sym_join)
        if found:
            hits.append(p.decode("utf-8", "replace"))
        elif require_all:
            return False, None
    if hits:
        return True, ", ".join(sorted(set(hits))[:4])
    return False, None


def _mk(sig, evidence, extra=None):
    m = {
        "id": sig["id"], "name": sig["name"], "category": sig["category"],
        "layer": sig["layer"], "confidence": sig["confidence"],
        "desc": sig["desc"], "evidence": evidence, "guides": sig.get("guides", []),
    }
    if extra:
        m.update(extra)
    return m


def analyze(ipa_path):
    z, names = _read_zip(ipa_path)
    app_root = _app_root(names)
    notes = []
    meta = {"bundle_id": None, "version": None, "min_os": None,
            "executable": None, "encrypted": None, "arch": None}

    if not app_root:
        z.close()
        return {"platform": "ios", "error": "No Payload/*.app found — not a valid IPA?",
                "meta": meta, "root": _empty(), "ssl": _empty(), "notes": [], "frameworks": []}

    info = _info_plist(z, app_root)
    meta["bundle_id"] = info.get("CFBundleIdentifier")
    meta["version"] = info.get("CFBundleShortVersionString") or info.get("CFBundleVersion")
    meta["min_os"] = info.get("MinimumOSVersion")

    bin_path = _main_binary_name(info, app_root)
    macho = b""
    if bin_path and bin_path in names:
        meta["executable"] = os.path.basename(bin_path)
        try:
            macho = z.read(bin_path)
        except Exception:
            macho = b""

    # Also fold in framework binaries' bytes (bounded) for signature coverage.
    fw_names = [n for n in names if "/Frameworks/" in n and n.endswith(".framework/") is False
                and "." not in os.path.basename(n) and app_root in n]
    extra_blob = bytearray(macho)
    bundled_frameworks = sorted({n.split("/Frameworks/")[1].split("/")[0]
                                 for n in names if "/Frameworks/" in n
                                 and n.split("/Frameworks/")[1]})
    for n in names:
        if "/Frameworks/" in n and os.path.splitext(n)[1] == "" and not n.endswith("/"):
            try:
                extra_blob += z.read(n)[:3 * 1024 * 1024]
            except Exception:
                pass

    symbols, encrypted, arch, pie = _lief_scan(macho) if macho else (set(), None, None, None)
    meta["encrypted"] = encrypted
    meta["arch"] = arch
    if encrypted:
        notes.append("Main binary is FairPlay-ENCRYPTED (App Store build). Static signatures below "
                     "may be incomplete — decrypt first (frida-ios-dump / a decrypted IPA) for full coverage.")

    blob = bytes(extra_blob)

    # Embedded certs (strong pinning hint)
    embedded_certs = [n for n in names if n.lower().endswith(_CERT_EXTS) and app_root in n]

    root_hits, ssl_hits = [], []
    for sig in S.IOS_JAILBREAK:
        ok, ev = _match(sig, blob, symbols)
        if ok:
            root_hits.append(_mk(sig, ev))

    for sig in S.IOS_SSL:
        if sig["id"] == "embedded-cert":
            continue
        ok, ev = _match(sig, blob, symbols)
        if ok:
            ssl_hits.append(_mk(sig, ev))

    if embedded_certs:
        cert_sig = next(s for s in S.IOS_SSL if s["id"] == "embedded-cert")
        ssl_hits.append(_mk(cert_sig, ", ".join(os.path.basename(c) for c in embedded_certs[:4]),
                            extra={"cert_files": embedded_certs}))

    # Bundled framework hints
    fw_hits = []
    for fwname in bundled_frameworks:
        low = fwname.lower()
        if "trustkit" in low:
            fw_hits.append({"id": "trustkit-ios", "name": "TrustKit.framework bundled"})
        if "alamofire" in low:
            fw_hits.append({"id": "alamofire", "name": "Alamofire.framework bundled"})
        if "afnetworking" in low:
            fw_hits.append({"id": "afnetworking", "name": "AFNetworking.framework bundled"})

    # located secret / weak-crypto / storage scan across the binary + bundle files
    secret_raw, crypto_raw = [], []
    storage_presence, db_findings, surface_acc = {}, [], {}
    exe_loc = meta["executable"] or "binary"
    if macho:
        secret_raw += masvs.scan_secrets(macho, exe_loc)
        crypto_raw += masvs.scan_crypto(macho, exe_loc)
        storage.ios_scan(macho, exe_loc, storage_presence)
        surface.scan(macho, surface_acc)
    _IOS_TEXT = (".plist", ".json", ".mobileprovision", ".strings", ".js", ".xml",
                 ".txt", ".pem", ".cer", ".der", ".html")
    _IOS_DB = (".sqlite", ".sqlite3", ".db", ".db3")
    for n in names:
        low = n.lower()
        rel = n.split(app_root + "/", 1)[-1] if app_root in n else n
        if low.endswith(_IOS_DB):
            try:
                b = z.read(n)[:24 * 1024 * 1024]
            except Exception:
                continue
            f = storage.parse_bundled_db(rel, b, masvs.scan_secrets, masvs.scan_pii)
            if f:
                db_findings.append(f)
        elif low.endswith(_IOS_TEXT):
            try:
                b = z.read(n)
            except Exception:
                continue
            secret_raw += masvs.scan_secrets(b, rel)
            crypto_raw += masvs.scan_crypto(b, rel)
            surface.scan(b, surface_acc)
        elif "/Frameworks/" in n and os.path.splitext(n)[1] == "" and not n.endswith("/"):
            try:
                b = z.read(n)[:6 * 1024 * 1024]
            except Exception:
                continue
            secret_raw += masvs.scan_secrets(b, rel)
            storage.ios_scan(b, rel, storage_presence)

    extra = (masvs.build_secret_findings(secret_raw)
             + masvs.build_crypto_findings(crypto_raw)
             + masvs.ios_config(info)
             + storage.build_ios_code_findings(storage_presence)
             + _entitlements_findings(z, app_root, names)
             + _ios_url_findings(info)
             + _ios_behavior_findings(blob, symbols, pie, bool(encrypted))
             + db_findings)
    z.close()

    return {
        "platform": "ios",
        "meta": meta,
        "extra": extra,
        "surface": surface.finalize(surface_acc),
        "frameworks": [{"id": "bundle", "name": f"{len(bundled_frameworks)} embedded frameworks",
                        "note": ", ".join(bundled_frameworks[:12]) + ("…" if len(bundled_frameworks) > 12 else ""),
                        "guides": []}] if bundled_frameworks else [],
        "root": {"implemented": len(root_hits) > 0, "layers": len(root_hits), "mechanisms": root_hits},
        "ssl": {"implemented": len(ssl_hits) > 0, "layers": len(ssl_hits), "mechanisms": ssl_hits},
        "notes": notes,
        "stats": {"macho_bytes": len(macho), "symbols": len(symbols),
                  "entries": len(names), "embedded_certs": len(embedded_certs)},
    }


def _empty():
    return {"implemented": False, "layers": 0, "mechanisms": []}


def _entitlements_findings(z, app_root, names):
    """Parse embedded.mobileprovision for insecure entitlements: get-task-allow
    (the app is debuggable in production) and wildcard app-ids."""
    F = []
    mp = app_root + "/embedded.mobileprovision"
    if mp not in names:
        return F
    try:
        raw = z.read(mp)
    except Exception:
        return F
    i, j = raw.find(b"<plist"), raw.find(b"</plist>")
    if i == -1 or j == -1:
        return F
    try:
        pl = plistlib.loads(raw[i:j + 8])
    except Exception:
        return F
    ent = pl.get("Entitlements", {}) if isinstance(pl, dict) else {}
    if ent.get("get-task-allow") is True:
        F.append({
            "id": "ios-get-task-allow",
            "title": "App is debuggable in production (get-task-allow=true)",
            "severity": "high", "category": "config",
            "location": "embedded.mobileprovision -> Entitlements.get-task-allow",
            "evidence": "get-task-allow = true",
            "description": "The provisioning profile grants get-task-allow, so the shipped app can be "
                           "attached to by a debugger and have its memory read on a normal device.",
            "risk": "Anyone can attach lldb/Frida to the process, dump memory and runtime secrets, and "
                    "trace execution — this is a development/ad-hoc entitlement that must not ship.",
            "reproduce": ["`security cms -D -i embedded.mobileprovision | plutil -p -` and check "
                          "Entitlements.get-task-allow.",
                          "On a device, attach: `lldb -n <App>` or `frida -U -n <App>`."],
            "mitigation": "Ship App Store / distribution builds (get-task-allow=false). Never release an "
                          "ad-hoc/development-signed build.",
            "masvs": "MASVS-RESILIENCE-2"})
    appid = ent.get("application-identifier", "") or ent.get("com.apple.application-identifier", "")
    if isinstance(appid, str) and appid.endswith("*"):
        F.append({
            "id": "ios-wildcard-appid",
            "title": "Wildcard application-identifier in provisioning profile",
            "severity": "low", "category": "config",
            "location": "embedded.mobileprovision -> Entitlements.application-identifier",
            "evidence": appid,
            "description": "The app is signed with a wildcard App ID (%s)." % appid,
            "risk": "Wildcard App IDs cannot use App ID-scoped services (keychain sharing, app groups, "
                    "push) securely and often indicate a loosely-managed signing setup.",
            "reproduce": ["Inspect Entitlements.application-identifier in the provisioning profile."],
            "mitigation": "Use an explicit App ID per app and scope entitlements tightly.",
            "masvs": "MASVS-CODE-1"})
    return F


# ---------------------------------------------------------------------------
#  iOS URL schemes / universal links / behavioural string+symbol signals
# ---------------------------------------------------------------------------
def _ios_url_findings(info):
    """Custom URL schemes the app registers (attacker-invocable deep links)."""
    F = []
    schemes = []
    for t in (info or {}).get("CFBundleURLTypes", []) or []:
        for s in (t.get("CFBundleURLSchemes") or []):
            if s:
                schemes.append(s)
    schemes = sorted(set(schemes))
    if schemes:
        F.append({
            "id": "ios-url-scheme",
            "title": "Custom URL schemes registered (%d)" % len(schemes),
            "severity": "low", "category": "platform",
            "location": "Info.plist -> CFBundleURLTypes",
            "evidence": ", ".join(schemes[:12]) + ("..." if len(schemes) > 12 else ""),
            "description": "The app registers custom URL scheme(s): %s. Any app (or a web page) can open "
                           "these and pass parameters the app will parse." % ", ".join(schemes[:12]),
            "risk": "Custom schemes are not verified (unlike Universal Links), so a malicious app can "
                    "impersonate them, and crafted parameters can drive deep-link handlers, WebViews or "
                    "auth callbacks (open redirect / account takeover / parameter injection).",
            "reproduce": ["Open the scheme: xcrun simctl openurl booted '%s://host/path?x=1' (or Safari)." % schemes[0],
                          "Fuzz the handler params; check for sensitive data in the URL or missing validation."],
            "mitigation": "Prefer Universal Links (verified) for sensitive flows; validate every parameter and never "
                          "trust scheme input for auth or to build file paths/WebView URLs.",
            "masvs": "MASVS-PLATFORM-1"})
    return F


# (id, [byte tokens], severity, title, desc, risk, repro[list], mit)
_IOS_STRING_SIGNALS = [
    ("ios-wkwebview-file", [b"allowFileAccessFromFileURLs", b"allowingReadAccessToURL"], "medium",
     "WKWebView file access configured",
     "The binary enables WKWebView file access (allowFileAccessFromFileURLs / allowingReadAccessToURL).",
     "Allowing file:// access lets JavaScript in a file context read local files (app data, cookies); a file:// "
     "XSS becomes local-file theft.",
     ["Check whether untrusted HTML can be loaded with file access enabled."],
     "Do not grant file access to a WKWebView loading untrusted content; scope allowingReadAccessToURL tightly."),
    ("ios-keychain-weak", [b"kSecAttrAccessibleAlways"], "medium",
     "Weak Keychain accessibility (kSecAttrAccessibleAlways)",
     "Keychain items are stored with kSecAttrAccessibleAlways(ThisDeviceOnly) - accessible even when locked.",
     "Items readable while locked are exposed to lock-screen / offline-extraction attacks.",
     ["Enumerate keychain items (objection: ios keychain dump) and check the accessibility attribute."],
     "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or WhenPasscodeSetThisDeviceOnly) for secrets."),
    ("ios-local-auth", [b"LAContext", b"evaluatePolicy"], "info",
     "Local / biometric authentication present (LocalAuthentication)",
     "The app uses LAContext/evaluatePolicy (Face ID / Touch ID).",
     "If evaluatePolicy only gates the UI, it is Frida/objection-bypassable; the protected action must be bound to "
     "a Keychain/Secure-Enclave key requiring biometric auth and re-checked server-side.",
     ["Objection: ios ui biometrics_bypass, or hook evaluatePolicy's reply block to success.",
      "Confirm the sensitive action still requires the backend after the bypass."],
     "Bind the protected secret to a SecAccessControl with biometryCurrentSet; never trust the boolean alone."),
    ("ios-fileprotection-none", [b"NSFileProtectionNone"], "medium",
     "Data Protection disabled (NSFileProtectionNone)",
     "The app writes files with NSFileProtectionNone, so they are not encrypted at rest.",
     "Unprotected files are readable from a backup or an offline/locked-device extraction.",
     ["Identify files written with NSFileProtectionNone and whether they hold sensitive data."],
     "Use NSFileProtectionComplete (or CompleteUnlessOpen) for sensitive files."),
    ("ios-hotpatch", [b"JSPatch", b"CodePush", b"Rollout.io"], "medium",
     "Dynamic code-update / hot-patch framework",
     "The app bundles a hot-patch / dynamic code framework (JSPatch / CodePush / Rollout).",
     "Server-delivered code can bypass App Store review and, if the channel is MITM-able or compromised, lead to "
     "remote code execution.",
     ["Identify the update channel and whether it is TLS-pinned and signature-verified."],
     "Avoid remote code delivery; if used, pin TLS and verify a signature on every payload."),
]


def _ios_behavior_findings(blob, symbols, pie, encrypted):
    """iOS string/symbol signals + binary hardening (PIE / stack-canary / ARC)."""
    F = []
    for sid, tokens, sev, title, desc, risk, repro, mit in _IOS_STRING_SIGNALS:
        hit = next((t for t in tokens if t in blob), None)
        if not hit:
            continue
        F.append({
            "id": sid, "title": title, "severity": sev, "category": "platform",
            "location": "app binary", "evidence": hit.decode("ascii", "replace"),
            "description": desc, "risk": risk, "reproduce": repro, "mitigation": mit,
            "masvs": "MASVS-PLATFORM-2"})
    if symbols and any(s in ("_NSLog", "NSLog") for s in symbols):
        F.append({
            "id": "ios-nslog", "title": "NSLog logging present", "severity": "info",
            "category": "storage", "location": "app binary", "evidence": "NSLog",
            "description": "The binary calls NSLog, which writes to the unified logging system.",
            "risk": "NSLog output can leak tokens/PII to device logs readable via Console/sysdiagnose.",
            "reproduce": ["Stream the device log (Console.app / log stream) while exercising the app."],
            "mitigation": "Strip NSLog in release; never log secrets/PII.", "masvs": "MASVS-STORAGE-2"})
    if not encrypted and pie is not None:
        missing = []
        if pie is False:
            missing.append("PIE/ASLR")
        if symbols and not any("__stack_chk_fail" in s for s in symbols):
            missing.append("stack-canary")
        if symbols and not any(("objc_release" in s) or ("objc_storeStrong" in s)
                               or ("swift_release" in s) for s in symbols):
            missing.append("ARC")
        if missing:
            F.append({
                "id": "ios-native-hardening",
                "title": "Binary missing exploit mitigations (%s)" % ", ".join(missing),
                "severity": "low", "category": "hardening", "location": "app binary",
                "evidence": ", ".join(missing),
                "description": "The main Mach-O is built without standard mitigations: " + ", ".join(missing) + ".",
                "risk": "Missing PIE (no ASLR), stack canary or ARC makes memory-corruption bugs materially easier to exploit.",
                "reproduce": ["otool -hv <binary> (PIE flag); otool -Iv | grep stack_chk (canary)."],
                "mitigation": "Rebuild with -fPIE -pie, -fstack-protector-strong, and ARC enabled.",
                "masvs": "MASVS-CODE-4"})
    return F

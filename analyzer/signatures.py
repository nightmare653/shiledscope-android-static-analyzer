"""
Signature knowledge base for ShieldScope.

Each signature is matched against raw bytes pulled from the app:
  - APK: concatenated classes*.dex bytes  (+ native .so bytes for layer == "native")
  - IPA: Mach-O strings/symbols          (+ bundle file listing)

`patterns` are byte-substrings. A signature fires if ANY pattern is present
(unless `all_required` is True, then ALL must be present).

Fields
------
id           unique key, also used to look up bypass guides in guides.py
name         human label
category     "root" | "ssl"
layer        "java" | "native" | "config" | "framework"  (drives bypass difficulty)
confidence   "high" | "medium" | "low"
platform     "android" | "ios" | "both"
patterns     list[bytes] to search for
all_required if True, every pattern must be found (AND); default ANY (OR)
desc         short explanation shown in the report
guides       list of guide ids (see guides.py) recommended for this mechanism
"""

# ---------------------------------------------------------------------------
# ANDROID  --  ROOT DETECTION
# ---------------------------------------------------------------------------
ANDROID_ROOT = [
    {
        "id": "rootbeer",
        "name": "RootBeer library",
        "category": "root", "layer": "java", "confidence": "high", "platform": "android",
        "patterns": [b"com/scottyab/rootbeer", b"Lcom/scottyab/rootbeer"],
        "desc": "The popular RootBeer library aggregates ~9 root checks (su paths, "
                "test-keys, dangerous props, RW system paths, BusyBox, etc.).",
        "guides": ["frida-rootbeer", "objection-root", "magisk-denylist"],
    },
    {
        "id": "su-path-check",
        "name": "su binary path check",
        "category": "root", "layer": "java", "confidence": "high", "platform": "android",
        "patterns": [b"/system/xbin/su", b"/system/bin/su", b"/sbin/su", b"/su/bin/su",
                     b"/system/bin/failsafe/su", b"/data/local/xbin/su"],
        "desc": "The app looks for the `su` binary in common locations on disk.",
        "guides": ["frida-file-exists", "objection-root", "magisk-denylist", "smali-patch-root"],
    },
    {
        "id": "root-packages",
        "name": "Root-management package check",
        "category": "root", "layer": "java", "confidence": "high", "platform": "android",
        "patterns": [b"com.noshufou.android.su", b"eu.chainfire.supersu",
                     b"com.koushikdutta.superuser", b"com.topjohnwu.magisk",
                     b"com.thirdparty.superuser", b"com.zachspong.temprootremovejb"],
        "desc": "The app enumerates installed packages looking for SuperSU / Magisk Manager / Superuser.",
        "guides": ["objection-root", "magisk-denylist", "frida-rootbeer"],
    },
    {
        "id": "test-keys",
        "name": "Build tags 'test-keys' check",
        "category": "root", "layer": "java", "confidence": "medium", "platform": "android",
        "patterns": [b"test-keys"],
        "desc": "Checks android.os.Build.TAGS for `test-keys`, indicating a custom/dev ROM.",
        "guides": ["frida-rootbeer", "objection-root", "magisk-props"],
    },
    {
        "id": "magisk-artifacts",
        "name": "Magisk artifact / path check",
        "category": "root", "layer": "java", "confidence": "high", "platform": "android",
        "patterns": [b"magisk", b"MagiskManager", b"/sbin/.magisk", b"magisk.db"],
        "desc": "Directly probes for Magisk files, the magisk mount namespace or its unix socket.",
        "guides": ["magisk-denylist", "magisk-shamiko", "frida-rootbeer"],
    },
    {
        "id": "busybox-which",
        "name": "BusyBox / `which su` check",
        "category": "root", "layer": "java", "confidence": "medium", "platform": "android",
        "patterns": [b"busybox", b"/system/xbin/busybox", b"which"],
        "all_required": False,
        "desc": "Runtime.exec(\"which su\") or a BusyBox lookup to detect root tooling.",
        "guides": ["frida-exec", "objection-root", "magisk-denylist"],
    },
    {
        "id": "safetynet",
        "name": "SafetyNet Attestation",
        "category": "root", "layer": "framework", "confidence": "high", "platform": "android",
        "patterns": [b"com/google/android/gms/safetynet", b"SafetyNetApi", b"attest"],
        "desc": "Google SafetyNet attestation (deprecated) validates device integrity server-side. "
                "Hard to bypass without a strong hook (attestation is signed by Google).",
        "guides": ["safetynet-bypass", "magisk-denylist"],
    },
    {
        "id": "play-integrity",
        "name": "Play Integrity API",
        "category": "root", "layer": "framework", "confidence": "high", "platform": "android",
        "patterns": [b"com/google/android/play/core/integrity", b"IntegrityManager",
                     b"StandardIntegrityManager"],
        "desc": "Play Integrity API (SafetyNet successor). Verdict is signed by Google and checked "
                "server-side — the hardest layer to bypass.",
        "guides": ["play-integrity-fix", "magisk-denylist"],
    },
    {
        "id": "freerasp",
        "name": "freeRASP / commercial RASP",
        "category": "root", "layer": "native", "confidence": "medium", "platform": "android",
        "patterns": [b"talsec", b"freerasp", b"libToken", b"AppSecureRoom"],
        "desc": "Runtime Application Self-Protection SDK (Talsec freeRASP or similar) performing "
                "root/hook/emulator/tamper checks partly in native code.",
        "guides": ["frida-native-rasp", "magisk-denylist"],
    },
    {
        "id": "dexguard-rasp",
        "name": "DexGuard / commercial hardening",
        "category": "root", "layer": "native", "confidence": "low", "platform": "android",
        "patterns": [b"dexguard", b"com/guardsquare"],
        "desc": "Guardsquare DexGuard RASP: obfuscated, native, self-integrity + root checks. "
                "Static signatures are weak here; expect heavy obfuscation.",
        "guides": ["frida-native-rasp", "magisk-denylist"],
    },
    {
        "id": "emulator-check",
        "name": "Emulator detection",
        "category": "root", "layer": "java", "confidence": "medium", "platform": "android",
        "patterns": [b"goldfish", b"ranchu", b"/dev/qemu_pipe", b"generic_x86",
                     b"vbox86", b"genymotion"],
        "desc": "Detects Android emulators (QEMU/Genymotion/VirtualBox) via build props & device files. "
                "Often paired with root detection.",
        "guides": ["frida-rootbeer", "objection-root"],
    },
]

# ---------------------------------------------------------------------------
# ANDROID  --  SSL PINNING
# ---------------------------------------------------------------------------
ANDROID_SSL = [
    {
        "id": "okhttp-pinner",
        "name": "OkHttp CertificatePinner",
        "category": "ssl", "layer": "java", "confidence": "high", "platform": "android",
        "patterns": [b"okhttp3/CertificatePinner", b"CertificatePinner",
                     b"sha256/", b"Certificate pinning failure"],
        "desc": "OkHttp's built-in CertificatePinner with sha256/ public-key pins.",
        "guides": ["objection-ssl-android", "frida-ssl-universal", "frida-okhttp"],
    },
    {
        "id": "network-security-config",
        "name": "Network Security Config <pin-set>",
        "category": "ssl", "layer": "config", "confidence": "high", "platform": "android",
        "patterns": [b"<pin-set", b"pin digest"],  # detected via decoded XML, see apk.py
        "desc": "Declarative pinning in res/xml/network_security_config.xml (<pin-set>).",
        "guides": ["nsc-repack", "frida-ssl-universal", "objection-ssl-android"],
    },
    {
        "id": "trustkit-android",
        "name": "TrustKit (Android)",
        "category": "ssl", "layer": "framework", "confidence": "high", "platform": "android",
        "patterns": [b"com/datatheorem/android/trustkit", b"trustkit"],
        "desc": "DataTheorem TrustKit pinning framework driven by the network security config.",
        "guides": ["frida-ssl-universal", "objection-ssl-android", "nsc-repack"],
    },
    {
        "id": "custom-trustmanager",
        "name": "Custom X509TrustManager / HostnameVerifier",
        "category": "ssl", "layer": "java", "confidence": "medium", "platform": "android",
        "patterns": [b"checkServerTrusted", b"X509TrustManager", b"HostnameVerifier"],
        "all_required": False,
        "desc": "A custom TrustManager/HostnameVerifier — often a hand-rolled pinning or "
                "cert-validation routine. (Also present in some libraries; verify manually.)",
        "guides": ["frida-ssl-universal", "objection-ssl-android"],
    },
    {
        "id": "webview-sslerror",
        "name": "WebView onReceivedSslError handling",
        "category": "ssl", "layer": "java", "confidence": "medium", "platform": "android",
        "patterns": [b"onReceivedSslError"],
        "desc": "WebView SSL error callback — may enforce (or dangerously ignore) certificate errors.",
        "guides": ["frida-webview-ssl"],
    },
    {
        "id": "conscrypt-native-ssl",
        "name": "Native / BoringSSL pinning",
        "category": "ssl", "layer": "native", "confidence": "medium", "platform": "android",
        "patterns": [b"ssl_verify_cert_chain", b"boringssl", b"X509_verify_cert",
                     b"ssl_crypto_x509"],
        "desc": "Pinning or cert-chain verification implemented in a native .so (BoringSSL/OpenSSL). "
                "Java hooks won't reach it — needs a native hook.",
        "guides": ["frida-native-ssl", "objection-ssl-android"],
    },
]

# ---------------------------------------------------------------------------
# APP FRAMEWORK DETECTION (Android)  --  changes which bypass applies
# ---------------------------------------------------------------------------
# Patterns here are deliberately DISTINCTIVE (native lib file names / unique class
# paths) to avoid false positives from a stray lowercase word appearing in a string.
ANDROID_FRAMEWORKS = [
    {"id": "flutter", "name": "Flutter", "patterns": [b"libflutter.so", b"Lio/flutter/", b"flutter_assets"],
     "note": "Flutter has its own BoringSSL trust store and IGNORES the system/user CA store and "
             "network security config. Use reFlutter or a native libflutter.so hook — objection/JSSL "
             "hooks will NOT work.",
     "guides": ["flutter-ssl"]},
    {"id": "react-native", "name": "React Native", "patterns": [b"libreactnativejni.so",
     b"index.android.bundle", b"Lcom/facebook/react/"],
     "note": "Network calls go through OkHttp under the hood, so standard OkHttp/JSSL hooks usually work. "
             "Pinning may also be declared in JS.",
     "guides": ["frida-ssl-universal", "objection-ssl-android"]},
    {"id": "xamarin", "name": "Xamarin / .NET MAUI", "patterns": [b"libmonodroid.so",
     b"libxamarin-app.so", b"Lmono/android/"],
     "note": "HTTP stack is Mono/.NET, not Java. Standard Java SSL hooks miss it; use a Xamarin-aware "
             "Frida script that hooks the mono runtime.",
     "guides": ["frida-ssl-universal"]},
    {"id": "cordova", "name": "Cordova / Ionic", "patterns": [b"Lorg/apache/cordova/", b"cordova_plugins.js"],
     "note": "WebView-based. Pinning (if any) is often a Cordova plugin; check WebView SSL handling too.",
     "guides": ["frida-webview-ssl", "frida-ssl-universal"]},
    {"id": "unity", "name": "Unity", "patterns": [b"libunity.so", b"Lcom/unity3d/player/"],
     "note": "Networking via il2cpp/Mono in native code; needs a native or il2cpp-aware hook.",
     "guides": ["frida-native-ssl"]},
]

# ---------------------------------------------------------------------------
# iOS  --  JAILBREAK DETECTION
# ---------------------------------------------------------------------------
IOS_JAILBREAK = [
    {
        "id": "cydia-path",
        "name": "Cydia / Sileo path check",
        "category": "root", "layer": "objc", "confidence": "high", "platform": "ios",
        "patterns": [b"/Applications/Cydia.app", b"cydia://", b"/Applications/Sileo.app",
                     b"/Applications/Zebra.app"],
        "desc": "Checks for jailbreak app-store bundles / URL schemes (Cydia, Sileo, Zebra).",
        "guides": ["objection-jb", "frida-ios-jb", "sslkillswitch-jb"],
    },
    {
        "id": "jb-files",
        "name": "Jailbreak file/path existence check",
        "category": "root", "layer": "objc", "confidence": "high", "platform": "ios",
        "patterns": [b"/bin/bash", b"/bin/sh", b"/usr/sbin/sshd", b"/etc/apt",
                     b"/private/var/lib/apt", b"/Library/MobileSubstrate/MobileSubstrate.dylib",
                     b"/usr/libexec/cydia"],
        "desc": "Tests for existence of shells, apt, OpenSSH or MobileSubstrate — classic JB artifacts.",
        "guides": ["objection-jb", "frida-ios-jb"],
    },
    {
        "id": "fork-sandbox",
        "name": "fork()/sandbox escape test",
        "category": "root", "layer": "objc", "confidence": "medium", "platform": "ios",
        "patterns": [b"fork", b"vfork", b"sandbox"],
        "all_required": False,
        "desc": "Calls fork()/vfork(): on a non-jailbroken (sandboxed) device this fails; success ⇒ JB.",
        "guides": ["frida-ios-jb", "objection-jb"],
    },
    {
        "id": "canopenurl-cydia",
        "name": "canOpenURL(cydia://) check",
        "category": "root", "layer": "objc", "confidence": "medium", "platform": "ios",
        "patterns": [b"canOpenURL", b"cydia"],
        "all_required": True,
        "desc": "Uses UIApplication canOpenURL: with jailbreak URL schemes.",
        "guides": ["frida-ios-jb", "objection-jb"],
    },
    {
        "id": "ios-security-suite",
        "name": "IOSSecuritySuite / commercial JB SDK",
        "category": "root", "layer": "objc", "confidence": "high", "platform": "ios",
        "patterns": [b"IOSSecuritySuite", b"jailbreak", b"amIJailbroken", b"DTTJailbreak"],
        "desc": "A jailbreak-detection SDK (IOSSecuritySuite or similar) bundling many checks + "
                "anti-debug + reverse-engineering detection.",
        "guides": ["frida-ios-jb", "objection-jb"],
    },
    {
        "id": "ptrace-antidebug",
        "name": "ptrace / sysctl anti-debug",
        "category": "root", "layer": "objc", "confidence": "medium", "platform": "ios",
        "patterns": [b"ptrace", b"PT_DENY_ATTACH", b"sysctl"],
        "all_required": False,
        "desc": "Anti-debugging (ptrace PT_DENY_ATTACH / sysctl P_TRACED) that resists Frida attach.",
        "guides": ["frida-ios-antidebug"],
    },
]

# ---------------------------------------------------------------------------
# iOS  --  SSL PINNING
# ---------------------------------------------------------------------------
IOS_SSL = [
    {
        "id": "trustkit-ios",
        "name": "TrustKit (iOS)",
        "category": "ssl", "layer": "framework", "confidence": "high", "platform": "ios",
        "patterns": [b"TrustKit", b"TSKConfiguration", b"kTSKPublicKeyHashes"],
        "desc": "DataTheorem TrustKit — plist/config-driven public-key pinning.",
        "guides": ["objection-ssl-ios", "frida-ssl-universal-ios", "sslkillswitch-jb"],
    },
    {
        "id": "afnetworking",
        "name": "AFNetworking AFSecurityPolicy",
        "category": "ssl", "layer": "framework", "confidence": "high", "platform": "ios",
        "patterns": [b"AFSecurityPolicy", b"AFSSLPinningMode", b"setSSLPinningMode"],
        "desc": "AFNetworking's AFSecurityPolicy with certificate or public-key pinning.",
        "guides": ["frida-ssl-universal-ios", "objection-ssl-ios"],
    },
    {
        "id": "alamofire",
        "name": "Alamofire ServerTrustManager",
        "category": "ssl", "layer": "framework", "confidence": "high", "platform": "ios",
        "patterns": [b"ServerTrustManager", b"ServerTrustEvaluating", b"PinnedCertificatesTrustEvaluator",
                     b"PublicKeysTrustEvaluator"],
        "desc": "Alamofire ServerTrustManager with pinned certificates or public keys.",
        "guides": ["frida-ssl-universal-ios", "objection-ssl-ios"],
    },
    {
        "id": "urlsession-challenge",
        "name": "URLSession didReceiveChallenge pinning",
        "category": "ssl", "layer": "objc", "confidence": "medium", "platform": "ios",
        "patterns": [b"didReceiveChallenge", b"SecTrustEvaluate", b"serverTrust",
                     b"SecTrustEvaluateWithError"],
        "all_required": False,
        "desc": "Manual pinning inside URLSession:didReceiveChallenge: using SecTrustEvaluate.",
        "guides": ["frida-ssl-universal-ios", "objection-ssl-ios"],
    },
    {
        "id": "sectrust-lowlevel",
        "name": "Low-level SecTrust / BoringSSL pinning",
        "category": "ssl", "layer": "native", "confidence": "medium", "platform": "ios",
        "patterns": [b"SSLSetSessionOption", b"tls_helper", b"boringssl", b"SecTrustSetAnchorCertificates"],
        "desc": "Pinning at the Security.framework / BoringSSL layer — needs a native hook.",
        "guides": ["frida-ssl-universal-ios", "frida-native-ssl"],
    },
    {
        "id": "embedded-cert",
        "name": "Embedded certificate in bundle",
        "category": "ssl", "layer": "config", "confidence": "medium", "platform": "ios",
        "patterns": [],  # detected via bundle file listing (.cer/.der/.crt/.pem), see ipa.py
        "desc": "A .cer/.der certificate shipped in the app bundle — a strong hint of certificate pinning.",
        "guides": ["objection-ssl-ios", "frida-ssl-universal-ios"],
    },
]


def all_android():
    return ANDROID_ROOT + ANDROID_SSL

def all_ios():
    return IOS_JAILBREAK + IOS_SSL

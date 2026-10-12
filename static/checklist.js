/* ShieldScope — mobile pentest checklist (Android + iOS, static + dynamic).
 * MASTG/MASVS + HackTricks-aligned test-case tracker. The right platform's
 * checklist is shown automatically for the analysed app (APK -> Android, IPA ->
 * iOS). State is saved per-app in localStorage (keyed by SHA-256) and can be
 * downloaded as Markdown / HTML / JSON.
 * Exposes window.SSChecklist = { tabHtml(d), wire(d, rootEl) }.
 */
(function () {
  "use strict";

  // ===================== ANDROID =====================
  const ANDROID_PHASES = [
    { id: "static", name: "Static analysis", icon: "🔍", groups: [
      { cat: "Recon & build", items: [
        { id: "st-recon-decompile", title: "Decompile the app (apktool + jadx)", how: "Unpack smali/resources/manifest and reconstruct Java to read logic and strings.", masvs: "MASVS-CODE" },
        { id: "st-recon-manifest", title: "Review AndroidManifest (package, SDK, components, permissions)", how: "Map the attack surface: minSdk/targetSdk, exported components, custom permissions.", masvs: "MASVS-PLATFORM" },
        { id: "st-recon-framework", title: "Identify the app framework", how: "Native/Java vs Flutter / React Native / Xamarin / Unity — changes where logic & pinning live.", masvs: "MASVS-CODE" },
        { id: "st-recon-thirdparty", title: "Inventory third-party SDKs & trackers", how: "List bundled libraries/SDKs; note analytics/ad trackers and their data access.", masvs: "MASVS-PRIVACY" },
      ]},
      { cat: "Data storage", items: [
        { id: "stor-secrets", title: "Hunt for hardcoded secrets / API keys", how: "Scan dex/resources/assets/native for keys, tokens, credentials, private keys.", masvs: "MASVS-STORAGE" },
        { id: "stor-prefs", title: "Check shared_prefs / local DBs for cleartext PII or secrets", how: "Look for plaintext tokens, passwords, PII written to prefs or SQLite.", masvs: "MASVS-STORAGE" },
        { id: "stor-backup", title: "allowBackup / dataExtractionRules review", how: "allowBackup=true makes the sandbox pullable via adb backup; check backup rules exclude secrets.", masvs: "MASVS-STORAGE" },
        { id: "stor-external", title: "Sensitive data written to external storage", how: "getExternalStorage*/MediaStore writes of sensitive files (world-readable historically).", masvs: "MASVS-STORAGE" },
        { id: "stor-keystore", title: "AndroidKeyStore used for key material", how: "Confirm keys are generated/stored in the KeyStore (StrongBox/TEE) not hardcoded.", masvs: "MASVS-CRYPTO" },
        { id: "stor-logs", title: "Secrets/PII in debug logs", how: "Find Log.d/Log.v calls that leak tokens, request/response bodies or PII.", masvs: "MASVS-STORAGE" },
      ]},
      { cat: "Cryptography", items: [
        { id: "crypto-weak", title: "Weak algorithms (ECB, DES, RC4, MD5, SHA-1)", how: "Flag deprecated ciphers/hashes and ECB mode; recommend AES-GCM / SHA-256+.", masvs: "MASVS-CRYPTO" },
        { id: "crypto-keys", title: "Hardcoded keys / IVs / salts", how: "Find embedded symmetric keys, static IVs or salts used for encryption.", masvs: "MASVS-CRYPTO" },
        { id: "crypto-random", title: "Insecure randomness for security values", how: "java.util.Random (not SecureRandom) for tokens/keys/IVs.", masvs: "MASVS-CRYPTO" },
      ]},
      { cat: "Network / TLS", items: [
        { id: "net-cleartext", title: "Cleartext traffic permitted", how: "usesCleartextTraffic / NSC cleartextTrafficPermitted=true, or http:// endpoints.", masvs: "MASVS-NETWORK" },
        { id: "net-pinning", title: "Certificate/public-key pinning present", how: "OkHttp CertificatePinner, NSC pin-set, TrustKit, custom TrustManager, native/Flutter pinning.", masvs: "MASVS-NETWORK" },
        { id: "net-trustall", title: "Trust-all TrustManager / disabled validation", how: "Empty checkServerTrusted or ALLOW_ALL hostname verifier = MITM hole (vulnerability).", masvs: "MASVS-NETWORK" },
        { id: "net-nsc", title: "Network Security Config review", how: "Trust anchors (user CAs?), per-domain overrides, debug-overrides shipped to prod.", masvs: "MASVS-NETWORK" },
      ]},
      { cat: "Platform / IPC", items: [
        { id: "plat-exported", title: "Exported components without permission", how: "Activities/services/receivers/providers reachable by other apps; test with adb am/content.", masvs: "MASVS-PLATFORM" },
        { id: "plat-provider", title: "ContentProvider exposure (grantUriPermissions / SQLi)", how: "Exported providers, path-permissions, injectable query/projection.", masvs: "MASVS-PLATFORM" },
        { id: "plat-deeplink", title: "Deep-link / intent handling (redirection)", how: "http(s)/custom schemes, missing autoVerify, intent-redirection (Intent.parseUri), task hijacking.", masvs: "MASVS-PLATFORM" },
        { id: "plat-pendingintent", title: "Mutable PendingIntent", how: "PendingIntent without FLAG_IMMUTABLE → intent hijacking on Android 12+.", masvs: "MASVS-PLATFORM" },
        { id: "plat-perms", title: "Dangerous / custom weak permissions", how: "Over-broad dangerous perms; custom permissions with normal/dangerous protectionLevel.", masvs: "MASVS-PRIVACY" },
      ]},
      { cat: "WebView", items: [
        { id: "web-js", title: "JavaScript + addJavascriptInterface exposure", how: "setJavaScriptEnabled with a JS bridge reachable by untrusted content → RCE.", masvs: "MASVS-PLATFORM" },
        { id: "web-fileaccess", title: "WebView file access / universal access", how: "setAllowFileAccess / AllowUniversalAccessFromFileURLs enabling local-file theft.", masvs: "MASVS-PLATFORM" },
        { id: "web-taint", title: "Intent input reaching WebView.loadUrl/loadData", how: "Attacker-controlled URL/HTML loaded in a WebView (XSS / phishing / RCE via bridge).", masvs: "MASVS-PLATFORM" },
        { id: "web-sslerror", title: "onReceivedSslError ignores cert errors", how: "handler.proceed() on SSL errors disables TLS validation inside the WebView.", masvs: "MASVS-NETWORK" },
      ]},
      { cat: "Code quality & config", items: [
        { id: "code-debuggable", title: "android:debuggable in release", how: "Debuggable flag lets anyone attach a debugger / run-as into the sandbox.", masvs: "MASVS-RESILIENCE" },
        { id: "code-flagsecure", title: "FLAG_SECURE on sensitive screens", how: "Login/OTP/payment screens should block screenshots/recents/overlays.", masvs: "MASVS-PLATFORM" },
        { id: "code-signing", title: "Signing scheme & certificate", how: "v1-only (Janus), debug cert in prod, weak key (RSA<2048), weak hash (MD5/SHA-1).", masvs: "MASVS-RESILIENCE" },
        { id: "code-tapjacking", title: "Tapjacking protection", how: "filterTouchesWhenObscured on sensitive controls.", masvs: "MASVS-PLATFORM" },
        { id: "code-exec", title: "Dangerous APIs (Runtime.exec, DexClassLoader)", how: "OS command exec and dynamic code loading from untrusted sources.", masvs: "MASVS-CODE" },
      ]},
      { cat: "Resilience / anti-tamper", items: [
        { id: "res-root", title: "Root detection", how: "su paths, RootBeer, Magisk artifacts, test-keys, package checks.", masvs: "MASVS-RESILIENCE" },
        { id: "res-integrity", title: "Attestation / integrity (SafetyNet, Play Integrity, PairIP)", how: "Server-verified device/app integrity and VM-based anti-tamper.", masvs: "MASVS-RESILIENCE" },
        { id: "res-antidebug", title: "Anti-debug / anti-Frida / anti-Xposed", how: "TracerPid/ptrace checks, Frida/Xposed artifact detection.", masvs: "MASVS-RESILIENCE" },
        { id: "res-packer", title: "Packer / RASP / obfuscation", how: "Commercial packer or RASP; obfuscation level (impacts further analysis).", masvs: "MASVS-RESILIENCE" },
      ]},
      { cat: "Auth", items: [
        { id: "auth-guest", title: "Guest / anonymous / skip-login path", how: "Under-authorized guest sessions reaching authenticated data (broken access control).", masvs: "MASVS-AUTH" },
        { id: "auth-clientflag", title: "Client-side authorization flags", how: "isPremium/isAdmin/isEntitled decided on-device → bypassable.", masvs: "MASVS-AUTH" },
        { id: "auth-jwt", title: "Hardcoded / weak JWTs", how: "Embedded tokens; alg=none, weak secret, missing signature validation.", masvs: "MASVS-AUTH" },
        { id: "auth-biometric", title: "Biometric / local auth gating", how: "BiometricPrompt result only gating UI → Frida-bypassable; must be KeyStore/server bound.", masvs: "MASVS-AUTH" },
      ]},
    ]},
    { id: "dynamic", name: "Dynamic analysis", icon: "⚡", groups: [
      { cat: "Environment setup", items: [
        { id: "dy-device", title: "Rooted device / emulator ready", how: "Magisk-rooted phone or emulator; frida-server running; app installed.", masvs: "MASVS-RESILIENCE" },
        { id: "dy-proxy", title: "Intercepting proxy + trusted CA", how: "Burp/mitmproxy configured; CA installed (system store on Android 7+ or NSC repack).", masvs: "MASVS-NETWORK" },
        { id: "dy-tools", title: "Frida / objection attached", how: "Confirm you can attach and enumerate classes/loaded libs on the target.", masvs: "MASVS-RESILIENCE" },
      ]},
      { cat: "Network interception", items: [
        { id: "dy-intercept", title: "Capture app traffic through the proxy", how: "Confirm requests are visible; map the real API from live traffic.", masvs: "MASVS-NETWORK" },
        { id: "dy-pinbypass", title: "Bypass SSL pinning", how: "objection android sslpinning disable / universal Frida script / reFlutter for Flutter.", masvs: "MASVS-NETWORK" },
        { id: "dy-mitm", title: "Confirm cert validation (negative test)", how: "Untrusted CA without bypass — a secure app must refuse the connection.", masvs: "MASVS-NETWORK" },
        { id: "dy-cleartext-live", title: "Observe any cleartext / weak-TLS requests", how: "Watch for http:// calls or downgraded TLS during normal use.", masvs: "MASVS-NETWORK" },
      ]},
      { cat: "Runtime storage", items: [
        { id: "dy-datadir", title: "Inspect /data/data/<pkg> at runtime", how: "run-as or rooted copy: shared_prefs, databases, files, caches for secrets/PII.", masvs: "MASVS-STORAGE" },
        { id: "dy-keystore", title: "Attempt key extraction / keystore abuse", how: "Hook crypto to dump keys/plaintext; test KeyStore keys usable without auth.", masvs: "MASVS-CRYPTO" },
        { id: "dy-memory", title: "Memory dump for secrets", how: "Dump process memory (Fridump/objection) and grep for tokens/keys/PII.", masvs: "MASVS-STORAGE" },
        { id: "dy-screenshots", title: "Recents screenshot / clipboard leakage", how: "Check the recents thumbnail and clipboard for sensitive data.", masvs: "MASVS-PLATFORM" },
      ]},
      { cat: "Auth & session", items: [
        { id: "dy-idor", title: "IDOR / BOLA on object ids", how: "Replay requests swapping user/account/object ids; check cross-user data access.", masvs: "MASVS-AUTH" },
        { id: "dy-authz", title: "Authorization enforced server-side", how: "Replay privileged calls with a low-priv/guest token; must be rejected by the backend.", masvs: "MASVS-AUTH" },
        { id: "dy-session", title: "Session / token handling", how: "Token expiry, revocation on logout, reuse, token in URL/logs.", masvs: "MASVS-AUTH" },
        { id: "dy-biometric", title: "Biometric / local-auth bypass", how: "Hook onAuthenticationSucceeded — is the sensitive action gated server-side?", masvs: "MASVS-AUTH" },
        { id: "dy-clientflag", title: "Flip client-side entitlement flags", how: "Frida-hook isPremium/isAdmin getters to true; confirm server re-checks.", masvs: "MASVS-AUTH" },
      ]},
      { cat: "Platform / IPC runtime", items: [
        { id: "dy-exported", title: "Invoke exported components", how: "adb am start/broadcast/start-service and content query against exported components.", masvs: "MASVS-PLATFORM" },
        { id: "dy-deeplink", title: "Abuse deep links", how: "Craft malicious deep links (intent redirection, WebView URL injection) and fire via adb.", masvs: "MASVS-PLATFORM" },
        { id: "dy-webview", title: "Exercise the WebView / JS bridge", how: "Load attacker content into the WebView and call any exposed bridge methods.", masvs: "MASVS-PLATFORM" },
      ]},
      { cat: "Resilience bypass", items: [
        { id: "dy-rootbypass", title: "Bypass root detection", how: "Magisk DenyList + Shamiko and/or Frida hooks; confirm the app runs on a rooted device.", masvs: "MASVS-RESILIENCE" },
        { id: "dy-antidebug", title: "Bypass anti-debug / anti-Frida", how: "Defeat TracerPid/ptrace checks and Frida detection (stealth Frida, hooks).", masvs: "MASVS-RESILIENCE" },
        { id: "dy-repackage", title: "Repackage & re-sign test", how: "apktool d/b + re-sign; does the app detect tampering / fail integrity?", masvs: "MASVS-RESILIENCE" },
        { id: "dy-unpack", title: "Runtime-unpack a packed app", how: "For packers (PairIP/DexProtector/…): dump decrypted DEX from memory (frida-dexdump).", masvs: "MASVS-RESILIENCE" },
      ]},
      { cat: "Runtime instrumentation", items: [
        { id: "dy-logcat", title: "Monitor logcat for leaks", how: "adb logcat while exercising the app — tokens, PII, crash traces, request bodies.", masvs: "MASVS-STORAGE" },
        { id: "dy-hooks", title: "Hook crypto / auth / network APIs", how: "Trace Cipher, SharedPreferences, OkHttp, SQLite to observe sensitive data at runtime.", masvs: "MASVS-CRYPTO" },
      ]},
      { cat: "API / business logic", items: [
        { id: "dy-replay", title: "Replay & tamper requests", how: "Burp Repeater: parameter tampering (amount/price/role), mass assignment, method swap.", masvs: "MASVS-AUTH" },
        { id: "dy-ratelimit", title: "Rate limiting / brute force / OTP", how: "Login/OTP/verify endpoints — lockout, rate limits, OTP reuse/leakage.", masvs: "MASVS-AUTH" },
        { id: "dy-fuzz", title: "Fuzz inputs for injection", how: "SQLi/NoSQLi/SSRF/path traversal on harvested endpoints and parameters.", masvs: "MASVS-CODE" },
      ]},
    ]},
  ];

  // ===================== iOS =====================
  const IOS_PHASES = [
    { id: "static", name: "Static analysis", icon: "🔍", groups: [
      { cat: "Recon & build", items: [
        { id: "ios-recon-binary", title: "Inspect the app binary (class-dump / strings / otool)", how: "Dump Obj-C classes, read strings, review load commands and linked frameworks.", masvs: "MASVS-CODE" },
        { id: "ios-recon-plist", title: "Review Info.plist (bundle id, URL types, ATS, permissions)", how: "Map URL schemes, ATS exceptions, usage-description strings, min iOS.", masvs: "MASVS-PLATFORM" },
        { id: "ios-recon-framework", title: "Identify the app framework", how: "Native Obj-C/Swift vs Flutter / React Native / Xamarin / Unity.", masvs: "MASVS-CODE" },
        { id: "ios-encryption", title: "FairPlay encryption / decrypt the binary", how: "App Store IPAs are encrypted — decrypt with frida-ios-dump for full symbol coverage.", masvs: "MASVS-RESILIENCE" },
        { id: "ios-recon-thirdparty", title: "Inventory third-party SDKs & trackers", how: "List embedded frameworks/SDKs and their data access.", masvs: "MASVS-PRIVACY" },
      ]},
      { cat: "Data storage", items: [
        { id: "ios-secrets", title: "Hunt hardcoded secrets / API keys", how: "Scan the binary, plists and resources for keys, tokens, credentials, private keys.", masvs: "MASVS-STORAGE" },
        { id: "ios-keychain", title: "Keychain usage & accessibility class", how: "Check kSecAttrAccessible (Always vs WhenUnlockedThisDeviceOnly) and access-control flags.", masvs: "MASVS-STORAGE" },
        { id: "ios-nsuserdefaults", title: "Sensitive data in NSUserDefaults / plists", how: "NSUserDefaults is plaintext and backed up — must not hold secrets/PII.", masvs: "MASVS-STORAGE" },
        { id: "ios-db", title: "Unencrypted Core Data / Realm / SQLite / YapDatabase", how: "Local DBs storing secrets/PII in cleartext.", masvs: "MASVS-STORAGE" },
        { id: "ios-dataprotection", title: "Data Protection class (NSFileProtection)", how: "Files written with NSFileProtectionNone are not encrypted at rest.", masvs: "MASVS-STORAGE" },
        { id: "ios-cache", title: "Cache / snapshots / cookies leakage", how: "URL cache, backgrounding snapshots, Cookies.binarycookies holding sensitive data.", masvs: "MASVS-STORAGE" },
        { id: "ios-keyboard", title: "Keyboard cache / custom keyboards", how: "Sensitive fields not marked secure can be cached by the keyboard.", masvs: "MASVS-STORAGE" },
      ]},
      { cat: "Cryptography", items: [
        { id: "ios-crypto-weak", title: "Weak algorithms (ECB, DES, MD5, SHA-1)", how: "Deprecated CommonCrypto ciphers/hashes and ECB mode.", masvs: "MASVS-CRYPTO" },
        { id: "ios-crypto-keys", title: "Hardcoded keys / IVs", how: "Embedded symmetric keys or static IVs used for encryption.", masvs: "MASVS-CRYPTO" },
        { id: "ios-crypto-random", title: "Insecure randomness", how: "rand()/arc4random without a secure context for security-sensitive values.", masvs: "MASVS-CRYPTO" },
      ]},
      { cat: "Network / TLS", items: [
        { id: "ios-ats", title: "App Transport Security (ATS)", how: "NSAllowsArbitraryLoads / per-domain NSExceptionDomains weakening TLS.", masvs: "MASVS-NETWORK" },
        { id: "ios-pinning", title: "Certificate / public-key pinning", how: "TrustKit, AFNetworking/Alamofire pinning, URLSession SecTrust, native BoringSSL.", masvs: "MASVS-NETWORK" },
        { id: "ios-cleartext", title: "Cleartext / HTTP endpoints", how: "http:// endpoints or ATS fully disabled.", masvs: "MASVS-NETWORK" },
        { id: "ios-hostname", title: "Hostname / SecTrust validation", how: "Custom URLSession:didReceiveChallenge that accepts any serverTrust.", masvs: "MASVS-NETWORK" },
      ]},
      { cat: "Platform / IPC", items: [
        { id: "ios-urlscheme", title: "Custom URL schemes (validate handlers)", how: "CFBundleURLTypes — attacker-invocable; review parameter handling in openURL.", masvs: "MASVS-PLATFORM" },
        { id: "ios-universal", title: "Universal Links (associated domains)", how: "applinks: entitlement + apple-app-site-association; check path handling.", masvs: "MASVS-PLATFORM" },
        { id: "ios-pasteboard", title: "UIPasteboard (clipboard) leakage", how: "generalPasteboard copies readable by any app / synced via Handoff.", masvs: "MASVS-PLATFORM" },
        { id: "ios-extensions", title: "App extensions input handling", how: "Share/action/today/keyboard extensions receiving untrusted input.", masvs: "MASVS-PLATFORM" },
        { id: "ios-activity", title: "UIActivity / document sharing exposure", how: "Sensitive data exposed through share sheets / UIDocumentInteraction.", masvs: "MASVS-PLATFORM" },
      ]},
      { cat: "WebView", items: [
        { id: "ios-webview", title: "UIWebView (deprecated) vs WKWebView", how: "UIWebView is unmaintained & weaker; confirm WKWebView is used.", masvs: "MASVS-PLATFORM" },
        { id: "ios-webview-file", title: "WKWebView file access", how: "allowFileAccessFromFileURLs / allowingReadAccessToURL enabling local-file theft.", masvs: "MASVS-PLATFORM" },
        { id: "ios-webview-js", title: "JS message handlers (native bridge)", how: "WKScriptMessageHandler reachable by untrusted content.", masvs: "MASVS-PLATFORM" },
      ]},
      { cat: "Code & config", items: [
        { id: "ios-gettaskallow", title: "get-task-allow (debuggable) entitlement", how: "If true in a release build, anyone can attach lldb/Frida and read memory.", masvs: "MASVS-RESILIENCE" },
        { id: "ios-hardening", title: "Binary hardening (PIE / stack-canary / ARC)", how: "otool/LIEF: PIE for ASLR, __stack_chk_fail, ARC — missing mitigations ease exploitation.", masvs: "MASVS-CODE" },
        { id: "ios-hotpatch", title: "Hot-patch / dynamic code frameworks", how: "JSPatch / CodePush / Rollout can deliver code that bypasses review (RCE if MITM'd).", masvs: "MASVS-RESILIENCE" },
        { id: "ios-logs", title: "NSLog / logging of sensitive data", how: "NSLog output goes to the unified log (Console/sysdiagnose).", masvs: "MASVS-STORAGE" },
      ]},
      { cat: "Resilience", items: [
        { id: "ios-jailbreak", title: "Jailbreak detection", how: "Cydia/Sileo paths, fork()/sandbox, canOpenURL(cydia://), IOSSecuritySuite.", masvs: "MASVS-RESILIENCE" },
        { id: "ios-antidebug", title: "Anti-debug (ptrace / sysctl)", how: "PT_DENY_ATTACH / sysctl P_TRACED resisting debugger & Frida attach.", masvs: "MASVS-RESILIENCE" },
        { id: "ios-antihook", title: "Anti-Frida / Cycript / integrity", how: "Detection of injected dylibs (MobileSubstrate), Frida/Cycript, binary integrity.", masvs: "MASVS-RESILIENCE" },
      ]},
      { cat: "Auth", items: [
        { id: "ios-localauth", title: "Local / biometric auth (LAContext)", how: "evaluatePolicy only gating UI is bypassable; must be SecAccessControl / server bound.", masvs: "MASVS-AUTH" },
        { id: "ios-authflags", title: "Client-side authorization flags", how: "isPremium/isAdmin decided on-device → bypassable via hooking.", masvs: "MASVS-AUTH" },
        { id: "ios-jwt", title: "Hardcoded / weak JWTs", how: "Embedded tokens; alg=none, weak secret, missing signature validation.", masvs: "MASVS-AUTH" },
      ]},
    ]},
    { id: "dynamic", name: "Dynamic analysis", icon: "⚡", groups: [
      { cat: "Environment setup", items: [
        { id: "iosdy-device", title: "Jailbroken device / suitable test device", how: "Jailbroken iOS (or a decrypted IPA on a dev device); app installed.", masvs: "MASVS-RESILIENCE" },
        { id: "iosdy-tools", title: "Frida / objection attached", how: "frida-server on the device; confirm attach and class/module enumeration.", masvs: "MASVS-RESILIENCE" },
        { id: "iosdy-proxy", title: "Intercepting proxy + trusted CA", how: "Burp/mitmproxy; install & trust the CA profile on the device.", masvs: "MASVS-NETWORK" },
      ]},
      { cat: "Network interception", items: [
        { id: "iosdy-intercept", title: "Capture app traffic", how: "Confirm requests are visible; map the real API from live traffic.", masvs: "MASVS-NETWORK" },
        { id: "iosdy-pinbypass", title: "Bypass SSL pinning", how: "SSL Kill Switch 2 / objection ios sslpinning disable / Frida universal script.", masvs: "MASVS-NETWORK" },
        { id: "iosdy-mitm", title: "Confirm cert validation (negative test)", how: "Untrusted CA without bypass — a secure app must refuse the connection.", masvs: "MASVS-NETWORK" },
        { id: "iosdy-cleartext", title: "Observe cleartext / weak-TLS requests", how: "Watch for http:// or downgraded TLS during normal use.", masvs: "MASVS-NETWORK" },
      ]},
      { cat: "Runtime storage", items: [
        { id: "iosdy-container", title: "Inspect the app container (Documents/Library/tmp)", how: "objection ios filesystem / SSH: prefs, DBs, caches, snapshots for secrets/PII.", masvs: "MASVS-STORAGE" },
        { id: "iosdy-keychain", title: "Dump the Keychain", how: "objection ios keychain dump — review stored items and accessibility.", masvs: "MASVS-STORAGE" },
        { id: "iosdy-memory", title: "Memory dump for secrets", how: "Fridump / objection memory dump; grep for tokens/keys/PII.", masvs: "MASVS-STORAGE" },
        { id: "iosdy-snapshot", title: "Backgrounding snapshot leakage", how: "Background the app on a sensitive screen; check the .../Snapshots image.", masvs: "MASVS-STORAGE" },
      ]},
      { cat: "Auth & session", items: [
        { id: "iosdy-idor", title: "IDOR / BOLA on object ids", how: "Replay requests swapping user/account/object ids; check cross-user data.", masvs: "MASVS-AUTH" },
        { id: "iosdy-authz", title: "Authorization enforced server-side", how: "Replay privileged calls with a low-priv token; must be rejected by the backend.", masvs: "MASVS-AUTH" },
        { id: "iosdy-biometric", title: "Biometric bypass", how: "objection ios ui biometrics_bypass / hook evaluatePolicy; is the action server-gated?", masvs: "MASVS-AUTH" },
        { id: "iosdy-session", title: "Session / token handling", how: "Token expiry, revocation on logout, reuse, token in URL/logs.", masvs: "MASVS-AUTH" },
      ]},
      { cat: "Platform / IPC", items: [
        { id: "iosdy-urlscheme", title: "Invoke URL schemes with payloads", how: "openurl the custom schemes with crafted params; test handler validation.", masvs: "MASVS-PLATFORM" },
        { id: "iosdy-universal", title: "Abuse universal links", how: "Craft links to the associated domain paths; test for redirection/injection.", masvs: "MASVS-PLATFORM" },
        { id: "iosdy-pasteboard", title: "Pasteboard leakage at runtime", how: "Copy sensitive data and read the general pasteboard from another app/device.", masvs: "MASVS-PLATFORM" },
        { id: "iosdy-extensions", title: "Exercise app extensions", how: "Feed untrusted input to share/action/keyboard extensions.", masvs: "MASVS-PLATFORM" },
      ]},
      { cat: "Resilience bypass", items: [
        { id: "iosdy-jbbypass", title: "Bypass jailbreak detection", how: "objection ios jailbreak disable / Liberty / Shadow / Frida hooks.", masvs: "MASVS-RESILIENCE" },
        { id: "iosdy-antidebug", title: "Bypass anti-debug", how: "Hook ptrace/sysctl; confirm the app runs under a debugger/Frida.", masvs: "MASVS-RESILIENCE" },
        { id: "iosdy-repackage", title: "Repackage & re-sign test", how: "Re-sign the IPA; does the app detect tampering / fail integrity?", masvs: "MASVS-RESILIENCE" },
      ]},
      { cat: "Runtime instrumentation", items: [
        { id: "iosdy-hooks", title: "Hook crypto / keychain / network APIs", how: "frida-trace / objection to observe CommonCrypto, Keychain, URLSession at runtime.", masvs: "MASVS-CRYPTO" },
        { id: "iosdy-logs", title: "Monitor device logs", how: "Console.app / idevicesyslog while exercising the app — tokens, PII, traces.", masvs: "MASVS-STORAGE" },
      ]},
      { cat: "API / business logic", items: [
        { id: "iosdy-replay", title: "Replay & tamper requests", how: "Burp Repeater: parameter tampering, mass assignment, method swap.", masvs: "MASVS-AUTH" },
        { id: "iosdy-ratelimit", title: "Rate limiting / brute force / OTP", how: "Login/OTP/verify endpoints — lockout, rate limits, OTP reuse/leakage.", masvs: "MASVS-AUTH" },
        { id: "iosdy-fuzz", title: "Fuzz inputs for injection", how: "SQLi/NoSQLi/SSRF/path traversal on harvested endpoints and parameters.", masvs: "MASVS-CODE" },
      ]},
    ]},
  ];

  const STATUSES = ["pass", "fail", "na"];
  const STATUS_LABEL = { pass: "✓ Pass", fail: "✗ Fail", na: "– N/A" };
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  function isIOS(d) { return (d && (d.platform === "ios" || (d.file && d.file.type === "ipa"))); }
  function phasesFor(d) { return isIOS(d) ? IOS_PHASES : ANDROID_PHASES; }
  function platformName(d) { return isIOS(d) ? "iOS" : "Android"; }
  function totalOf(phases) { return phases.reduce((n, p) => n + p.groups.reduce((m, g) => m + g.items.length, 0), 0); }

  // ---- observations: pre-annotate items from ShieldScope's own findings -----
  function observations(d) {
    const o = {}, ex = d.extra || [];
    const hasId = (p) => ex.some(f => (f.id || "") === p || (f.id || "").startsWith(p));
    const catCount = (c) => ex.filter(f => f.category === c).length;
    const rootM = (d.root && d.root.mechanisms) || [];
    const rootHas = (id) => rootM.some(m => (m.id || "") === id);
    const meta = d.meta || {};
    if (isIOS(d)) {
      if (hasId("ios-url-scheme")) o["ios-urlscheme"] = "Custom URL scheme(s) registered.";
      if (hasId("ios-uiwebview")) o["ios-webview"] = "Deprecated UIWebView in use.";
      if (hasId("ios-wkwebview-file")) o["ios-webview-file"] = "WKWebView file access enabled.";
      if (hasId("ios-pasteboard")) o["ios-pasteboard"] = "Uses the general pasteboard.";
      if (hasId("ios-keychain-weak")) o["ios-keychain"] = "Weak Keychain accessibility (Always).";
      if (hasId("ios-local-auth")) o["ios-localauth"] = "LocalAuthentication (biometric) present.";
      if (hasId("ios-fileprotection-none")) o["ios-dataprotection"] = "NSFileProtectionNone found.";
      if (hasId("ios-userdefaults")) o["ios-nsuserdefaults"] = "Uses NSUserDefaults.";
      if (hasId("ios-hotpatch")) o["ios-hotpatch"] = "Hot-patch / dynamic-code framework detected.";
      if (hasId("ios-native-hardening")) o["ios-hardening"] = "Binary missing exploit mitigations.";
      if (hasId("ios-nslog")) o["ios-logs"] = "NSLog logging present.";
      if (hasId("ats-disabled") || hasId("ats-exceptions")) o["ios-ats"] = "ATS disabled / has exceptions.";
      if (hasId("ios-get-task-allow")) o["ios-gettaskallow"] = "get-task-allow=true (debuggable).";
      if (d.ssl && d.ssl.implemented) o["ios-pinning"] = "SSL pinning present (" + d.ssl.layers + " layer(s)).";
      else if (d.ssl) o["ios-pinning"] = "No SSL pinning detected statically.";
      if (d.root && d.root.implemented) o["ios-jailbreak"] = "Jailbreak detection present (" + d.root.layers + " layer(s)).";
      if (rootHas("ios-code-integrity") || rootHas("ios-js-tamper"))
        o["ios-antihook"] = "Tamper/integrity protection present (" + (rootHas("ios-js-tamper") ? "Jscrambler JS" : "SecCode integrity") + ").";
      if (meta.encrypted) o["ios-encryption"] = "Binary is FairPlay-encrypted — decrypt first.";
      if (catCount("secret")) o["ios-secrets"] = catCount("secret") + " hardcoded-secret finding(s).";
      if (catCount("crypto")) o["ios-crypto-weak"] = catCount("crypto") + " weak-crypto indicator(s).";
      return o;
    }
    if (hasId("allow-backup")) o["stor-backup"] = "allowBackup appears enabled — sandbox is pullable via adb backup.";
    if (hasId("debuggable")) o["code-debuggable"] = "android:debuggable=true found.";
    if (hasId("cleartext")) o["net-cleartext"] = "Cleartext traffic permitted.";
    if (ex.some(f => (f.id || "").startsWith("trustall-"))) o["net-trustall"] = "Trust-all TrustManager detected — TLS validation disabled.";
    if (hasId("nsc-user-ca")) o["net-nsc"] = "NSC trusts user-installed CAs.";
    if (d.root && d.root.implemented) o["res-root"] = "Root detection present (" + d.root.layers + " layer(s)).";
    {
      const TAMPER = ["sig-verify", "installer-check", "integrity-checksum", "js-tamper-protection", "codepush-signing", "native-rasp"];
      const tm = rootM.filter(m => TAMPER.indexOf(m.id || "") !== -1);
      if (tm.length) o["res-integrity"] = tm.length + " anti-tamper mechanism(s): " + tm.map(m => m.id).join(", ") + ".";
    }
    if (d.ssl && d.ssl.implemented) o["net-pinning"] = "SSL pinning present (" + d.ssl.layers + " layer(s)).";
    else if (d.ssl) o["net-pinning"] = "No SSL pinning detected statically.";
    if (catCount("secret")) o["stor-secrets"] = catCount("secret") + " hardcoded-secret finding(s).";
    if (catCount("crypto")) o["crypto-weak"] = catCount("crypto") + " weak-crypto indicator(s).";
    if (d.ipc && d.ipc.length) { const u = d.ipc.filter(r => !r.protected).length; o["plat-exported"] = d.ipc.length + " exported component(s), " + u + " unguarded."; }
    if (hasId("webview-deeplink-taint")) o["web-taint"] = "Deep-link input reaches a WebView.";
    if (hasId("webview-js-bridge")) o["web-js"] = "addJavascriptInterface bridge detected.";
    if (hasId("webview-file-access")) o["web-fileaccess"] = "WebView file-URL access enabled.";
    if (hasId("intent-redirect")) o["plat-deeplink"] = "Intent.parseUri (intent redirection) detected.";
    if (hasId("storage-external")) o["stor-external"] = "Uses external storage.";
    if (hasId("cmd-exec") || hasId("dynamic-code-load")) o["code-exec"] = "Runtime.exec / DexClassLoader detected.";
    if (hasId("pendingintent-mutable")) o["plat-pendingintent"] = "Mutable PendingIntent found.";
    if (hasId("sign-janus") || hasId("sign-debug-cert") || hasId("sign-weak")) o["code-signing"] = "Signing issue flagged by the scan.";
    if (hasId("keyboard-cache")) o["code-flagsecure"] = "Password fields without keyboard-cache protection.";
    if (hasId("tapjacking")) o["code-tapjacking"] = "No obscured-touch filtering (tapjacking).";
    if (hasId("auth-guest-access")) o["auth-guest"] = "Guest / skip-login path detected.";
    if (hasId("auth-clientside-flag")) o["auth-clientflag"] = "Client-side entitlement flag detected.";
    if (hasId("biometric-auth")) o["auth-biometric"] = "Biometric / local auth present.";
    if (hasId("secret-jwt") || ex.some(f => f.rule === "jwt")) o["auth-jwt"] = "JWT found in the app.";
    if (hasId("res-packer") || hasId("app-shielding") || (d.discovered && d.discovered.packer)) o["res-packer"] = "Commercial packer / RASP detected.";
    if (d.frameworks && d.frameworks.some(f => /flutter/i.test(f.name))) o["net-pinning"] = (o["net-pinning"] ? o["net-pinning"] + " " : "") + "Flutter — pinning bypass needs reFlutter.";
    return o;
  }

  // ---- rendering -----------------------------------------------------------
  function itemHtml(it, obs) {
    const hint = obs[it.id];
    return '<div class="ck-item" data-id="' + it.id + '">' +
      '<div class="ck-row"><div class="ck-status">' +
      STATUSES.map(s => '<button class="ck-sbtn ck-' + s + '" data-s="' + s + '" title="' + STATUS_LABEL[s] + '">' + STATUS_LABEL[s].split(" ")[0] + '</button>').join("") +
      '</div><div class="ck-text"><div class="ck-title">' + esc(it.title) + ' <span class="ck-masvs">' + esc(it.masvs) + '</span></div>' +
      '<div class="ck-how">' + esc(it.how) + '</div>' +
      (hint ? '<div class="ck-hint">🔎 ShieldScope: ' + esc(hint) + '</div>' : "") +
      '</div><button class="ck-note-toggle" title="Add note / evidence">📝</button></div>' +
      '<textarea class="ck-note hidden" rows="2" placeholder="notes / evidence / request-response…"></textarea></div>';
  }

  function phaseHtml(phase, obs, active) {
    const groups = phase.groups.map(g =>
      '<div class="ck-group"><h4 class="ck-cat">' + esc(g.cat) + ' <span class="ck-catcount">0/' + g.items.length + '</span></h4>' +
      g.items.map(it => itemHtml(it, obs)).join("") + '</div>').join("");
    return '<div class="ck-phase' + (active ? "" : " hidden") + '" data-phase="' + phase.id + '">' + groups + '</div>';
  }

  function tabHtml(d) {
    const PH = phasesFor(d), TOTAL = totalOf(PH), obs = observations(d);
    const subtabs = PH.map((p, i) =>
      '<button class="ck-subtab ' + (i === 0 ? "active" : "") + '" data-sub="' + p.id + '">' + p.icon + ' ' + p.name +
      ' <span class="ck-subcount" data-phase-count="' + p.id + '">0/' + p.groups.reduce((m, g) => m + g.items.length, 0) + '</span></button>').join("");
    const panes = PH.map((p, i) => phaseHtml(p, obs, i === 0)).join("");
    return '<div class="ck" data-total="' + TOTAL + '">' +
      '<div class="ck-head"><div class="ck-progwrap"><div class="ck-progbar"><div class="ck-progfill" style="width:0%"></div></div>' +
      '<div class="ck-progtext"><b class="ck-done">0</b> / ' + TOTAL + ' tested · <span class="ck-pass-n">0</span> pass · <span class="ck-fail-n">0</span> fail · <span class="ck-na-n">0</span> n/a</div></div>' +
      '<div class="ck-actions"><button class="mini" data-dl="md">⬇ Markdown</button><button class="mini" data-dl="html">⬇ HTML</button>' +
      '<button class="mini" data-dl="json">⬇ JSON</button><button class="mini ck-reset" title="Clear all statuses & notes for this app">↺ Reset</button></div></div>' +
      '<p class="lead">' + platformName(d) + ' MASTG/MASVS-aligned test cases. Tick each as you work; items ShieldScope has evidence for are pre-annotated. Saved in this browser per app (SHA-256) — download to keep or share.</p>' +
      '<div class="ck-subtabs">' + subtabs + '</div>' + panes + '</div>';
  }

  // ---- state + wiring ------------------------------------------------------
  function keyFor(d) { return "ss_checklist_" + ((d.file && (d.file.sha256 || d.file.name)) || "app"); }
  function loadState(d) { try { return JSON.parse(localStorage.getItem(keyFor(d))) || {}; } catch (e) { return {}; } }
  function saveState(d, st) { try { localStorage.setItem(keyFor(d), JSON.stringify(st)); } catch (e) {} }

  function wire(d, rootEl) {
    const ck = rootEl.querySelector(".ck");
    if (!ck) return;
    const PH = phasesFor(d), TOTAL = totalOf(PH);
    const state = loadState(d);

    ck.querySelectorAll(".ck-item").forEach(item => {
      const id = item.dataset.id, s = state[id];
      if (!s) return;
      if (s.status) {
        item.classList.add("set-" + s.status);
        const b = item.querySelector('.ck-sbtn[data-s="' + s.status + '"]');
        if (b) b.classList.add("on");
      }
      if (s.note) {
        const ta = item.querySelector(".ck-note");
        ta.value = s.note; ta.classList.remove("hidden");
        item.querySelector(".ck-note-toggle").classList.add("has");
      }
    });

    function setStatus(item, status) {
      const id = item.dataset.id;
      const cur = (state[id] && state[id].status) || null;
      const next = cur === status ? null : status;
      STATUSES.forEach(s => item.classList.remove("set-" + s));
      item.querySelectorAll(".ck-sbtn").forEach(b => b.classList.remove("on"));
      if (next) {
        item.classList.add("set-" + next);
        item.querySelector('.ck-sbtn[data-s="' + next + '"]').classList.add("on");
      }
      state[id] = Object.assign({}, state[id], { status: next });
      if (!next) delete state[id].status;
      saveState(d, state); refresh();
    }

    ck.addEventListener("click", (e) => {
      const sbtn = e.target.closest(".ck-sbtn");
      if (sbtn) { setStatus(sbtn.closest(".ck-item"), sbtn.dataset.s); return; }
      const nt = e.target.closest(".ck-note-toggle");
      if (nt) { nt.closest(".ck-item").querySelector(".ck-note").classList.toggle("hidden"); return; }
      const sub = e.target.closest(".ck-subtab");
      if (sub) {
        ck.querySelectorAll(".ck-subtab").forEach(b => b.classList.toggle("active", b === sub));
        ck.querySelectorAll(".ck-phase").forEach(p => p.classList.toggle("hidden", p.dataset.phase !== sub.dataset.sub));
        return;
      }
      const dl = e.target.closest("[data-dl]");
      if (dl) { downloadReport(d, state, dl.dataset.dl); return; }
      if (e.target.closest(".ck-reset")) {
        if (confirm("Clear all checklist statuses and notes for this app?")) {
          for (const k in state) delete state[k];
          saveState(d, state);
          ck.querySelectorAll(".ck-item").forEach(item => {
            STATUSES.forEach(s => item.classList.remove("set-" + s));
            item.querySelectorAll(".ck-sbtn").forEach(b => b.classList.remove("on"));
            const ta = item.querySelector(".ck-note"); ta.value = ""; ta.classList.add("hidden");
            item.querySelector(".ck-note-toggle").classList.remove("has");
          });
          refresh();
        }
      }
    });

    ck.addEventListener("input", (e) => {
      const ta = e.target.closest(".ck-note");
      if (!ta) return;
      const item = ta.closest(".ck-item"), id = item.dataset.id;
      state[id] = Object.assign({}, state[id], { note: ta.value });
      if (!ta.value) delete state[id].note;
      item.querySelector(".ck-note-toggle").classList.toggle("has", !!ta.value);
      saveState(d, state);
    });

    function refresh() {
      let done = 0, pass = 0, fail = 0, na = 0;
      PH.forEach(p => {
        let pdone = 0;
        const pane = ck.querySelector('.ck-phase[data-phase="' + p.id + '"]');
        p.groups.forEach((g, gi) => {
          const gdone = g.items.filter(it => state[it.id] && state[it.id].status).length;
          pdone += gdone;
          if (pane) {
            const gEl = pane.querySelectorAll(".ck-group")[gi];
            if (gEl) { const cc = gEl.querySelector(".ck-catcount"); if (cc) cc.textContent = gdone + "/" + g.items.length; }
          }
          g.items.forEach(it => {
            const s = state[it.id] && state[it.id].status;
            if (s) { done++; if (s === "pass") pass++; else if (s === "fail") fail++; else na++; }
          });
        });
        const sc = ck.querySelector('[data-phase-count="' + p.id + '"]');
        if (sc) sc.textContent = pdone + "/" + p.groups.reduce((m, g) => m + g.items.length, 0);
      });
      ck.querySelector(".ck-done").textContent = done;
      ck.querySelector(".ck-pass-n").textContent = pass;
      ck.querySelector(".ck-fail-n").textContent = fail;
      ck.querySelector(".ck-na-n").textContent = na;
      ck.querySelector(".ck-progfill").style.width = (TOTAL ? Math.round(done / TOTAL * 100) : 0) + "%";
    }
    refresh();
  }

  // ---- downloads -----------------------------------------------------------
  function appName(d) { return (d.file && d.file.name) || "app"; }
  function slug(d) { return (appName(d).replace(/\.[^.]+$/, "") || "app").replace(/[^\w.-]+/g, "_"); }

  function buildMarkdown(d, state) {
    const PH = phasesFor(d), TOTAL = totalOf(PH);
    const mark = { pass: "[x] ✓ PASS", fail: "[x] ✗ FAIL", na: "[~] – N/A" };
    let done = 0; PH.forEach(p => p.groups.forEach(g => g.items.forEach(it => { if (state[it.id] && state[it.id].status) done++; })));
    let md = "# " + platformName(d) + " pentest checklist — " + appName(d) + "\n\n";
    if (d.meta && (d.meta.package || d.meta.bundle_id)) md += "**App id:** " + (d.meta.package || d.meta.bundle_id) + "  \n";
    if (d.file && d.file.sha256) md += "**SHA-256:** " + d.file.sha256 + "  \n";
    md += "**Date:** " + new Date().toISOString().slice(0, 10) + "  \n**Progress:** " + done + "/" + TOTAL + " tested\n\n";
    PH.forEach(p => {
      md += "## " + p.name + "\n\n";
      p.groups.forEach(g => {
        md += "### " + g.cat + "\n\n";
        g.items.forEach(it => {
          const st = state[it.id] || {};
          md += "- " + (st.status ? mark[st.status] : "[ ]") + " **" + it.title + "** _(" + it.masvs + ")_\n";
          if (st.note) md += "  - note: " + st.note.replace(/\n/g, " ") + "\n";
        });
        md += "\n";
      });
    });
    md += "\n_Generated by ShieldScope. For authorized testing only._\n";
    return md;
  }

  function buildHtml(d, state) {
    const PH = phasesFor(d), TOTAL = totalOf(PH);
    const cls = { pass: "pass", fail: "fail", na: "na" }, lbl = { pass: "PASS", fail: "FAIL", na: "N/A" };
    let rows = "";
    PH.forEach(p => {
      rows += '<tr class="ph"><td colspan="2">' + p.icon + " " + esc(p.name) + "</td></tr>";
      p.groups.forEach(g => {
        rows += '<tr class="cat"><td colspan="2">' + esc(g.cat) + "</td></tr>";
        g.items.forEach(it => {
          const st = state[it.id] || {};
          const s = st.status ? '<span class="st ' + cls[st.status] + '">' + lbl[st.status] + "</span>" : '<span class="st none">—</span>';
          rows += "<tr><td>" + s + "</td><td><b>" + esc(it.title) + '</b> <span class="m">' + esc(it.masvs) + '</span><br><span class="how">' + esc(it.how) + "</span>" + (st.note ? '<br><span class="note">📝 ' + esc(st.note) + "</span>" : "") + "</td></tr>";
        });
      });
    });
    let done = 0; PH.forEach(p => p.groups.forEach(g => g.items.forEach(it => { if (state[it.id] && state[it.id].status) done++; })));
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>ShieldScope checklist — " + esc(appName(d)) + "</title>" +
      "<style>body{font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:30px auto;padding:0 16px;color:#1a2230}" +
      "h1{font-size:20px}.meta{color:#667;font-size:13px;margin-bottom:16px}table{border-collapse:collapse;width:100%}td{border:1px solid #e3e8ef;padding:7px 10px;vertical-align:top}" +
      "tr.ph td{background:#111826;color:#fff;font-weight:700;font-size:15px}tr.cat td{background:#eef2f7;font-weight:600}" +
      ".st{font-weight:700;padding:2px 8px;border-radius:5px;font-size:12px}.st.pass{background:#dcfce7;color:#15803d}" +
      ".st.fail{background:#fee2e2;color:#b91c1c}.st.na{background:#e5e7eb;color:#4b5563}.st.none{color:#9aa5b1}" +
      ".m{color:#8b5cf6;font-size:11px}.how{color:#667;font-size:12.5px}.note{color:#b45309;font-size:12.5px}</style></head>" +
      "<body><h1>🛡️ " + platformName(d) + " pentest checklist — " + esc(appName(d)) + "</h1>" +
      '<div class="meta">' + ((d.meta && (d.meta.package || d.meta.bundle_id)) ? "App id: " + esc(d.meta.package || d.meta.bundle_id) + " · " : "") + ((d.file && d.file.sha256) ? "SHA-256: " + esc(d.file.sha256) + " · " : "") + new Date().toISOString().slice(0, 10) + " · " + done + "/" + TOTAL + " tested</div>" +
      "<table>" + rows + "</table>" +
      '<p style="color:#8b98a8;font-size:12px;margin-top:20px">Generated by ShieldScope · for authorized testing only.</p></body></html>';
  }

  function buildJson(d, state) {
    const PH = phasesFor(d), TOTAL = totalOf(PH), items = [];
    PH.forEach(p => p.groups.forEach(g => g.items.forEach(it => {
      const st = state[it.id] || {};
      items.push({ phase: p.id, category: g.cat, id: it.id, title: it.title, masvs: it.masvs, status: st.status || null, note: st.note || "" });
    })));
    return JSON.stringify({
      tool: "ShieldScope", platform: platformName(d).toLowerCase(), app: appName(d),
      app_id: d.meta && (d.meta.package || d.meta.bundle_id), sha256: d.file && d.file.sha256,
      generated: new Date().toISOString(), total: TOTAL, tested: items.filter(i => i.status).length, items,
    }, null, 2);
  }

  function downloadReport(d, state, kind) {
    let text, mime, ext;
    if (kind === "md") { text = buildMarkdown(d, state); mime = "text/markdown"; ext = "md"; }
    else if (kind === "html") { text = buildHtml(d, state); mime = "text/html"; ext = "html"; }
    else { text = buildJson(d, state); mime = "application/json"; ext = "json"; }
    const blob = new Blob([text], { type: mime + ";charset=utf-8" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "shieldscope_checklist_" + platformName(d).toLowerCase() + "_" + slug(d) + "." + ext;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }

  window.SSChecklist = { tabHtml, wire };
})();

"""
Bypass-guide knowledge base for ShieldScope.

Each guide id maps to a structured, step-by-step walkthrough. Signatures in
signatures.py reference these ids; report.py collects only the guides that were
actually triggered so the report stays focused on what the app really uses.

Guide schema
------------
title       str
difficulty  "easy" | "medium" | "hard"
needs       list[str]  -- environment prerequisites
steps       list[str]  -- ordered, copy-pasteable instructions (may contain `code`)
resources   list[{"label": str, "url": str}]

Everything here is for AUTHORIZED security testing (your own apps, pentest
engagements with scope, CTFs, bug-bounty programs that permit it).
"""

GUIDES = {

    # ===================================================================
    #  ANDROID -- SSL PINNING BYPASS
    # ===================================================================
    "objection-ssl-android": {
        "title": "objection — one-command SSL pinning disable (Android)",
        "difficulty": "easy",
        "needs": ["Rooted device/emulator OR objection patched APK", "frida-server running", "objection (`pip install objection`)"],
        "steps": [
            "Start frida-server on the device: `adb shell /data/local/tmp/frida-server &`",
            "Attach objection to the app: `objection -g <package.name> explore`",
            "Inside the objection REPL run: `android sslpinning disable`",
            "objection hooks OkHttp CertificatePinner, TrustManager, TrustKit and WebView SSL error handling at once.",
            "Route traffic through Burp/mitmproxy and confirm requests are now visible.",
            "If pinning re-arms on new connections, keep the job running (objection leaves the hooks installed for the session).",
        ],
        "resources": [
            {"label": "objection (GitHub)", "url": "https://github.com/sensepost/objection"},
            {"label": "objection wiki — pinning", "url": "https://github.com/sensepost/objection/wiki"},
        ],
    },
    "frida-ssl-universal": {
        "title": "Frida — universal SSL pinning bypass (Android)",
        "difficulty": "easy",
        "needs": ["Frida (`pip install frida-tools`)", "frida-server on device (matching arch/version)"],
        "steps": [
            "Grab a maintained universal script (they cover OkHttp, TrustManager, TrustKit, Conscrypt, etc.).",
            "Spawn the app under the script: `frida -U -f <package.name> -l android-ssl-bypass.js`  (add `--no-pause`).",
            "Or attach to a running app: `frida -U <package.name> -l android-ssl-bypass.js`",
            "Watch the console — a good script prints each hooked class as it neutralises it.",
            "Proxy traffic through Burp and verify. If some calls still fail, the app likely uses native pinning or Flutter (see those guides).",
        ],
        "resources": [
            {"label": "httptoolkit/frida-interception-and-unpinning", "url": "https://github.com/httptoolkit/frida-interception-and-unpinning"},
            {"label": "Frida CodeShare — universal android ssl pinning", "url": "https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/"},
            {"label": "Frida docs", "url": "https://frida.re/docs/home/"},
        ],
    },
    "frida-okhttp": {
        "title": "Frida — targeted OkHttp CertificatePinner hook",
        "difficulty": "medium",
        "needs": ["Frida", "frida-server"],
        "steps": [
            "When a universal script misses a custom OkHttp setup, hook `okhttp3.CertificatePinner.check` directly.",
            "In the Frida script, replace the implementation of `check(String, List)` and `check$okhttp` with a no-op that simply returns.",
            "Example core: `CertificatePinner.check.overload('java.lang.String','java.util.List').implementation = function(){ return; }`",
            "Also stub `Handshake` verification if the app re-checks pins itself.",
            "Reload and confirm the `Certificate pinning failure!` exception no longer fires.",
        ],
        "resources": [
            {"label": "OkHttp CertificatePinner docs", "url": "https://square.github.io/okhttp/features/https/"},
            {"label": "Frida Java API (Interceptor/Java.use)", "url": "https://frida.re/docs/javascript-api/"},
        ],
    },
    "nsc-repack": {
        "title": "Patch network_security_config.xml + repackage (no root)",
        "difficulty": "medium",
        "needs": ["apktool", "keytool/uber-apk-signer", "adb"],
        "steps": [
            "Decode the APK: `apktool d target.apk -o target_src`",
            "Open `target_src/res/xml/network_security_config.xml` and REMOVE every `<pin-set>...</pin-set>` block.",
            "Add a debug-overrides / trust-anchors block so your Burp CA is trusted:\n`<base-config cleartextTrafficPermitted=\"true\"><trust-anchors><certificates src=\"system\"/><certificates src=\"user\"/></trust-anchors></base-config>`",
            "Rebuild: `apktool b target_src -o target_patched.apk`",
            "Sign it: `java -jar uber-apk-signer.jar -a target_patched.apk` (or zipalign + apksigner).",
            "Install: `adb install -r target_patched-aligned-signed.apk` and add your Burp CA as a user cert.",
            "Note: this only defeats config-based pinning. Code-level pins (OkHttp/TrustKit) still need a hook.",
        ],
        "resources": [
            {"label": "apktool", "url": "https://apktool.org/"},
            {"label": "uber-apk-signer", "url": "https://github.com/patrickfav/uber-apk-signer"},
            {"label": "Android Network Security Config", "url": "https://developer.android.com/privacy-and-security/security-config"},
        ],
    },
    "frida-webview-ssl": {
        "title": "Frida — WebView SSL error bypass",
        "difficulty": "medium",
        "needs": ["Frida", "frida-server"],
        "steps": [
            "Hook `android.webkit.WebViewClient.onReceivedSslError` and call `handler.proceed()` to accept the cert.",
            "Also consider hooking `WebViewClient.onReceivedError` for related failures.",
            "Useful only for content loaded inside a WebView, not the app's native HTTP stack.",
        ],
        "resources": [
            {"label": "WebViewClient.onReceivedSslError", "url": "https://developer.android.com/reference/android/webkit/WebViewClient"},
        ],
    },
    "frida-native-ssl": {
        "title": "Frida — native / BoringSSL pinning hook",
        "difficulty": "hard",
        "needs": ["Frida", "frida-server", "Ghidra/IDA for offset hunting (sometimes)"],
        "steps": [
            "Java hooks can't reach pinning done in a `.so`. Hook the native verify function instead.",
            "Common target: BoringSSL `ssl_crypto_x509_session_verify_cert_chain` / `SSL_CTX_set_custom_verify` — force the callback to return 'OK'.",
            "Use `Interceptor.attach(Module.findExportByName('libssl.so','SSL_get_verify_result'), {...})` and set the return to 0.",
            "For stripped/static libs, locate the function in Ghidra, then hook by `Module.base.add(offset)`.",
            "The httptoolkit unpinning repo ships a maintained native BoringSSL bypass — start there before hand-rolling.",
        ],
        "resources": [
            {"label": "httptoolkit native-connect-hook", "url": "https://github.com/httptoolkit/frida-interception-and-unpinning"},
            {"label": "Frida Interceptor API", "url": "https://frida.re/docs/javascript-api/#interceptor"},
        ],
    },
    "flutter-ssl": {
        "title": "Flutter app — SSL bypass (reFlutter / native hook)",
        "difficulty": "hard",
        "needs": ["reFlutter OR a libflutter.so Frida hook", "Burp/mitmproxy"],
        "steps": [
            "Flutter ignores the system & user CA store and the network security config — normal bypasses do nothing.",
            "Easiest path: patch the app with `reFlutter` — it rebuilds the app to trust your proxy and route through it.\n`reflutter target.apk` → choose the proxy option → install the produced APK.",
            "Alternative: use a Frida script that hooks `ssl_verify_result` inside `libflutter.so` (offsets vary per Flutter version — some scripts auto-scan the pattern).",
            "Set the Dart proxy / point the device proxy at Burp, add the Burp CA, and confirm TLS traffic appears.",
        ],
        "resources": [
            {"label": "reFlutter", "url": "https://github.com/Impact-I/reFlutter"},
            {"label": "NVISO — intercepting Flutter traffic", "url": "https://blog.nviso.eu/2022/08/18/intercept-flutter-traffic-on-ios-and-android-http-https-dio-pinning/"},
        ],
    },

    # ===================================================================
    #  ANDROID -- ROOT DETECTION BYPASS
    # ===================================================================
    "objection-root": {
        "title": "objection — root detection disable (Android)",
        "difficulty": "easy",
        "needs": ["frida-server", "objection"],
        "steps": [
            "Attach: `objection -g <package.name> explore`",
            "Run: `android root disable`",
            "objection hooks common root checks (RootBeer, su path checks, package checks) and forces them to report 'not rooted'.",
            "If the app crashes or still detects, combine with `magisk-denylist` so nothing is visible in the first place.",
        ],
        "resources": [
            {"label": "objection", "url": "https://github.com/sensepost/objection"},
        ],
    },
    "frida-rootbeer": {
        "title": "Frida — defeat RootBeer / aggregate root checks",
        "difficulty": "easy",
        "needs": ["Frida", "frida-server"],
        "steps": [
            "RootBeer exposes many boolean methods — override them all to return false.",
            "Hook `com.scottyab.rootbeer.RootBeer` and set `isRooted`, `isRootedWithoutBusyBoxCheck`, `checkForSuBinary`, `checkForDangerousProps`, `detectRootManagementApps`, `checkForBinary` … to return false.",
            "For a quick win, use a RootBeer-specific CodeShare script rather than writing each override.",
            "Spawn with `frida -U -f <pkg> -l rootbeer-bypass.js --no-pause` so hooks land before the check runs.",
        ],
        "resources": [
            {"label": "RootBeer library", "url": "https://github.com/scottyab/rootbeer"},
            {"label": "Frida CodeShare", "url": "https://codeshare.frida.re/"},
        ],
    },
    "frida-file-exists": {
        "title": "Frida — spoof su/file existence checks",
        "difficulty": "medium",
        "needs": ["Frida", "frida-server"],
        "steps": [
            "Hook `java.io.File.exists` and return false when the path contains `su`, `magisk`, `busybox`, etc.",
            "Also hook `File.canExecute` / `File.canRead` for the same paths.",
            "Cover the native side too: `Interceptor.attach(Module.findExportByName('libc.so','access'), ...)` and `fopen`/`stat` to hide the same paths.",
            "Test that `/system/xbin/su` and Magisk paths now read as missing.",
        ],
        "resources": [
            {"label": "Frida Java.use docs", "url": "https://frida.re/docs/javascript-api/#java"},
        ],
    },
    "frida-exec": {
        "title": "Frida — neutralise Runtime.exec('which su')",
        "difficulty": "medium",
        "needs": ["Frida", "frida-server"],
        "steps": [
            "Hook `java.lang.Runtime.exec` overloads; when the command is `which`, `su`, or `busybox`, return a harmless command (e.g. `echo`) so the lookup yields nothing.",
            "Alternatively return an empty stream from the process's stdout.",
            "Cover `ProcessBuilder.start` as well if the app uses it.",
        ],
        "resources": [
            {"label": "Frida JavaScript API", "url": "https://frida.re/docs/javascript-api/"},
        ],
    },
    "frida-native-rasp": {
        "title": "Frida — commercial RASP (freeRASP/DexGuard) checks",
        "difficulty": "hard",
        "needs": ["Frida", "frida-server", "Ghidra/IDA", "patience"],
        "steps": [
            "These SDKs run checks in obfuscated native code and often detect Frida itself — expect anti-hooking.",
            "First reduce the attack surface: hide root with Magisk DenyList + Shamiko (see magisk guides) so many checks pass naturally.",
            "Identify the native callback that reports the verdict (Ghidra) and hook it to return 'clean'.",
            "Consider using a stealth Frida (gadget injected via repackaging, renamed frida-server, or `strongr-frida`) to dodge Frida detection.",
            "This is genuinely hard and version-specific; budget time and validate each check individually.",
        ],
        "resources": [
            {"label": "Talsec freeRASP", "url": "https://github.com/talsec/Free-RASP-Community"},
            {"label": "strongR-frida-android", "url": "https://github.com/hzzhezhe/strongR-frida-android"},
        ],
    },
    "magisk-denylist": {
        "title": "Magisk DenyList — hide root from the app (no code needed)",
        "difficulty": "easy",
        "needs": ["Magisk-rooted device", "Zygisk enabled"],
        "steps": [
            "Magisk → Settings → enable **Zygisk**, then reboot.",
            "Magisk → Settings → **Configure DenyList** → tick the target app (expand and tick all its processes).",
            "This unmounts Magisk modifications and hides the su/Magisk artifacts from that app's process.",
            "Relaunch the app — many file/package/prop-based root checks now pass with zero hooking.",
            "For stubborn apps add Shamiko (next guide) for stronger, DenyList-driven hiding.",
        ],
        "resources": [
            {"label": "Magisk", "url": "https://github.com/topjohnwu/Magisk"},
            {"label": "Magisk DenyList docs", "url": "https://topjohnwu.github.io/Magisk/deny.html"},
        ],
    },
    "magisk-shamiko": {
        "title": "Shamiko — stronger root hiding on top of DenyList",
        "difficulty": "medium",
        "needs": ["Magisk + Zygisk", "Shamiko module"],
        "steps": [
            "Configure the DenyList with your target app (as above) but do NOT enforce it — Shamiko uses the list in 'whitelist off' mode.",
            "Flash the Shamiko Magisk module and reboot.",
            "Shamiko hides root more aggressively (mount namespace, props, common detection vectors).",
            "Pair with `MagiskHide Props Config` to spoof device fingerprint/props if the app checks those.",
        ],
        "resources": [
            {"label": "Shamiko (LSPosed releases)", "url": "https://github.com/LSPosed/LSPosed.github.io/releases"},
        ],
    },
    "magisk-props": {
        "title": "MagiskHide Props Config — spoof build props / test-keys",
        "difficulty": "medium",
        "needs": ["Magisk", "MagiskHide Props Config module"],
        "steps": [
            "Flash the `MagiskHide Props Config` module and reboot.",
            "Run `props` in adb shell → set fingerprint to a stock, certified fingerprint; force BASIC integrity.",
            "This changes `ro.build.tags` away from `test-keys` and normalises props many checks read.",
            "Reboot and re-test.",
        ],
        "resources": [
            {"label": "MagiskHide Props Config", "url": "https://github.com/Magisk-Modules-Repo/MagiskHidePropsConf"},
        ],
    },
    "smali-patch-root": {
        "title": "Static patch — rip out the root check in smali (no root)",
        "difficulty": "medium",
        "needs": ["apktool", "uber-apk-signer", "jadx (to read logic)"],
        "steps": [
            "Decompile to read the logic: `jadx-gui target.apk` and find the method that returns the 'is rooted' boolean.",
            "Decode to smali: `apktool d target.apk -o src`",
            "In the corresponding `.smali`, force the detection method to return false: set the register to 0 and `return v0` (`const/4 v0, 0x0`).",
            "Rebuild + sign + install (see nsc-repack for the exact commands).",
            "Best when there's a single choke-point method; brittle if checks are scattered/obfuscated.",
        ],
        "resources": [
            {"label": "jadx", "url": "https://github.com/skylot/jadx"},
            {"label": "apktool smali guide", "url": "https://apktool.org/docs/the-basics/decoding"},
        ],
    },
    "safetynet-bypass": {
        "title": "SafetyNet attestation — device integrity bypass",
        "difficulty": "hard",
        "needs": ["Magisk", "Universal SafetyNet Fix / Play Integrity Fix module"],
        "steps": [
            "SafetyNet's verdict is signed by Google and usually verified server-side — you can't just hook a local boolean.",
            "Use Magisk DenyList + **Universal SafetyNet Fix** (or the newer Play Integrity Fix) to pass BASIC/CTS profile.",
            "Hardware-backed attestation (key attestation) on newer devices can't be spoofed in software — you may need a device that doesn't enforce it.",
            "Verify with an integrity-checker app that BASIC and CTS pass before re-testing the target.",
        ],
        "resources": [
            {"label": "Play Integrity Fix", "url": "https://github.com/chiteroman/PlayIntegrityFix"},
            {"label": "Universal SafetyNet Fix", "url": "https://github.com/kdrag0n/safetynet-fix"},
        ],
    },
    "play-integrity-fix": {
        "title": "Play Integrity API — MEETS_DEVICE / BASIC bypass",
        "difficulty": "hard",
        "needs": ["Magisk + Zygisk", "Play Integrity Fix module"],
        "steps": [
            "Verdict is signed by Google; the server decides. Aim to pass the tiers the app actually requires.",
            "Install the **Play Integrity Fix** Zygisk module + configure DenyList for the app and Play Store/Services.",
            "MEETS_BASIC_INTEGRITY and often MEETS_DEVICE_INTEGRITY become passable; MEETS_STRONG_INTEGRITY (hardware-backed) generally cannot be spoofed.",
            "Clear Play Store/Services data, reboot, verify verdicts with an integrity checker, then re-test.",
        ],
        "resources": [
            {"label": "Play Integrity Fix", "url": "https://github.com/chiteroman/PlayIntegrityFix"},
            {"label": "Play Integrity API docs", "url": "https://developer.android.com/google/play/integrity"},
        ],
    },
    "pairip-bypass": {
        "title": "PairIP (Google Play integrity protection) — bypass approaches",
        "difficulty": "hard",
        "needs": ["Rooted device / emulator", "Frida", "apktool/jadx (for repack routes)"],
        "steps": [
            "Identify the scope: PairIP moves the app's real bytecode into an encrypted VM run by "
            "`com.pairip.VMRunner.executeVM` (native `libpairipcore.so`). It checks Play install "
            "source, app signature, debuggers and Frida — mostly in native code.",
            "License/'Get this app from Play' gate: hook the license flow — force "
            "`com.pairip.licensecheck.LicenseClient` / `LicenseClientV3` verify callbacks to report "
            "success, or stub `com.pairip.licensecheck.LicenseActivity` so it doesn't finish the app.",
            "Signature check: hook `PackageManager.getPackageInfo`/`GET_SIGNATURES` (and "
            "`com.pairip.SignatureCheck`) to return the original signature; or patch the check.",
            "Anti-Frida/anti-debug: run frida-server renamed/on a non-default port, use gadget or "
            "`frida --runtime=v8`, and hook the native detection (ptrace/`/proc` scans in libpairipcore.so).",
            "For static/repack routes, dump the decrypted DEX from memory at runtime (the VM "
            "materialises classes) with a Frida DEX dumper, then rebuild.",
            "Use the community PairIP bypass scripts/research below as a starting point — offsets "
            "and patterns change every build, so expect to adapt.",
        ],
        "resources": [
            {"label": "Bypassing PairIP Integrity Checks (Medium)", "url": "https://petruknisme.medium.com/bypassing-pairip-integrity-checks-21d7bdd4a052"},
            {"label": "Reversing PairIP VM (Byteria Lab)", "url": "https://blog.byterialab.com/reversing-googles-new-vm-based-integrity-protection-pairip/"},
            {"label": "pairipcore research (Solaree)", "url": "https://github.com/Solaree/pairipcore"},
            {"label": "pairipcore-vm (MatrixEditor)", "url": "https://github.com/MatrixEditor/pairipcore-vm"},
        ],
    },

    # ===================================================================
    #  iOS -- SSL PINNING BYPASS
    # ===================================================================
    "objection-ssl-ios": {
        "title": "objection — SSL pinning disable (iOS)",
        "difficulty": "easy",
        "needs": ["Jailbroken device OR objection-patched IPA", "frida-server (jailbroken)", "objection"],
        "steps": [
            "Attach: `objection -g <bundle.id> explore`",
            "Run: `ios sslpinning disable`",
            "Hooks SecTrustEvaluate, NSURLSession challenge handling, TrustKit and AFNetworking/Alamofire trust evaluation.",
            "Proxy through Burp and verify TLS traffic is visible.",
        ],
        "resources": [
            {"label": "objection", "url": "https://github.com/sensepost/objection"},
        ],
    },
    "frida-ssl-universal-ios": {
        "title": "Frida — universal SSL pinning bypass (iOS)",
        "difficulty": "medium",
        "needs": ["Frida", "frida-server on jailbroken device (or Frida gadget in a resigned IPA)"],
        "steps": [
            "Run a maintained iOS unpinning script that covers SecTrust, TrustKit, AFNetworking and Alamofire.",
            "Spawn: `frida -U -f <bundle.id> -l ios-ssl-bypass.js --no-pause` (or attach with `frida -U <bundle.id> -l ...`).",
            "On a non-jailbroken device, inject the Frida **gadget** into the IPA and resign (see sideload flow) — then load the script.",
            "Route through Burp; confirm the pinning failures stop.",
        ],
        "resources": [
            {"label": "httptoolkit frida-interception-and-unpinning", "url": "https://github.com/httptoolkit/frida-interception-and-unpinning"},
            {"label": "Frida CodeShare (iOS pinning)", "url": "https://codeshare.frida.re/"},
        ],
    },
    "sslkillswitch-jb": {
        "title": "SSL Kill Switch 3 — system-wide pinning kill (jailbroken)",
        "difficulty": "easy",
        "needs": ["Jailbroken iOS device", "SSL Kill Switch 3 (Cydia/Sileo tweak)"],
        "steps": [
            "Add the SSL Kill Switch repo and install the tweak (respring after install).",
            "Settings → SSL Kill Switch → enable 'Disable Certificate Validation'.",
            "It patches the Secure Transport / BoringSSL APIs process-wide, defeating most pinning without touching the app.",
            "Set the device HTTP proxy to Burp, install the Burp CA profile, and test.",
        ],
        "resources": [
            {"label": "SSL Kill Switch 3", "url": "https://github.com/NyaMisty/ssl-kill-switch3"},
            {"label": "SSL Kill Switch 2 (classic)", "url": "https://github.com/nabla-c0d3/ssl-kill-switch2"},
        ],
    },

    # ===================================================================
    #  iOS -- JAILBREAK DETECTION BYPASS
    # ===================================================================
    "objection-jb": {
        "title": "objection — jailbreak detection disable (iOS)",
        "difficulty": "easy",
        "needs": ["frida-server (jailbroken) or gadget", "objection"],
        "steps": [
            "Attach: `objection -g <bundle.id> explore`",
            "Run: `ios jailbreak disable`",
            "Hooks common file-existence, fork(), canOpenURL and dyld checks to report 'not jailbroken'.",
            "If it still trips, identify the specific check with `ios monitor` / class tracing and hook it manually (frida-ios-jb).",
        ],
        "resources": [
            {"label": "objection", "url": "https://github.com/sensepost/objection"},
        ],
    },
    "frida-ios-jb": {
        "title": "Frida — targeted jailbreak-check bypass (iOS)",
        "difficulty": "medium",
        "needs": ["Frida", "frida-server / gadget"],
        "steps": [
            "Hide filesystem artifacts: hook `NSFileManager fileExistsAtPath:` and libc `stat`/`access`/`fopen` to deny JB paths (/bin/bash, /Applications/Cydia.app, MobileSubstrate, apt).",
            "Neutralise `fork`/`vfork` sandbox tests by returning -1 (as if it failed).",
            "Hook `UIApplication canOpenURL:` to return false for cydia:// and similar schemes.",
            "For commercial SDKs (IOSSecuritySuite), find and hook the top-level `amIJailbroken`/verdict method to return false.",
            "Use a well-maintained 'jailbreak bypass' CodeShare script as a base and add app-specific hooks.",
        ],
        "resources": [
            {"label": "Frida iOS docs", "url": "https://frida.re/docs/ios/"},
            {"label": "Frida CodeShare", "url": "https://codeshare.frida.re/"},
        ],
    },
    "frida-ios-antidebug": {
        "title": "Frida — defeat ptrace/sysctl anti-debug (iOS)",
        "difficulty": "hard",
        "needs": ["Frida", "frida-server / gadget"],
        "steps": [
            "Apps calling `ptrace(PT_DENY_ATTACH)` block debuggers/Frida attach. Spawn (don't attach) and hook early.",
            "Hook `ptrace` in libsystem_kernel and force it to return 0 without applying PT_DENY_ATTACH.",
            "Hook `sysctl` and clear the `P_TRACED` flag in the returned kinfo_proc so the app thinks it isn't traced.",
            "Also watch for `getppid`/`exit`-based traps; neutralise each as found.",
        ],
        "resources": [
            {"label": "Frida Interceptor", "url": "https://frida.re/docs/javascript-api/#interceptor"},
            {"label": "OWASP MASTG anti-debugging", "url": "https://mas.owasp.org/MASTG/"},
        ],
    },

    # ===================================================================
    #  SHARED / TOOLING
    # ===================================================================
    "frida-ssl-universal-both": {
        "title": "Setting up Frida + Burp (either platform)",
        "difficulty": "easy",
        "needs": ["Frida", "Burp Suite / mitmproxy"],
        "steps": [
            "Install the Burp CA on the device (Android: as user cert + patched NSC or system cert on root; iOS: install the profile).",
            "Set the device/emulator HTTP proxy to your Burp listener (or use a transparent proxy).",
            "Run the appropriate unpinning script, then browse the app while watching Burp's HTTP history.",
        ],
        "resources": [
            {"label": "PortSwigger — mobile testing", "url": "https://portswigger.net/burp/documentation/desktop/mobile"},
            {"label": "OWASP MASTG", "url": "https://mas.owasp.org/MASTG/"},
        ],
    },
    "frida-antihook": {
        "title": "Defeat anti-Frida / anti-Xposed self-detection",
        "difficulty": "hard",
        "needs": ["Frida", "frida-server (renamed)", "Ghidra/IDA for native checks"],
        "steps": [
            "The app scans for instrumentation: frida-server ports/strings, /data/local/tmp agents, /proc/<pid>/maps entries (frida-agent, gum-js-loop), and Xposed classes (de.robv.android.xposed, LSPosed).",
            "Rename frida-server and load the gadget via repackaging instead of a well-known server, or use `strongR-frida` to dodge string/port detection.",
            "Hook the Java detector to return clean: `Java.use('<class>').<method>.implementation = function(){ return false; };`.",
            "For native checks, find the string compare / file-open in Ghidra and patch or hook it (Interceptor.attach on the check).",
            "Hide Xposed with a hider module (e.g. LSPosed itself supports hiding) so class-lookup checks pass.",
        ],
        "resources": [
            {"label": "strongR-frida-android", "url": "https://github.com/hzzhezhe/strongR-frida-android"},
            {"label": "objection (patch/repackage)", "url": "https://github.com/sensepost/objection"},
        ],
    },
    "frida-antidebug": {
        "title": "Bypass anti-debug (TracerPid / ptrace / isDebuggerConnected)",
        "difficulty": "medium",
        "needs": ["Frida", "frida-server"],
        "steps": [
            "The app reads TracerPid from /proc/self/status (or calls ptrace(PTRACE_TRACEME)) and refuses to run if traced.",
            "Java path: hook `android.os.Debug.isDebuggerConnected` and any custom checker to return false.",
            "Native TracerPid path: hook `fopen`/`read` and rewrite the TracerPid line to 0, or hook the parser function directly.",
            "ptrace self-attach path: `Interceptor.replace(Module.getExportByName(null,'ptrace'), new NativeCallback(function(){return 0;}, 'long', ['int','int','pointer','pointer']));`.",
            "Re-run and confirm the app proceeds while your debugger/Frida stays attached.",
        ],
        "resources": [
            {"label": "Frida Interceptor", "url": "https://frida.re/docs/javascript-api/#interceptor"},
        ],
    },
    "app-shielding-bypass": {
        "title": "Commercial app-shielding / packer / RASP (DexProtector, Appdome, Promon, Bangcle, Qihoo, Legu)",
        "difficulty": "hard",
        "needs": ["Rooted device", "Frida (stealth)", "Ghidra/IDA", "frida-dexdump", "patience"],
        "steps": [
            "These products encrypt/pack the real DEX and unpack it in native code at runtime, plus run RASP (root/Frida/debugger/repackage checks) — static analysis alone will not see the real code.",
            "Dump the decrypted DEX from memory once it is loaded: `frida-dexdump -U -f <package>` (or objection memory dump), then decompile the recovered classes.",
            "Reduce RASP friction first: Magisk DenyList + Shamiko for root hiding, and a renamed/stealth Frida for instrumentation checks.",
            "Locate the integrity/verdict routine in the packer's native lib (Ghidra) and hook/patch it to report 'clean'.",
            "Expect version-specific behaviour; validate each control (root, debugger, Frida, repackage, signature) separately.",
        ],
        "resources": [
            {"label": "frida-dexdump", "url": "https://github.com/hluwa/frida-dexdump"},
            {"label": "strongR-frida-android", "url": "https://github.com/hzzhezhe/strongR-frida-android"},
        ],
    },
}


def get(guide_id):
    return GUIDES.get(guide_id)

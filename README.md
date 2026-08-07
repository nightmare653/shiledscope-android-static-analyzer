# 🛡️ ShieldScope

Static analyzer for **Android (APK)** and **iOS (IPA)** apps that answers three questions and then tells you how to get past the answers:

1. **Is root / jailbreak detection implemented?** Which mechanisms, and **how many independent layers**?
2. **Is SSL / certificate pinning implemented?** Which mechanisms, how many layers?
3. **How do I bypass each one?** — step-by-step playbooks (Frida, objection, Magisk, apktool repack, reFlutter, SSL Kill Switch…) with resource links, tailored to exactly what the app uses.

All analysis is **static** and local — no device needed, nothing leaves your machine.

> ⚠️ For **authorized** testing only: your own apps, scoped pentest engagements, CTFs, and bug-bounty programs that permit it.

## Run

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

Drop an `.apk` or `.ipa` onto the page → **Analyze**.

## How it works

| | Android | iOS |
|---|---|---|
| Metadata | androguard (package, SDKs, NSC flag, debuggable) | Info.plist (bundle id, min OS), LIEF (arch, FairPlay `cryptid`) |
| Scan target | all `classes*.dex` + native `.so` bytes | main Mach-O + framework binaries + LIEF symbols |
| Special decode | `network_security_config.xml` AXML → `<pin-set>` | embedded `.cer/.der`, bundled `*.framework` |
| Framework aware | Flutter / React Native / Xamarin / Unity / Cordova | bundled frameworks list |

Detection is a byte-signature engine (`analyzer/signatures.py`). Each finding links to bypass guides (`analyzer/guides.py`). The report shows a per-mechanism breakdown, a layer count, a heuristic protection score, and only the guides the app actually triggers.

### Beyond detection

- **Auto-generated Frida bypass script** (`analyzer/frida_gen.py`) — one ready-to-run `shieldscope_bypass.js` stitched from *only* the mechanisms found (RootBeer overrides, file/native path hiding, package-lookup blocking, `Runtime.exec` scrubbing, universal SSL/OkHttp, WebView, iOS SecTrust/jailbreak/ptrace), with the app's real package/bundle id pre-filled and the exact `frida -U -f … -l …` command. Downloadable from the UI.
- **False-positive reduction** (`analyzer/apk.py::_verify_custom_tm`) — the noisy custom-`X509TrustManager` signature is confirmed or debunked via androguard class analysis (is the implementing class outside known libraries?).
- **Cross-evidence confidence** (`analyzer/report.py::_refine_confidence`) — findings are boosted when multiple patterns match or independent mechanisms co-occur, and lone weak hits are flagged `unverified`. Shown as `N signals` / `corroborated` / `✓ verified` badges.
- **MASVS extra checks** (`analyzer/masvs.py`) — hardcoded secrets (AWS/Google/Stripe/GitHub keys, Firebase, JWTs, private keys), `debuggable`/`allowBackup`, exported components without permission, cleartext traffic, iOS ATS-disabled/exceptions, and weak-crypto indicators (ECB/DES/RC4/MD5/SHA-1). Every finding is **descriptive and located**: it reports the exact **file/element location**, the **full secret value**, a plain-English **description**, the **risk/impact**, concrete **steps to reproduce** (real `adb`/`am`/`apktool` commands with the app's own package name), and a **mitigation**. Reported separately from the layer totals. Secret matches are placeholder-filtered and private-key blocks are validated to cut false positives.

Analyzers use a single pass over the archive so every secret/crypto hit carries the precise file it came from (`classes10.dex`, `res/values/strings.xml`, `resources.arsc`, …).

### Signing, attack surface & reporting

- **APK signing & certificate analysis** (`analyzer/signing.py`) — signature scheme (v1/v2/v3), the **Janus** vulnerability (v1-only + minSdk<24, CVE-2017-13156), signer cert details, **debug-certificate** detection, weak key (RSA<2048/DSA), weak signature hash (MD5/SHA-1), expiry.
- **Attack-surface extraction** (`analyzer/surface.py`) — harvests URLs / endpoints / IPs / cloud buckets (S3, Firebase, GCS) from dex + resources, and enumerates the **exported IPC surface** (activities/services/receivers/providers) with a ready-to-run **adb PoC** per component (`am start` / `am broadcast` / `content query`).
- **OWASP MASVS mapping** — every finding and detected control is tagged with its MASVS v2 id (`MASVS-STORAGE-1`, `MASVS-NETWORK-2`, …).
- **Report export** — one-click **HTML** (print-to-PDF), **JSON**, and **SARIF 2.1.0** (for CI / GitHub code scanning), generated fully client-side/offline.

### Extracted-data analyzer (offline)

Upload a pulled data dir — an `.ab` Android backup, or a `.tar`/`.zip` of `/data/data/<pkg>/` (via `adb backup` / `run-as` / rooted copy) — and it scans **offline**: `shared_prefs/*.xml` for cleartext secrets, and `*.db`/`*.sqlite` (opened read-only with stdlib `sqlite3`) for secrets + PII, flagging encrypted/opaque stores as good. See `analyzer/datadir.py`.

Validated against real ~120 MB apps (Wolt / Wolt Partner): correctly separates Flutter vs React Native, and surfaces a live Google API key, Firebase URL, exported components, and `allowBackup` with reproduction steps.

### Detected mechanisms (summary)

- **Android root:** RootBeer, su-path checks, root-package enumeration, `test-keys`, Magisk artifacts, BusyBox/`which su`, SafetyNet, Play Integrity, freeRASP/DexGuard RASP, emulator checks.
- **Android SSL:** OkHttp CertificatePinner, Network Security Config `<pin-set>`, TrustKit, custom TrustManager/HostnameVerifier, WebView SSL errors, native/BoringSSL pinning.
- **iOS jailbreak:** Cydia/Sileo paths, JB file checks, `fork()`/sandbox, `canOpenURL(cydia://)`, IOSSecuritySuite, ptrace/sysctl anti-debug.
- **iOS SSL:** TrustKit, AFNetworking, Alamofire ServerTrustManager, URLSession challenge pinning, low-level SecTrust/BoringSSL, embedded certs.

## Limitations

Static analysis infers from bytes/strings: it can **miss** heavily obfuscated, packed, or server-side checks, and can occasionally **over-report** code that lives in a shared library. Confirm dynamically (Frida/objection) before drawing firm conclusions. App Store IPAs are usually FairPlay-encrypted — decrypt first for full symbol coverage.

## Layout

```
shieldscope/
  app.py                 Flask app (upload + /api/analyze)
  analyzer/
    report.py            entry point, type detection, scoring, guide collection
    apk.py  ipa.py       platform analyzers
    signatures.py        byte-signature knowledge base
    guides.py            step-by-step bypass playbooks
  templates/index.html  static/style.css  static/app.js
```

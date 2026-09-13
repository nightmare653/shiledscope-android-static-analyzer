# 🛡️ ShieldScope

Static analyzer for **Android (APK)** and **iOS (IPA)** apps that answers three questions and then tells you how to get past the answers:

1. **Is root / jailbreak detection implemented?** Which mechanisms, and **how many independent layers**?
2. **Is SSL / certificate pinning implemented?** Which mechanisms, how many layers?
3. **How do I bypass each one?** — step-by-step playbooks (Frida, objection, Magisk, apktool repack, reFlutter, SSL Kill Switch…) with resource links, tailored to exactly what the app uses.

All analysis is **static** and local — no device needed, nothing leaves your machine.

> ⚠️ For **authorized** testing only: your own apps, scoped pentest engagements, CTFs, and bug-bounty programs that permit it.

## Run

**GUI (web):**
```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```
Drop an `.apk` or `.ipa` onto the page → **Analyze**.

**CLI (headless / CI):**
```bash
python cli.py app.apk                    # readable summary in the terminal
python cli.py app.apk --json out.json    # full result as JSON
python cli.py app.apk --keep-decompiled  # keep + print the decompiled tree (smali/java/res)
python cli.py app.apk --fail-on high     # non-zero exit if any high finding (CI gate)
```
Same engine as the GUI; no server needed.

### Requirements (Android deep engine)

The Android analyzer decompiles the app, so it needs three external tools on the
machine (auto-detected on startup; override with the env vars if they live
elsewhere):

| Tool | Purpose | Env override |
|---|---|---|
| **Java 17+** (JRE) | runs jadx & apktool | `SHIELDSCOPE_JAVA` |
| **jadx** | Java decompilation (reconstructs constant strings) | `SHIELDSCOPE_JADX_JAR` → `jadx-*-all.jar` |
| **apktool** | smali + decoded resources/manifest | `SHIELDSCOPE_APKTOOL_JAR` → `apktool.jar` |

Optional extra engines (auto-detected; each just widens coverage when present):

| Tool | Purpose | Env override |
|---|---|---|
| **dex2jar + CFR** | DEX→Java **fallback** when jadx is absent/times out (different decompilers recover different obfuscated classes; smali is still scanned alongside) | `SHIELDSCOPE_DEX2JAR` → dex-tools dir · `SHIELDSCOPE_CFR_JAR` → `cfr*.jar` |
| **Ghidra** | decompiles native `.so` to C so native pinning/root logic + secrets become scannable (opt-in, heavy) | `SHIELDSCOPE_GHIDRA` → Ghidra dir; enable per-run with `SHIELDSCOPE_ENABLE_GHIDRA=1` |
| **blutter** | Flutter `libapp.so` → Dart class/method dump (Flutter hides logic/secrets/pinning in an AOT snapshot) | `SHIELDSCOPE_BLUTTER` → `blutter.py` |
| **hbctool** | React Native **Hermes** bytecode bundle → disassembly | on `PATH` (`pip install hbctool`) |
| **frida-dexdump** | runtime-unpacks a **packed** app (PairIP/DexProtector/Bangcle/…) from a device and re-scans the recovered DEX | on `PATH` (`pip install frida-dexdump`); needs a device + frida-server |

Install: `winget install Skylot.jadx` (then grab the CLI zip) / `apt install jadx apktool` /
`brew install jadx apktool`. dex2jar (`pxb1988/dex2jar`) and CFR (`cfr.jar`) are single
downloads; Ghidra is the NSA suite. Other tuning: `SHIELDSCOPE_HEAP` (default `4g`),
`SHIELDSCOPE_JADX_TIMEOUT` (default `600`s), `SHIELDSCOPE_APKTOOL_TIMEOUT` (default `300`s),
`SHIELDSCOPE_DECOMPILE_FALLBACK=0` to disable the dex2jar+CFR path,
`SHIELDSCOPE_GHIDRA_TIMEOUT` (default `600`s/lib) and `SHIELDSCOPE_GHIDRA_MAXLIBS` (default `8`).
Every external tool runs under a hard timeout — a hostile app **cannot** hang the run.
Coverage degrades gracefully: jadx → dex2jar+CFR → complete smali → raw bytes.

### Extra capabilities

- **Runtime unpack of packed apps** — when a commercial packer/RASP is detected and a
  device is connected, `POST /api/ai/frida/dexdump` (package, device_id) dumps the
  decrypted DEX with frida-dexdump and re-runs the full engine on it, surfacing findings
  the packed APK hid. Needs frida-dexdump + a device.
- **Secret liveness validation (opt-in, network)** — `python cli.py app.apk --validate-secrets`
  (or `SHIELDSCOPE_VALIDATE_SECRETS=1`) probes each discovered vendor key with a single
  READ-ONLY API call (GitHub, GitLab, Stripe, Slack, SendGrid, Telegram, npm, OpenAI,
  HuggingFace, Google) and marks it **live / invalid / unknown**; live keys are promoted to
  confirmed high-severity. Authorized testing only.
- **Result cache** — `SHIELDSCOPE_CACHE=1` caches the static result by APK SHA-256
  (`SHIELDSCOPE_CACHE_DIR`, default `~/.shieldscope/cache`), keyed by engine version so a
  code change self-invalidates. Re-scanning an unchanged APK returns instantly.
- **CORS** — the web API is restricted to the local UI origin (no wildcard), closing the
  drive-by risk. Add origins with `SHIELDSCOPE_CORS_ORIGINS` (comma-separated).

## How it works (Android deep engine)

The Android path (`analyzer/apk_deep.py`) is a staged pipeline, not a byte scan:

1. **Unpack** (`analyzer/unpack.py`) — apktool (smali + decoded resources/manifest)
   and jadx (Java with reconstructed constant strings) run under hard timeouts,
   plus **recursive extraction of nested archives** (jar/zip/apk/aar inside
   `assets/`, `lib/`, …). A secret hidden in a bundled jar ends up on disk as a
   real file.
2. **Behavioral detection** (`analyzer/detect.py`) — root/jailbreak & SSL pinning
   are matched over **smali** (string constants + `.implements` interface
   contracts) and native `.so` symbols, so detection **survives R8/DexGuard
   renaming** (a class renamed to `Lp3/a;` is still found). It reads
   `checkServerTrusted` bodies to tell real pinning from a **trust-all
   TrustManager** (a MITM *vulnerability*, reported as such — never counted as
   protection). It also scores obfuscation and records the app's actual (renamed)
   TrustManager class names.
3. **Exhaustive secret hunt** (`analyzer/deepscan.py` + `analyzer/secret_rules.py`)
   — walks the **entire** tree (no extension allowlist): decompiled Java, decoded
   resources, `resources.arsc`, nested-archive contents, and `strings` of every
   binary. ~48 vendor detectors + entropy, run via a fast **anchor-dispatch**
   engine (a 160 MB decompiled tree scans in well under a minute, parallelised).
4. **Signing / manifest / IPC / attack surface** — signer cert (Janus, debug
   cert, weak key/hash), exported components with adb PoCs, URLs/buckets/IPs,
   weak crypto — over the raw dex/so bytes and the parsed manifest.

Each finding links to bypass guides (`analyzer/guides.py`); the auto-generated
Frida script (`analyzer/frida_gen.py`) hooks the **discovered** class names, so
it works on obfuscated apps.

### Auth-surface & API attack surface

- **Auth surface** (`analyzer/detect.py`) — flags **guest / anonymous / skip-login
  access paths** (a common broken-access-control entry that lets an unauthenticated
  user reach authenticated data / IDOR) and **client-side authorization flags**
  (`isPremium`/`isAdmin`/… decided on-device → bypassable), each with a test playbook.
- **API endpoints + pentest playbooks** (`analyzer/apiscan.py`) — harvests every
  endpoint (absolute URLs **and** relative `/api/...` paths, including ones built
  from a base URL), separates third-party/SDK hosts, and **classifies each by
  sensitivity** (auth, IDOR-prone user data, financial, admin, file, GraphQL, OTP…)
  with a concrete **how-to-test** playbook: the likely weakness, the request/payload
  to try, and the tool. Static leads to verify with an intercepting proxy.

### jadx is adaptive

jadx is the slow stage. On a large multidex app it can run 15+ min and still only
produce *partial* Java — which is slower **and** less complete than the smali apktool
already gave us. So the engine runs jadx only when the dex is small enough to finish
quickly (`SHIELDSCOPE_JADX_MAXDEX_MB`, default 45); larger apps use complete smali
instead. Force either way with `SHIELDSCOPE_FORCE_JADX=1`/`=0`.

### Tests

```bash
pytest -m "not integration"   # fast unit tests (no APK/tools needed)
pytest -m integration         # full engine on sample APKs (slow; needs jadx/apktool + APKs)
```
Point the integration tests at your APKs with `SHIELDSCOPE_TEST_APKS=/path/to/dir`.

> The legacy byte-signature engine (`analyzer/apk.py`, `analyzer/signatures.py`)
> remains for reference and supplies the fast metadata read; iOS still uses
> `analyzer/ipa.py`.

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

- **Android root / integrity / anti-tamper:** RootBeer, su-path checks, root-package enumeration, `test-keys`, Magisk artifacts, BusyBox/`which su`, SafetyNet, Play Integrity, freeRASP/DexGuard RASP, emulator checks, and **PairIP** — Google Play's VM-based integrity protection (`libpairipcore.so` / `com.pairip.VMRunner` / `licensecheck`), detected via smali class refs *and* the native lib, with a dedicated bypass playbook.
- **Hygiene checks (parity with common APK scanners):** missing `FLAG_SECURE` (screens capturable/overlayable), tapjacking (no obscured-touch filtering), debug logging in release, unprotected broadcasts, and keyboard-cache on password fields.
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

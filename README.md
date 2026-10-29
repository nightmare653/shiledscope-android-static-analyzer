# 🛡️ ShieldScope — Android/iOS static analyzer

ShieldScope is a **local, static** security analyzer for **Android (APK)** and
**iOS (IPA)** apps (plus pulled data directories). It answers three questions and
then tells you how to act on the answers:

1. **Is root / jailbreak detection implemented?** Which mechanisms, and how many independent layers?
2. **Is SSL / certificate pinning implemented?** Which mechanisms, how many layers?
3. **What else is wrong, and how do I test it?** — secrets, insecure config, weak crypto, exported IPC, WebView/intent issues, signing problems, and more — each with a located, plain-English finding, a reproduction, and a fix, plus a **MASTG/MASVS pentest checklist** you tick off and export.

Everything runs **on your machine** — no device needed for static analysis, and nothing leaves your computer unless you explicitly enable the optional AI layer or secret-liveness validation.

> ⚠️ **For authorized testing only** — your own apps, scoped pentest engagements, CTFs, and bug-bounty programs that permit it.

---

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [CLI usage](#cli-usage) — every flag, examples, exit codes
- [Web GUI](#web-gui)
- [Understanding the output](#understanding-the-output) — **score, severity tags, categories, MASVS tags, confidence badges**
- [What ShieldScope detects](#what-shieldscope-detects)
- [The pentest checklist](#the-pentest-checklist-android--ios)
- [Secret liveness validation](#secret-liveness-validation-opt-in)
- [Exports](#exports)
- [Decompile engines & coverage](#decompile-engines--coverage)
- [Environment-variable reference](#environment-variable-reference)
- [JSON output schema](#json-output-schema)
- [Optional AI layer](#optional-ai-layer)
- [Tests](#tests)
- [Limitations](#limitations)
- [Project layout](#project-layout)

---

## Install

ShieldScope's engine is **Python 3** (standard library + a few packages). The
Android deep engine also shells out to external decompilers.

```bash
pip install -r requirements.txt
```

`requirements.txt` pulls in Flask (web UI), flask-cors, androguard (manifest /
signing), and LIEF (native-binary hardening checks).

### External tools (Android deep engine)

| Tool | Purpose | Required? | How to point ShieldScope at it |
|---|---|---|---|
| **Java 17+** (JRE/JDK) | runs jadx / apktool / dex2jar / CFR | required for the deep engine | `SHIELDSCOPE_JAVA` or `JAVA_HOME`, else `PATH` |
| **apktool** | smali + decoded manifest & resources | strongly recommended | `SHIELDSCOPE_APKTOOL_JAR` → `apktool.jar` |
| **jadx** | DEX → Java (reconstructs constant strings) | recommended | `SHIELDSCOPE_JADX_JAR` → `jadx-*-all.jar` |
| **dex2jar + CFR** | DEX → Java **fallback** when jadx is absent/times out | optional | `SHIELDSCOPE_DEX2JAR` → dex-tools dir · `SHIELDSCOPE_CFR_JAR` → `cfr*.jar` |
| **Ghidra** | decompiles native `.so` to C (opt-in, heavy) | optional | `SHIELDSCOPE_GHIDRA` → Ghidra dir; enable per run with `SHIELDSCOPE_ENABLE_GHIDRA=1` |
| **objdump** | fast `.so` / Mach-O dynamic symbol & import dump (sharpens native pinning / anti-debug / root detection without Ghidra) | optional | on `PATH` (binutils / LLVM), or `SHIELDSCOPE_OBJDUMP` |
| **rizin** (or radare2) | `.so` / Mach-O imports + exports + symbols (objdump fallback) | optional | on `PATH`, or `SHIELDSCOPE_RIZIN` |
| **blutter** | Flutter `libapp.so` → Dart dump | optional | `SHIELDSCOPE_BLUTTER` → `blutter.py` |
| **hbctool** | React-Native Hermes bytecode → disasm | optional | on `PATH` (`pip install hbctool`) |
| **frida-dexdump** | runtime-unpack a **packed** app (device needed) | optional | on `PATH` (`pip install frida-dexdump`) |

Everything is **auto-detected** on startup; set the env var only if a tool lives
somewhere unusual. **Coverage degrades gracefully** if a tool is missing:
`jadx → dex2jar+CFR → complete smali → raw bytes`. Every external tool runs under
a hard timeout, so a hostile app **cannot** hang the run.

Typical installs:

```bash
# jadx + apktool
winget install Skylot.jadx          # Windows (then grab the CLI zip)
apt install jadx apktool            # Debian/Ubuntu
brew install jadx apktool           # macOS
# dex2jar + CFR (single downloads)
#   dex2jar: github.com/pxb1988/dex2jar/releases   (a dex-tools dir)
#   cfr:     github.com/leibnitz27/cfr/releases     (cfr-0.152.jar)
```

---

## Quick start

```bash
# CLI — readable summary in the terminal
python cli.py app.apk

# CLI — full machine-readable result
python cli.py app.apk --json result.json

# Web GUI
python app.py          # then open http://127.0.0.1:5000
```

The CLI and the GUI use the **same engine**.

---

## CLI usage

```
python cli.py <target> [--json FILE] [--keep-decompiled] [-q] [--fail-on LEVEL] [--validate-secrets]
```

**`<target>`** — path to an `.apk`, `.ipa`, or an extracted data dir
(`.ab` Android backup / `.tar` / `.zip` of `/data/data/<pkg>/`, or a lone `.db` /
`.xml`). Type is detected from file **content**, not just the extension.

| Flag | What it does | When to use it |
|---|---|---|
| `--check-tools` | Print which analysis tools are installed, whether the output will be **accurate**, and copy-paste **install steps** for anything missing — then exit (no target needed). | Before your first scan, or when results look thin, to confirm the environment is complete. |
| `--json FILE` | Write the **complete** result as JSON to `FILE`. | Automation, CI, re-rendering, diffing, feeding other tools. |
| `--keep-decompiled` | Keep the decompiled scratch tree (apktool smali + resources + manifest, jadx/CFR Java when run, raw unzip) and print its path. | When you want to grep the decompiled sources yourself after the scan. |
| `-q`, `--quiet` | Suppress the readable summary (useful with `--json`). | CI / piping. |
| `--fail-on {high,medium,low}` | **Exit non-zero** if any finding at or above this severity exists. | CI gate — e.g. fail the build on any `high`. |
| `--validate-secrets` | **Opt-in, network.** Probe each discovered vendor key with a read-only API call and mark it live/invalid. | Confirming which hardcoded keys are actually exploitable (authorized testing only). |

### Examples

```bash
python cli.py --check-tools                   # are all tools present? will output be accurate?
python cli.py app.apk                        # readable terminal summary
python cli.py app.apk --json out.json         # full JSON result
python cli.py app.apk --keep-decompiled       # keep + print the decompiled tree path
python cli.py app.apk --fail-on high          # CI gate: non-zero exit on any high finding
python cli.py app.apk --validate-secrets      # confirm which embedded keys are live
python cli.py app.ipa --json ios.json          # iOS works the same way
python cli.py backup.ab                       # scan a pulled data dir offline
SHIELDSCOPE_CACHE=1 python cli.py app.apk      # cache the result by SHA-256 (instant re-scan)
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. (If `--fail-on` is set, no finding reached that severity.) |
| `1` | Analysis failed — the engine returned `ok:false`. |
| `2` | Bad invocation (no such file). |
| `3` | `--fail-on` tripped: a finding at/above the chosen severity exists. |

---

## Web GUI

```bash
python app.py        # http://127.0.0.1:5000
```

Drag an `.apk` / `.ipa` (or a pulled data dir) onto the page → **Analyze**. Results
render as **tabs**:

- **Overview** — app identity (package/bundle id, version, SDK, permissions, SHA-256), **language / build** (Kotlin / Java / mixed, or the cross-platform framework's language), the protection score, signing, obfuscation, frameworks, notes.
- **Protection** — root/jailbreak and SSL/pinning mechanisms, each with its layer, confidence, and bypass guides.
- **Findings** — every other issue (secrets, config, crypto, WebView, IPC, …), expandable with full detail.
- **Attack surface** — exported IPC components (with `adb` PoCs), harvested API endpoints (with test playbooks), and network surface (URLs / buckets / IPs).
- **Bypass** — the auto-generated Frida script for exactly the mechanisms found, plus step-by-step bypass playbooks.
- **✅ Checklist** — the [MASTG/MASVS pentest checklist](#the-pentest-checklist-android--ios) for the app's platform.

A toolbar on top exposes the **exports** (HTML / JSON / SARIF / Burp scope / targets) and the optional AI pentest plan.

The GUI's CORS is restricted to the local origin (not wildcarded). Add origins
with `SHIELDSCOPE_CORS_ORIGINS` if you front it with something else.

---

## Understanding the output

Each run produces a **protection score**, a set of **mechanisms** (root + SSL), and
a list of **findings**. Everything is tagged so you can triage fast.

### Protection score & rating

A 0–100 heuristic for how hard the app is to tamper/intercept, rewarding multiple
independent and hard-to-bypass layers:

| Score | Rating |
|---|---|
| 0 | None detected |
| 1–24 | Weak |
| 25–54 | Moderate |
| 55–79 | Strong |
| 80–100 | Very strong |

A **trust-all TrustManager** (disabled TLS validation) **caps** the rating at
"Moderate" regardless of score — a live MITM hole shouldn't read as "very strong".

### Severity tags

Every finding carries one severity. In the terminal they're colour-coded; in JSON
they're the `severity` field.

| Tag | Meaning — how to treat it |
|---|---|
| **high** | Likely exploitable / direct exposure (live secret, disabled TLS, debuggable build, RCE-class WebView bridge, private key in the app). Fix now. |
| **medium** | Real weakness that usually needs a condition or a chain (exported component, `allowBackup`, cleartext, intent redirection, weak key/hash). |
| **low** | Hardening gap / defence-in-depth (no `FLAG_SECURE`, tapjacking, missing native mitigations, keyboard cache). |
| **info** | Observation / capability to verify dynamically (uses external storage, sends SMS, raw SQL, biometric auth present). Not a bug by itself. |

`--fail-on` uses this ordering (`high` > `medium` > `low`; `info` never trips it).

### Finding categories

The `category` field groups findings by subject:

| Category | What it covers |
|---|---|
| `root` | root/jailbreak & integrity/anti-tamper mechanisms |
| `ssl` | certificate/public-key pinning (and trust-all vulns) |
| `secret` | hardcoded credentials, keys, tokens, private keys |
| `crypto` | weak/deprecated algorithms, ECB, hardcoded keys |
| `config` | manifest/plist config: `allowBackup`, `debuggable`, cleartext, NSC, exported components, low minSdk, ATS |
| `platform` | IPC / deep links / intent redirection / clipboard / pasteboard / URL schemes |
| `webview` | insecure WebView configuration |
| `storage` | insecure local storage (prefs, SQLite, external storage, Data Protection) |
| `code` | dangerous APIs: command exec, dynamic code loading, SMS, raw SQL |
| `auth` | guest/skip-login paths, client-side authorization flags, biometric/local auth |
| `signing` | signature scheme, Janus, debug cert, weak key/hash, expiry |
| `hardening` | missing native-binary exploit mitigations (NX/PIE/RELRO/canary/ARC) |
| `permission` | dangerous / weak-custom permissions |
| `pii` | personal data found in extracted data dirs |

### MASVS tags

Every finding is mapped to an **OWASP MASVS v2** control so you can line results up
with the standard. The tag is the `masvs` field. Tags you'll see:

| Tag | MASVS control — what it's about |
|---|---|
| `MASVS-STORAGE-1` | Secure storage of sensitive data (no secrets/PII in cleartext). |
| `MASVS-STORAGE-2` | No sensitive data in logs, backups, external storage, clipboard. |
| `MASVS-CRYPTO-1` | Strong, standard cryptographic key management. |
| `MASVS-CRYPTO-2` | No weak/deprecated cryptographic algorithms. |
| `MASVS-AUTH-1` | Secure authentication (tokens/credentials). |
| `MASVS-AUTH-2` | Authorization enforced on the backend, not the client/biometric UI. |
| `MASVS-NETWORK-1` | Secure network config (no cleartext, no disabled validation). |
| `MASVS-NETWORK-2` | Certificate/public-key pinning for sensitive endpoints. |
| `MASVS-PLATFORM-1` | Safe IPC: exported components, deep links, providers, intents. |
| `MASVS-PLATFORM-2` | Safe WebView usage (no risky bridges/file access). |
| `MASVS-PLATFORM-3` | No sensitive data leaked via UI (screens, clipboard, pasteboard). |
| `MASVS-CODE-1` | Input validation / injection resistance. |
| `MASVS-CODE-2` | No unsafe dynamic code loading / updates. |
| `MASVS-CODE-4` | Binary built with exploit mitigations. |
| `MASVS-RESILIENCE-2` | Anti-tamper / integrity checks present. |
| `MASVS-RESILIENCE-3` | Trusted signing / no debug cert / integrity. |
| `MASVS-RESILIENCE-4` | Anti-debug / anti-instrumentation. |
| `MASVS-PRIVACY-1` | Minimises collection of personal data. |
| `MASVS-PRIVACY-2` | Minimises permissions. |

### Confidence badges

To cut false positives, findings carry a confidence signal (shown as badges in the
GUI, and as fields on root/SSL mechanisms in JSON):

| Badge / field | Meaning |
|---|---|
| **N signals** (`signals`, `multi_signal`) | Multiple independent patterns matched → confidence boosted. |
| **corroborated** (`corroborated`) | Several independent mechanisms co-occur (deliberate hardening) → boosted. |
| **✓ verified** (`verified: true`) | Behaviourally confirmed (e.g. a custom TrustManager read as real pinning, not trust-all). |
| **unverified** (`unverified: true`) | A single weak, unconfirmed hit — treat with caution. |

### Anatomy of a finding

Every finding is **descriptive and located**. In JSON each one has:

| Field | What it is |
|---|---|
| `id` | Stable identifier (secrets use a hash of the value, so each is unique). |
| `title` | One-line headline. |
| `severity` | `high` / `medium` / `low` / `info` (see above). |
| `category` | Subject group (see above). |
| `location` | Exact file / class / manifest element it came from (e.g. `classes2.dex:13171`, `com.app.MainActivity`, `res/xml/...`). |
| `evidence` | The matched value / token / class — the proof. |
| `description` | Plain-English explanation. |
| `risk` | Why it matters / the impact. |
| `reproduce` | Concrete steps (real `adb`/`am`/`apktool`/`frida` commands with the app's own package). |
| `mitigation` | How to fix it. |
| `masvs` | The MASVS control tag. |

---

## What ShieldScope detects

**App-owned code only** where it matters: behavioural detectors filter out
known third-party SDK namespaces so you see *your* app's issues, not a library's.

- **Android root / integrity / anti-tamper** — RootBeer, su-path & root-package checks, `test-keys`, Magisk artifacts, BusyBox/`which su`, SafetyNet, Play Integrity, freeRASP/DexGuard RASP, emulator checks, **anti-Frida / anti-Xposed / anti-debug (TracerPid)**, commercial **packers/RASP** (DexProtector, Appdome, Promon, Bangcle/SecNeo, Qihoo, Tencent Legu) and **PairIP** (Google Play's VM-based protection, via smali + `libpairipcore.so`).
- **Android SSL / pinning** — OkHttp CertificatePinner, Network Security Config `<pin-set>`, TrustKit, **X509TrustManagerExtensions**, custom `HttpsURLConnection` `SSLSocketFactory`, Volley HurlStack, **Cronet** `addPublicKeyPins`, React-Native pinning bridges, custom TrustManager/HostnameVerifier, WebView SSL errors, native/BoringSSL, **Flutter** `badCertificateCallback`. Reads `checkServerTrusted` bodies to tell real pinning from a **trust-all** TrustManager (reported as a MITM *vulnerability*).
- **Secret hunt** — ~48 vendor detectors (AWS, Google/Firebase, Stripe, GitHub/GitLab, Slack, Twilio, SendGrid, Mailgun/Mailchimp, Telegram, Discord, OpenAI/Anthropic/HuggingFace, DB URIs, basic-auth URLs, JWTs, private keys …) **plus** keyword-gated high-entropy detection over the whole tree, with placeholder/class-reference filtering. Optional [liveness validation](#secret-liveness-validation-opt-in).
- **Behavioural code checks (HackTricks / MASTG-aligned)** — OS command exec (`Runtime.exec`/`ProcessBuilder`), **dynamic code loading** (`DexClassLoader`), SMS send, **intent redirection** (`Intent.parseUri`), raw-SQL / SQLi surface, and **biometric/local auth** presence.
- **Config / manifest** — `allowBackup`, `debuggable`, cleartext traffic, exported components (with `adb` PoCs), content-provider exposure, task hijacking, deep-link surface, mutable `PendingIntent`, custom/dangerous permissions, Firebase misconfig, NSC trusting **user CAs** / shipping `<debug-overrides>`, low `minSdkVersion`.
- **WebView** — `addJavascriptInterface` bridge, universal/file access from file URLs, remote debugging, `setSavePassword`, mixed content, and deep-link → WebView taint.
- **Signing** — v1/v2/v3 scheme, **Janus** (CVE-2017-13156), **debug certificate** in release, weak key (RSA<2048/DSA), weak signature hash (MD5/SHA-1), expiry.
- **Crypto** — ECB mode, DES/3DES/RC4, MD5/SHA-1, weak-crypto indicators.
- **Storage** — SharedPreferences/SQLite without encryption, external-storage use, clipboard writes.
- **Native hardening** — per-`.so` NX / PIE / RELRO / stack-canary via LIEF.
- **Attack surface** — API endpoints (absolute + relative paths) classified by sensitivity with test playbooks; exported IPC with `adb` PoCs; URLs / cloud buckets / IPs.
- **iOS** — jailbreak (Cydia/Sileo, fork/sandbox, IOSSecuritySuite, ptrace/sysctl, anti-Frida/dylib-integrity), SSL (TrustKit, AFNetworking, Alamofire, URLSession SecTrust, native, Flutter), entitlements (**get-task-allow** = debuggable, wildcard App ID), **custom URL schemes**, **WKWebView file access**, weak **Keychain** accessibility, **LocalAuthentication**, **NSFileProtectionNone**, **hot-patch frameworks** (JSPatch/CodePush/Rollout), NSLog, **binary hardening** (PIE/stack-canary/ARC), NSUserDefaults/UIWebView/pasteboard, ATS, and secret/storage scanning.
- **Extracted data dirs** — `shared_prefs/*.xml` and `*.db`/`*.sqlite` scanned offline for cleartext secrets & PII; encrypted stores flagged as good.

Each finding links to **bypass guides** (`analyzer/guides.py`), and the
auto-generated **Frida script** (`analyzer/frida_gen.py`) hooks the *discovered*
class names, so it works on obfuscated apps.

---

## The pentest checklist (Android + iOS)

The **Checklist** tab is a MASTG/MASVS + HackTricks-aligned test-case tracker that
**auto-selects the platform** of the analysed app (APK → Android, IPA → iOS).

- **Static** and **Dynamic** sub-tabs, grouped by category (storage, crypto, network, platform/IPC, WebView, resilience, auth; plus dynamic setup, interception, runtime storage, instrumentation, business logic).
- Mark each item **✓ Pass / ✗ Fail / – N/A** and attach a free-text note.
- Live **progress** (overall + per-phase + per-category), saved **per app** in your browser (keyed by SHA-256) so it persists across reloads.
- **Auto-annotated** from the scan: items ShieldScope already has evidence for are pre-flagged (e.g. a detected WebView bridge pre-flags the WebView test case, a weak-Keychain finding pre-flags the Keychain item).
- **Download** as **Markdown / HTML / JSON** — the file is titled and named per platform (`shieldscope_checklist_android_<app>.md`).

---

## Secret liveness validation (opt-in)

With `--validate-secrets` (CLI) or `SHIELDSCOPE_VALIDATE_SECRETS=1`, ShieldScope
confirms **which hardcoded keys are actually live** by making a single,
**read-only** probe to each vendor's API: GitHub, GitLab, Stripe, Slack, SendGrid,
Telegram, npm, OpenAI, HuggingFace, Google. A live key is promoted to a confirmed
**high-severity** finding and sorted to the top; a dead one is marked so you can
deprioritise it.

This is **off by default** and **network-gated** — it sends the discovered key to
its own vendor over TLS, nothing else, for **authorized testing only**. No key is
ever written anywhere. Tunables: `SHIELDSCOPE_VALIDATE_TIMEOUT`,
`SHIELDSCOPE_VALIDATE_MAX`.

---

## Exports

From the GUI toolbar (all generated client-side / offline):

| Export | Use it for |
|---|---|
| **HTML** | A self-contained report to print / PDF / share. |
| **JSON** | The full result (same as CLI `--json`) for automation/diffing. |
| **SARIF 2.1.0** | CI / GitHub code scanning ingestion. |
| **Burp scope** | A scope file for your intercepting proxy, built from harvested hosts. |
| **Targets** | A flat list of endpoints/hosts to probe. |

The **checklist** has its own Markdown / HTML / JSON download (see above).

---

## Decompile engines & coverage

The Android path is a staged pipeline, not a byte scan:

1. **Unpack** — apktool (smali + decoded resources/manifest) and jadx (Java with reconstructed strings), plus recursive extraction of nested archives. jadx is **adaptive**: on a large multidex app it only runs when the dex is small enough to finish quickly (`SHIELDSCOPE_JADX_MAXDEX_MB`, default 45), otherwise complete smali is used. Force either way with `SHIELDSCOPE_FORCE_JADX=1`/`=0`.
2. **dex2jar + CFR fallback** — when jadx produced no Java, dex2jar → CFR recovers readable Java; **smali is still scanned alongside** (different decompilers recover different classes). Disable with `SHIELDSCOPE_DECOMPILE_FALLBACK=0`.
3. **Native `.so`** — a raw-string pass over every `.so`, plus (when present) a fast **objdump / rizin** dynamic-symbol & import dump that sharpens native pinning / root / anti-debug / anti-Frida detection on stripped blobs without a heavy decompile. **Ghidra (opt-in)** additionally decompiles native `.so` to C so native logic and secrets become scannable (`SHIELDSCOPE_ENABLE_GHIDRA=1`).
4. **Framework deep-dive** — Flutter (`libapp.so` via blutter) and React-Native Hermes (via hbctool); Xamarin assemblies are detected and flagged.
5. **Runtime unpack (packed apps)** — when a packer/RASP is detected and a device is connected, `POST /api/ai/frida/dexdump` dumps the decrypted DEX with frida-dexdump and re-runs the engine on it.

If jadx/apktool are missing the engine degrades to smali-only, then raw bytes.

---

## Environment-variable reference

All optional; everything is auto-detected when unset.

| Variable | Default | What it controls |
|---|---|---|
| `SHIELDSCOPE_JAVA` | `JAVA_HOME`/`PATH` | Path to `java`. |
| `SHIELDSCOPE_APKTOOL_JAR` | auto | Path to `apktool.jar`. |
| `SHIELDSCOPE_JADX_JAR` | auto | Path to `jadx-*-all.jar`. |
| `SHIELDSCOPE_DEX2JAR` | auto | dex-tools dir (DEX→JAR fallback). |
| `SHIELDSCOPE_CFR_JAR` | auto | Path to `cfr*.jar` (JAR→Java fallback). |
| `SHIELDSCOPE_GHIDRA` | auto | Ghidra install dir. |
| `SHIELDSCOPE_ENABLE_GHIDRA` | `0` | `1` enables native `.so` decompilation this run. |
| `SHIELDSCOPE_GHIDRA_TIMEOUT` | `600` | Seconds per native lib. |
| `SHIELDSCOPE_GHIDRA_MAXLIBS` | `8` | Max `.so` files to decompile. |
| `SHIELDSCOPE_BLUTTER` | auto | Path to `blutter.py` (Flutter Dart dump). |
| `SHIELDSCOPE_OBJDUMP` | auto | Path to objdump / llvm-objdump (native symbol dump). |
| `SHIELDSCOPE_RIZIN` | auto | Path to rizin / radare2 (native symbol dump, objdump fallback). |
| `SHIELDSCOPE_HEAP` | `4g` | JVM max heap for the external tools. |
| `SHIELDSCOPE_JADX_TIMEOUT` | `600` | jadx hard timeout (s). |
| `SHIELDSCOPE_APKTOOL_TIMEOUT` | `300` | apktool hard timeout (s). |
| `SHIELDSCOPE_FW_TIMEOUT` | `300` | Flutter/Hermes stage timeout (s). |
| `SHIELDSCOPE_JADX_MAXDEX_MB` | `45` | Dex size above which jadx is skipped for smali. |
| `SHIELDSCOPE_FORCE_JADX` | — | `1` always run jadx, `0` never. |
| `SHIELDSCOPE_DECOMPILE_FALLBACK` | `1` | `0` disables the dex2jar+CFR fallback. |
| `SHIELDSCOPE_CODE_ENTROPY` | `1` | `0` disables keyword-gated entropy on code (faster). |
| `SHIELDSCOPE_CACHE` | `0` | `1` caches the static result by SHA-256 (+ engine version). |
| `SHIELDSCOPE_CACHE_DIR` | `~/.shieldscope/cache` | Cache location. |
| `SHIELDSCOPE_VALIDATE_SECRETS` | `0` | `1` enables secret-liveness probes (network). |
| `SHIELDSCOPE_VALIDATE_TIMEOUT` | `8` | Per-probe timeout (s). |
| `SHIELDSCOPE_VALIDATE_MAX` | `40` | Max probes per scan. |
| `SHIELDSCOPE_CORS_ORIGINS` | local UI | Comma-separated extra allowed origins for the web API. |
| `SHIELDSCOPE_PYTHON` | `PATH` | Python used to drive blutter. |
| `SHIELDSCOPE_AI_PROVIDER` / `_BASE_URL` / `_MODEL` / `_API_KEY` | off | Optional AI layer (see below). |

---

## JSON output schema

`--json` / the `/api/analyze` response is a single object. Top-level keys:

| Key | Contents |
|---|---|
| `ok` | `true` on success. |
| `platform` | `android` / `ios`. |
| `file` | `{name, size, sha256, type}`. |
| `meta` | package/bundle id, version, SDK, permissions, debuggable, etc. |
| `score`, `rating` | Protection score (0–100) and label. |
| `summary` | Short human-readable lines. |
| `root`, `ssl` | `{implemented, layers, mechanisms[]}` — each mechanism has id/name/layer/confidence/guides. |
| `extra` | The flat list of **findings** (see [Anatomy of a finding](#anatomy-of-a-finding)). |
| `secret_validation` | Present with `--validate-secrets`: `{live, invalid, unknown, probes}`. |
| `api` | Harvested endpoints + per-endpoint playbooks + counts. |
| `ipc` | Exported components with `adb` PoCs. |
| `surface` | URLs / buckets / IPs. |
| `signing` | Certificate/scheme details. |
| `frameworks` | Detected app frameworks + notes (Flutter / React Native / Xamarin / Unity / Cordova / Capacitor / Ionic). |
| `language` | Primary source language / build: a cross-platform framework's language (Dart / C# / JS) or, for a native app, **Kotlin / Java / mixed** with the `kotlin_pct` ratio over the app's own classes. |
| `obfuscation` | Level + ratio. |
| `guides` | Full bypass guides referenced by the findings. |
| `frida` | Generated bypass script + the `frida` command. |
| `unpack`, `stats` | Which engines ran and coverage counters. |
| `tool_status` | Tool-readiness report: `{level, headline, detail, tools[], missing_required, missing_recommended}` — whether all tools are present and the output will be accurate, with install steps. Also at CLI `--check-tools` and web `GET /api/tools`. |

---

## Optional AI layer

Entirely **additive and off by default** — ShieldScope is fully deterministic
without it. Point it at **your own** model (local Ollama / LM Studio, or cloud
Anthropic / OpenAI / any OpenAI-compatible endpoint) via the GUI's "AI assist"
panel or the `SHIELDSCOPE_AI_*` env vars. It can turn findings into a prioritised
attack plan, explain a finding, or chat about the app. Nothing is sent to a model
unless you configure it and click the AI buttons.

---

## Tests

```bash
pytest -m "not integration"   # fast unit tests (no APK / external tools needed)
pytest -m integration         # full engine on sample APKs (slow; needs jadx/apktool + APKs)
```

Point the integration tests at your own APKs with `SHIELDSCOPE_TEST_APKS=/path/to/dir`.

---

## Limitations

Static analysis infers from bytes/strings: it can **miss** heavily obfuscated,
packed (unless runtime-dumped), or server-side checks, and can occasionally
**over-report** code in a shared library. **Confirm dynamically** (Frida/objection)
before drawing firm conclusions. App Store IPAs are usually FairPlay-encrypted —
decrypt first (e.g. frida-ios-dump) for full symbol coverage.

---

## Project layout

```
shieldscope/
  app.py                  Flask app (upload + /api/analyze + optional AI endpoints)
  cli.py                  CLI entry point (same engine, no server)
  analyzer/
    report.py             entry point: type detection, scoring, MASVS mapping, caching
    apk_deep.py           Android deep-analysis orchestrator
    unpack.py  tools.py   decompile pipeline + external-tool layer (bounded, killable)
    detect.py             root/SSL/behavioural detection (obfuscation-resilient)
    deepscan.py  secret_rules.py   exhaustive secret hunt + rules/entropy
    manifest_checks.py  masvs.py  signing.py  surface.py  storage.py  apiscan.py
    ipa.py                iOS analyzer
    manifest_fallback.py  apktool-manifest fallback when androguard can't parse
    validate.py           opt-in secret liveness validation
    frida_gen.py  guides.py   Frida script generator + bypass playbooks
  ai/                     optional bring-your-own-model layer
  templates/  static/     web UI (index.html, app.js, checklist.js, style.css)
```

---

*ShieldScope — for authorized security testing only.*

"""
Insecure data-storage static checks (Part A).

Two kinds of signal, both fully offline:

1. Code indicators — Android framework method / class names are stored as strings
   in the dex string pool, so we can detect *which storage APIs the app uses*
   (SharedPreferences, SQLite/Room, external storage, WebView bridges, clipboard)
   and whether the protective ones (EncryptedSharedPreferences, SQLCipher) are
   present. These are ATTACK-SURFACE indicators to review, not proof of a bug —
   the prose says so.

2. Bundled databases — some apps ship a seed .db/.sqlite in assets/ or res/raw.
   Those we open offline with the stdlib sqlite3 and scan table contents for
   secrets / PII (and note if the file is opaque ⇒ likely encrypted, which is good).
"""

import os
import re
import sqlite3
import tempfile

# tokens we look for in dex bytes (method / class names live in the string pool)
IND = {
    "prefs":        [b"getSharedPreferences"],
    "enc_prefs":    [b"EncryptedSharedPreferences", b"androidx/security/crypto"],
    "sqlite":       [b"SQLiteDatabase", b"openOrCreateDatabase", b"androidx/room"],
    "sqlcipher":    [b"net/sqlcipher", b"SQLiteDatabaseHook"],
    "external":     [b"getExternalStorageDirectory", b"getExternalFilesDir",
                     b"getExternalCacheDir", b"getExternalStoragePublicDirectory"],
    "js_bridge":    [b"addJavascriptInterface"],
    "webview_dbg":  [b"setWebContentsDebuggingEnabled"],
    "webview_file": [b"setAllowUniversalAccessFromFileURLs", b"setAllowFileAccessFromFileURLs"],
    "webview_pw":   [b"setSavePassword"],
    "clipboard":    [b"setPrimaryClip"],
}
_ALL_TOKENS = [(k, t) for k, toks in IND.items() for t in toks]


def scan(data, location, presence):
    """Record first location where each storage token appears (mutates `presence`)."""
    for key, tok in _ALL_TOKENS:
        if key not in presence and tok in data:
            presence[key] = location


def _f(fid, title, sev, location, desc, risk, repro, mit, evidence=""):
    return {"id": fid, "title": title, "severity": sev, "category": "storage",
            "location": location, "evidence": evidence, "description": desc,
            "risk": risk, "reproduce": repro, "mitigation": mit}


def build_code_findings(presence):
    F = []
    def loc(key):
        return "app bytecode (%s)" % presence.get(key, "dex") if key in presence else None

    if "prefs" in presence and "enc_prefs" not in presence:
        F.append(_f("storage-prefs-plaintext", "SharedPreferences without encryption", "medium",
            loc("prefs"),
            "The app uses SharedPreferences but androidx.security EncryptedSharedPreferences "
            "was not detected, so preference values are likely stored as cleartext XML in the "
            "app's data dir.",
            "Anything written there (tokens, session ids, flags, PII) is readable from "
            "`/data/data/<pkg>/shared_prefs/*.xml` via adb backup, run-as on a debuggable build, "
            "or on a rooted/compromised device.",
            ["Pull the data: `adb backup -noapk <pkg>` (or `run-as <pkg>`), unpack it.",
             "Read `shared_prefs/*.xml` and look for cleartext secrets.",
             "(Use ShieldScope's *extracted-data* mode on the pulled folder to automate this.)"],
            "Store secrets with EncryptedSharedPreferences (androidx.security.crypto) backed by "
            "the Android Keystore; never keep long-lived tokens in plain prefs."))

    if ("sqlite" in presence) and "sqlcipher" not in presence:
        F.append(_f("storage-sqlite-plain", "SQLite/Room database without SQLCipher", "low",
            loc("sqlite"),
            "The app uses a local SQLite/Room database and no SQLCipher was detected — the DB "
            "file is likely unencrypted on disk.",
            "Cached records (messages, PII, tokens) can be read straight from the `.db` file "
            "off-device (adb backup / run-as / rooted pull).",
            ["Pull `/data/data/<pkg>/databases/*.db`.",
             "Open with `sqlite3 file.db` and dump tables (ShieldScope extracted-data mode does this)."],
            "Encrypt at-rest with SQLCipher (or store only non-sensitive data locally); "
            "rely on the Keystore for the DB key."))

    if "external" in presence:
        F.append(_f("storage-external", "Writes to external/shared storage", "low",
            loc("external"),
            "The app uses external-storage APIs. Files on legacy external storage are world-"
            "readable and survive uninstall.",
            "Any other app (or a user with file access) can read sensitive files the app writes "
            "there; pre-scoped-storage this is a common data-leak vector.",
            ["Trigger the feature and inspect `/sdcard/Android/data/<pkg>/` and public dirs for sensitive files."],
            "Keep sensitive data in internal storage; if external is required use app-scoped "
            "storage and encrypt the contents."))

    if "js_bridge" in presence:
        F.append(_f("webview-js-bridge", "WebView JavaScript bridge (addJavascriptInterface)", "medium",
            loc("js_bridge"),
            "The app exposes native methods to WebView JavaScript via addJavascriptInterface.",
            "If the WebView loads any untrusted/remote content (or is MITM'd over HTTP), the page "
            "can call the bridged native methods — a common path to RCE / data theft, especially "
            "on API < 17 or with broad @JavascriptInterface surfaces.",
            ["Identify the bridged object and its @JavascriptInterface methods.",
             "Load attacker-controlled content in the WebView and invoke the bridge from JS."],
            "Only bridge to trusted, local content over HTTPS; minimise exposed methods; validate "
            "all inputs; set targetSdk ≥ 17 and review each @JavascriptInterface."))

    if "webview_file" in presence:
        F.append(_f("webview-file-access", "WebView universal/file access enabled", "medium",
            loc("webview_file"),
            "setAllowUniversalAccessFromFileURLs / setAllowFileAccessFromFileURLs is used.",
            "A file:// page (or injected content) can read arbitrary local files and cross-origin "
            "resources, enabling local-file exfiltration.",
            ["Load a crafted file:// page that XHRs local files / other origins and observe access."],
            "Disable these settings; never enable universal access from file URLs; serve content "
            "from https:// instead of file://."))

    if "webview_dbg" in presence:
        F.append(_f("webview-debug", "WebView remote debugging enabled", "low",
            loc("webview_dbg"),
            "setWebContentsDebuggingEnabled(true) is present.",
            "On a debuggable/attacker-accessible device, the WebView can be inspected via "
            "chrome://inspect, exposing the DOM, JS state and any in-page secrets.",
            ["Connect the device and open chrome://inspect to attach to the WebView."],
            "Gate it behind BuildConfig.DEBUG so it is never enabled in release builds."))

    if "webview_pw" in presence:
        F.append(_f("webview-savepassword", "WebView setSavePassword used", "low",
            loc("webview_pw"),
            "The deprecated WebSettings.setSavePassword API is referenced.",
            "Legacy password saving can persist credentials insecurely in the WebView store.",
            ["Inspect the WebView data dir for saved credentials."],
            "Remove setSavePassword; handle credentials via a secure, app-managed flow."))

    if "clipboard" in presence:
        F.append(_f("clipboard-write", "Writes to the system clipboard", "info",
            loc("clipboard"),
            "The app writes to the global clipboard (ClipboardManager.setPrimaryClip).",
            "If it copies sensitive data (passwords, OTPs, tokens), any app can read the clipboard "
            "in the background.",
            ["Copy the sensitive value in-app, then read the clipboard from another app."],
            "Avoid putting secrets on the clipboard; if unavoidable, flag the clip as sensitive "
            "(EXTRA_IS_SENSITIVE) and clear it quickly."))
    return F


# ---------------------------------------------------------------------------
#  iOS storage indicators (scanned over the Mach-O / frameworks)
# ---------------------------------------------------------------------------
IOS_IND = {
    "userdefaults": [b"NSUserDefaults"],
    "pasteboard":   [b"UIPasteboard", b"generalPasteboard"],
    "uiwebview":    [b"UIWebView"],
    "wk_js":        [b"javaScriptEnabled", b"WKUserContentController"],
    "keychain_ok":  [b"kSecClass", b"SecItemAdd"],
}
_IOS_TOKENS = [(k, t) for k, toks in IOS_IND.items() for t in toks]


def ios_scan(data, location, presence):
    for key, tok in _IOS_TOKENS:
        if key not in presence and tok in data:
            presence[key] = location


def build_ios_code_findings(presence):
    F = []
    def loc(k):
        return "app binary (%s)" % presence.get(k) if k in presence else None
    if "userdefaults" in presence and "keychain_ok" not in presence:
        F.append(_f("ios-userdefaults", "NSUserDefaults used without Keychain", "low",
            loc("userdefaults"),
            "The app uses NSUserDefaults but no Keychain (kSecClass/SecItemAdd) usage was detected.",
            "NSUserDefaults is a plist in the app container, not encrypted at rest; secrets stored "
            "there are readable from a device backup or a jailbroken device.",
            ["Pull the app container and read Library/Preferences/<bundle>.plist."],
            "Store secrets in the iOS Keychain (kSecAttrAccessibleWhenUnlockedThisDeviceOnly), "
            "not NSUserDefaults."))
    if "pasteboard" in presence:
        F.append(_f("ios-pasteboard", "Writes to the general UIPasteboard", "info",
            loc("pasteboard"),
            "The app uses the general (system-wide) UIPasteboard.",
            "Any app can read the general pasteboard; copying secrets/OTPs there leaks them.",
            ["Copy a sensitive value in-app, read the pasteboard from another app."],
            "Use a named, app-scoped pasteboard and mark items with expiry / localOnly."))
    if "uiwebview" in presence:
        F.append(_f("ios-uiwebview", "Deprecated UIWebView in use", "low",
            loc("uiwebview"),
            "The app references the deprecated, insecure UIWebView.",
            "UIWebView lacks modern isolation and is rejected by Apple; it is more exposed to "
            "injection and mixed-content issues.",
            ["Locate UIWebView usage in the binary/nib."],
            "Migrate to WKWebView with JS bridges minimised and HTTPS enforced."))
    return F


# ---------------------------------------------------------------------------
#  Bundled databases shipped inside the APK/IPA (assets/, res/raw, .app)
# ---------------------------------------------------------------------------
_SQLITE_MAGIC = b"SQLite format 3\x00"


def parse_bundled_db(name, data, secret_scan, pii_scan):
    """
    Parse one shipped DB file offline. Returns a finding dict or None.
    `secret_scan(bytes, loc)` and `pii_scan(text, loc)` are injected from masvs.
    """
    if not data:
        return None
    if not data.startswith(_SQLITE_MAGIC):
        # not a plain sqlite file — could be Realm / encrypted / SQLCipher
        return {"id": "bundled-db-opaque-" + re.sub(r"\W+", "-", name.lower()),
                "title": "Bundled database (non-plain/encrypted): " + os.path.basename(name),
                "severity": "info", "category": "storage", "location": name,
                "evidence": "header: " + data[:16].hex(),
                "description": "A shipped database file that is not a plain SQLite (possibly Realm "
                               "or SQLCipher-encrypted).",
                "risk": "If it is encrypted, good — verify the key isn't hardcoded. If it is a "
                        "custom store, review it manually for bundled sensitive data.",
                "reproduce": ["Open the file with the matching engine (Realm Studio / SQLCipher with the app key)."],
                "mitigation": "Do not ship real user/PII data inside the app; keep any bundled "
                              "DB free of secrets."}
    # write to temp and open read-only
    tmp = None
    tables, hits = [], []
    try:
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        with open(tmp, "wb") as f:
            f.write(data)
        con = sqlite3.connect("file:%s?mode=ro&immutable=1" % tmp.replace("\\", "/"), uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]
        for t in tables:
            try:
                cur.execute('SELECT * FROM "%s" LIMIT 200' % t)
                rows = cur.fetchall()
            except Exception:
                continue
            for row in rows:
                for cell in row:
                    if not isinstance(cell, (str, bytes)):
                        continue
                    b = cell.encode("utf-8", "replace") if isinstance(cell, str) else cell
                    for h in secret_scan(b, "%s → table %s" % (name, t)):
                        hits.append("secret[%s]: %s" % (h["label"], h["value"][:60]))
                    for p in pii_scan(cell if isinstance(cell, str) else b.decode("utf-8", "replace"),
                                      "%s → table %s" % (name, t)):
                        hits.append("PII[%s]: %s" % (p["kind"], p["value"][:50]))
        con.close()
    except Exception:
        pass
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    sev = "high" if hits else "low"
    dedup = sorted(set(hits))[:12]
    return {"id": "bundled-db-" + re.sub(r"\W+", "-", name.lower()),
            "title": "Bundled SQLite database: " + os.path.basename(name),
            "severity": sev, "category": "storage", "location": name,
            "evidence": ("tables: %s" % ", ".join(tables[:10]))
                        + (("\n" + "\n".join(dedup)) if dedup else ""),
            "description": "A SQLite database is shipped inside the app package (%d table%s)."
                           % (len(tables), "s" if len(tables) != 1 else ""),
            "risk": ("Sensitive data / PII was found inside the shipped DB — it is extractable by "
                     "anyone who unzips the app." if hits else
                     "Shipped DBs are readable by anyone who unzips the app; verify no secrets/PII "
                     "are baked in."),
            "reproduce": ["`unzip app.apk %s`" % name,
                          "`sqlite3 %s .tables` then `SELECT * FROM <table>;`" % os.path.basename(name)],
            "mitigation": "Ship only non-sensitive seed data; populate user/PII data at runtime into "
                          "encrypted storage."}

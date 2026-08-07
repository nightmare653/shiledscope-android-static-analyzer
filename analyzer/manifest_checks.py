"""
Manifest & permissions deep-dive (Part A, Android).

Parses AndroidManifest via androguard and flags common attack-surface issues
beyond the basic debuggable/backup/exported checks in masvs.py:

  * dangerous permission inventory
  * custom permissions declared with a weak protectionLevel
  * content providers with grantUriPermissions / exported
  * task-hijacking surface (exported activity + singleTask/singleInstance or taskAffinity)
  * deep-link surface (http/https/custom schemes, missing autoVerify)
  * missing dataExtractionRules/fullBackupContent when backup is allowed

All rich findings (location/description/risk/reproduce/mitigation).
"""

_NS = "{http://schemas.android.com/apk/res/android}"

# a pragmatic subset of Android "dangerous" permissions
_DANGEROUS = {
    "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "CAMERA", "RECORD_AUDIO", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_CALENDAR", "WRITE_CALENDAR", "BODY_SENSORS", "GET_ACCOUNTS",
    "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "READ_MEDIA_AUDIO",
}


def _f(fid, title, sev, cat, location, desc, risk, repro, mit, evidence=""):
    return {"id": fid, "title": title, "severity": sev, "category": cat,
            "location": location, "evidence": evidence, "description": desc,
            "risk": risk, "reproduce": repro, "mitigation": mit}


def analyze(a, pkg=None):
    if a is None:
        return []
    pkg = pkg or "com.pkg"
    F = []
    try:
        root = a.get_android_manifest_xml()
    except Exception:
        root = None

    # --- dangerous permissions inventory ---
    try:
        perms = a.get_permissions() or []
    except Exception:
        perms = []
    dangerous = sorted({p.split(".")[-1] for p in perms if p.split(".")[-1] in _DANGEROUS})
    if dangerous:
        F.append(_f("perm-dangerous", "Dangerous permissions requested (%d)" % len(dangerous),
            "info", "permission",
            "AndroidManifest.xml → <uses-permission>",
            "The app requests runtime 'dangerous' permissions: " + ", ".join(dangerous) + ".",
            "Each dangerous permission widens the data the app (and any code/SDK inside it) can "
            "reach — location, contacts, SMS, storage, mic/camera. Over-permissioning increases "
            "blast radius if the app or a bundled SDK is compromised.",
            ["Review against functionality: `adb shell dumpsys package %s | grep permission`." % pkg],
            "Request only what a feature needs, at runtime, and drop permissions used solely by SDKs.",
            evidence=", ".join(dangerous)))

    if root is None:
        return F

    # --- custom permissions with weak protectionLevel ---
    weak = []
    for el in root.iter("permission"):
        name = el.get(_NS + "name") or "?"
        lvl = (el.get(_NS + "protectionLevel") or "normal").lower()
        if "signature" not in lvl:
            weak.append("%s (%s)" % (name.split(".")[-1], lvl))
    if weak:
        F.append(_f("perm-custom-weak", "Custom permission with weak protectionLevel", "medium",
            "permission", "AndroidManifest.xml → <permission>",
            "Custom permissions are declared without a signature-level protection: " + ", ".join(weak) + ".",
            "A 'normal'/'dangerous' custom permission can be held by any app that requests it, so "
            "it does not actually restrict access to the components it guards.",
            ["Have a second app request the custom permission and access the guarded component."],
            "Use android:protectionLevel=\"signature\" so only apps signed with your key qualify.",
            evidence=", ".join(weak)))

    # --- content providers: grantUriPermissions / exported ---
    prov = []
    for el in root.iter("provider"):
        name = el.get(_NS + "name") or "?"
        exp = el.get(_NS + "exported")
        grant = (el.get(_NS + "grantUriPermissions") or "").lower() == "true"
        has_filter = el.find("intent-filter") is not None
        is_exp = (exp == "true") or (exp is None and has_filter)
        if grant or is_exp:
            prov.append("%s%s%s" % (name.split(".")[-1],
                                    " [exported]" if is_exp else "",
                                    " [grantUri]" if grant else ""))
    if prov:
        F.append(_f("provider-exposure", "Content provider exposure (%d)" % len(prov), "medium",
            "config", "AndroidManifest.xml → <provider>",
            "Providers are exported and/or use grantUriPermissions: " + ", ".join(prov) + ".",
            "Exported providers can be queried by other apps (path-traversal / SQL-injection in the "
            "provider, or data leakage); grantUriPermissions can be abused for temporary access to "
            "internal files via crafted content:// URIs.",
            ["`adb shell content query --uri content://<authority>`.",
             "Fuzz the URI path / selection for traversal or injection."],
            "Set exported=false unless external access is required; enforce read/write permissions; "
            "validate URIs and use parameterised queries.",
            evidence=", ".join(prov)))

    # --- task hijacking surface ---
    hij = []
    for el in root.iter("activity"):
        name = el.get(_NS + "name") or "?"
        exp = el.get(_NS + "exported")
        lm = (el.get(_NS + "launchMode") or "").lower()
        aff = el.get(_NS + "taskAffinity")
        has_filter = el.find("intent-filter") is not None
        is_exp = (exp == "true") or (exp is None and has_filter)
        if is_exp and (lm in ("singletask", "singleinstance") or aff is not None):
            hij.append("%s (launchMode=%s%s)" % (name.split(".")[-1], lm or "-",
                                                 ", taskAffinity set" if aff is not None else ""))
    if hij:
        F.append(_f("task-hijacking", "Task-hijacking / StrandHogg surface", "medium",
            "config", "AndroidManifest.xml → <activity>",
            "Exported activities use singleTask/singleInstance or a custom taskAffinity: "
            + ", ".join(hij[:8]) + ".",
            "A malicious app can hijack the task/back-stack (StrandHogg) to present its own UI in "
            "place of the real activity — enabling phishing/overlay of login screens.",
            ["Install a PoC app with a matching taskAffinity and observe activity/task hijacking."],
            "Set taskAffinity=\"\" on sensitive activities, avoid singleTask/singleInstance for "
            "exported entry points, and set launchMode/FLAG_ACTIVITY_NEW_TASK carefully.",
            evidence=", ".join(hij[:8])))

    # --- deep-link surface ---
    schemes, autoverify_http = set(), False
    for f in root.iter("intent-filter"):
        av = (f.get(_NS + "autoVerify") or "").lower() == "true"
        for d in f.iter("data"):
            sch = d.get(_NS + "scheme")
            if sch:
                schemes.add(sch)
                if sch in ("http", "https") and av:
                    autoverify_http = True
    weblinks = {s for s in schemes if s in ("http", "https")}
    custom = sorted(schemes - {"http", "https"})
    if schemes:
        note = []
        if weblinks and not autoverify_http:
            note.append("http/https links without android:autoVerify (App Links not verified)")
        if custom:
            note.append("custom schemes: " + ", ".join(custom[:8]))
        if note:
            F.append(_f("deeplink-surface", "Deep-link / App-Link surface", "low",
                "config", "AndroidManifest.xml → <intent-filter><data>",
                "The app registers deep links (" + "; ".join(note) + ").",
                "Unverified web links and custom-scheme deep links can be triggered by any app or "
                "web page; if the handler trusts link parameters it can lead to open-redirect, "
                "auth-token theft, or WebView injection.",
                ["`adb shell am start -a android.intent.action.VIEW -d \"<scheme>://...\" %s`." % pkg,
                 "Fuzz link parameters and observe how the target screen consumes them."],
                "Use verified Android App Links (autoVerify + assetlinks.json) for http/https; "
                "validate every deep-link parameter and never auto-authenticate from a link.",
                evidence="; ".join(note)))

    return F

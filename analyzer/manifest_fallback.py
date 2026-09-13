"""
Decoded-manifest fallback for when androguard's APK() can't parse an app.

androguard's `APK(path)` occasionally throws on real-world apps (odd resource
tables, exotic signing blocks, huge multidex, version quirks). When it does,
`apk._meta` returns an all-None meta and `a = None` — and EVERY downstream
consumer that keys off the androguard object then silently returns nothing:

  * package / version / SDK / permission count      (header metadata)
  * manifest_checks (perms, providers, deep links, task-hijacking, backup)
  * masvs.android_config (allowBackup, debuggable, cleartext, exported)
  * surface.ipc (exported component inventory + adb PoCs)

So one library hiccup wipes out five categories of findings AND the app
identity in the UI. apktool has usually already decoded a perfectly good
AndroidManifest.xml (+ apktool.yml) to disk by that point, so we parse that and
expose the small slice of the androguard APK API those modules actually call.

Signing is deliberately NOT served here: reading the signer certificate needs
the real APK signature block, which apktool does not give us. Feeding a shim to
signing.analyze would make it report a bogus "unsigned" finding, so callers keep
passing the real (possibly None) androguard object to signing.
"""

import os
import re
import xml.etree.ElementTree as ET

_NS_URI = "http://schemas.android.com/apk/res/android"
_NS = "{%s}" % _NS_URI


class DecodedAPK:
    """Minimal stand-in for androguard's APK, backed by apktool output.

    Implements only the methods the manifest/config/IPC analyzers use. Version
    and SDK numbers come from apktool.yml (apktool strips them out of the decoded
    AndroidManifest.xml); everything else comes from the manifest XML itself.
    """

    def __init__(self, root, yml, raw_dir):
        self._root = root
        self._yml = yml or {}
        self._raw_dir = raw_dir

    # ---- identity / versions ----
    def get_package(self):
        return self._root.get("package")

    def get_androidversion_name(self):
        return self._yml.get("versionName") or self._root.get(_NS + "versionName")

    def get_androidversion_code(self):
        return self._yml.get("versionCode") or self._root.get(_NS + "versionCode")

    def get_min_sdk_version(self):
        if self._yml.get("minSdkVersion"):
            return self._yml["minSdkVersion"]
        el = self._root.find("uses-sdk")
        return el.get(_NS + "minSdkVersion") if el is not None else None

    def get_target_sdk_version(self):
        if self._yml.get("targetSdkVersion"):
            return self._yml["targetSdkVersion"]
        el = self._root.find("uses-sdk")
        return el.get(_NS + "targetSdkVersion") if el is not None else None

    # ---- permissions ----
    def get_permissions(self):
        out = []
        for tag in ("uses-permission", "uses-permission-sdk-23"):
            for el in self._root.iter(tag):
                name = el.get(_NS + "name")
                if name:
                    out.append(name)
        return out

    # ---- manifest access ----
    def get_android_manifest_xml(self):
        return self._root

    def get_element(self, tag, attribute, **_):
        """First `tag` element's android:`attribute`, matched case-insensitively.

        androguard callers pass the attribute with inconsistent casing
        (`allowBackup`, `usescleartexttraffic`, `debuggable`), so we compare the
        android-namespaced local name case-insensitively to match them all.
        """
        want = attribute.lower()
        for el in self._root.iter(tag):
            for key, val in el.attrib.items():
                if key.startswith(_NS) and key[len(_NS):].lower() == want:
                    return val
        return None

    # ---- raw file access (read from the unzipped tree) ----
    def get_file(self, name):
        p = os.path.join(self._raw_dir, name.replace("/", os.sep))
        try:
            with open(p, "rb") as f:
                return f.read()
        except OSError:
            raise FileNotFoundError(name)

    # ---- signing: not available from apktool; be explicit ----
    def get_certificates(self):
        return []

    def is_signed_v1(self):
        return False

    def is_signed_v2(self):
        return False

    def is_signed_v3(self):
        return False


def _parse_apktool_yml(apktool_dir):
    """Pull versionName/versionCode/min/targetSdkVersion out of apktool.yml.

    apktool.yml is YAML but we avoid a YAML dependency and just grab the handful
    of scalar fields we need with a line scan (they live under `versionInfo:` and
    `sdkInfo:` as `  key: value`)."""
    path = os.path.join(apktool_dir, "apktool.yml")
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return out
    for key in ("versionCode", "versionName", "minSdkVersion",
                "targetSdkVersion"):
        m = re.search(r"^\s*%s:\s*(.+?)\s*$" % key, text, re.M)
        if m:
            val = m.group(1).strip().strip("'\"")
            if val and val.lower() != "null":
                out[key] = val
    return out


def build(unpacked):
    """Build a DecodedAPK from apktool output, or None if there's no manifest."""
    man = getattr(unpacked, "manifest_path", None)
    if not man or not os.path.isfile(man):
        return None
    try:
        root = ET.parse(man).getroot()
    except Exception:
        return None
    yml = _parse_apktool_yml(getattr(unpacked, "apktool_dir", "") or "")
    return DecodedAPK(root, yml, getattr(unpacked, "raw_dir", "") or "")


def backfill_meta(meta, shim):
    """Fill in an all-None meta dict from the decoded-manifest shim."""
    meta = meta or {}
    try:
        meta["package"] = meta.get("package") or shim.get_package()
        meta["version_name"] = meta.get("version_name") or shim.get_androidversion_name()
        meta["version_code"] = meta.get("version_code") or shim.get_androidversion_code()
        meta["min_sdk"] = meta.get("min_sdk") or shim.get_min_sdk_version()
        meta["target_sdk"] = meta.get("target_sdk") or shim.get_target_sdk_version()
        if not meta.get("permissions_count"):
            meta["permissions_count"] = len(shim.get_permissions() or [])
        dbg = shim.get_element("application", "debuggable")
        if meta.get("debuggable") is None and dbg is not None:
            meta["debuggable"] = (str(dbg).lower() == "true")
        meta["nsc_referenced"] = bool(
            shim.get_element("application", "networkSecurityConfig"))
    except Exception:
        pass
    meta["source"] = "apktool-manifest (androguard parse failed)"
    return meta

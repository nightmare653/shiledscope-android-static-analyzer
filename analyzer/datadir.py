"""
Extracted-data analyzer (Part B) — FULLY OFFLINE.

You pull an app's runtime data yourself (`adb backup -noapk <pkg>`, `run-as` on a
debuggable build, or a rooted copy of /data/data/<pkg>/) and hand ShieldScope the
result. It never touches the network.

Accepted inputs (single upload):
  * <name>.ab            Android backup (unencrypted) — auto-converted to tar
  * <name>.tar / .tar.gz a tar of the data dir
  * <name>.zip           a zip of the data dir
  * a single .db/.sqlite or shared_prefs .xml

It scans, offline:
  * shared_prefs/*.xml   -> keys/values that look sensitive (tokens, passwords, PII)
  * *.db / *.sqlite*     -> opens read-only with sqlite3, dumps tables, flags secrets/PII
  * other text/cache     -> secret + PII regexes
"""

import io
import os
import re
import tarfile
import zipfile
import xml.etree.ElementTree as ET

from . import masvs
from . import storage

_SQLITE_MAGIC = b"SQLite format 3\x00"
_TEXT_EXT = (".xml", ".json", ".txt", ".js", ".plist", ".properties", ".log", ".csv")
_DB_EXT = (".db", ".sqlite", ".sqlite3", ".db3")
_SENSITIVE_KEY = re.compile(r"(?i)(token|secret|passwd|password|auth|session|jwt|refresh|"
                            r"access|api[_-]?key|pin\b|card|cvv|ssn|private|credential|cookie)")


# ---------------------------------------------------------------------------
#  extraction — yields (relpath, bytes), one entry at a time (bounded memory)
# ---------------------------------------------------------------------------
def _read_ab(data):
    if not data.startswith(b"ANDROID BACKUP"):
        raise ValueError("not an .ab file")
    parts = data.split(b"\n", 4)
    if len(parts) < 5:
        raise ValueError("truncated .ab header")
    compressed, enc, payload = parts[2].strip(), parts[3].strip(), parts[4]
    if enc and enc != b"none":
        raise ValueError("encrypted backup (%s) — decrypt with android-backup-extractor "
                         "(abe.jar) first, then upload the tar." % enc.decode("ascii", "replace"))
    if compressed == b"1":
        import zlib
        return zlib.decompress(payload)
    return payload


def _iter_entries(path):
    with open(path, "rb") as f:
        head = f.read(64)

    # .ab android backup
    if head.startswith(b"ANDROID BACKUP"):
        with open(path, "rb") as f:
            tar_bytes = _read_ab(f.read())
        with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
            for m in tf.getmembers():
                if m.isfile() and m.size <= 64 * 1024 * 1024:
                    try:
                        yield m.name, tf.extractfile(m).read()
                    except Exception:
                        continue
        return

    # tar / tar.gz
    if tarfile.is_tarfile(path):
        with tarfile.open(path) as tf:
            for m in tf.getmembers():
                if m.isfile() and m.size <= 64 * 1024 * 1024:
                    try:
                        yield m.name, tf.extractfile(m).read()
                    except Exception:
                        continue
        return

    # zip
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir() and info.file_size <= 64 * 1024 * 1024:
                    try:
                        yield info.filename, z.read(info.filename)
                    except Exception:
                        continue
        return

    # single file (db or xml)
    with open(path, "rb") as f:
        yield os.path.basename(path), f.read()


# ---------------------------------------------------------------------------
#  shared_prefs scanning
# ---------------------------------------------------------------------------
def _scan_prefs(name, data):
    try:
        root = ET.fromstring(data)
    except Exception:
        return None
    sensitive = []
    for el in root:
        key = el.get("name") or ""
        val = el.text if (el.tag == "string" and el.text) else el.get("value", "")
        val = val or ""
        flagged = bool(_SENSITIVE_KEY.search(key))
        if not flagged and val:
            if masvs.scan_secrets(val.encode("utf-8", "replace"), name) or \
               masvs.scan_pii(val, name):
                flagged = True
        if flagged and val:
            sensitive.append("%s = %s" % (key, val if len(val) <= 120 else val[:117] + "…"))
    if not sensitive:
        return None
    return {"id": "prefs-" + re.sub(r"\W+", "-", name.lower()),
            "title": "Sensitive data in SharedPreferences: " + os.path.basename(name),
            "severity": "high", "category": "storage", "location": name,
            "evidence": "\n".join(sensitive[:20]),
            "description": "A shared-prefs XML in the app's data dir contains keys/values that look "
                           "sensitive and are stored in cleartext.",
            "risk": "These values are readable by anyone who can pull the data dir (adb backup, "
                    "run-as on a debuggable build, or a rooted/compromised device). Long-lived "
                    "tokens here allow account takeover; PII here is a privacy breach.",
            "reproduce": ["`adb backup -noapk <pkg>` (or `run-as <pkg> cat shared_prefs/%s`)."
                          % os.path.basename(name),
                          "Open the XML and read the values shown above."],
            "mitigation": "Store secrets with EncryptedSharedPreferences (Keystore-backed); keep "
                          "only short-lived tokens on device; never persist passwords/PANs."}


# ---------------------------------------------------------------------------
#  entry point
# ---------------------------------------------------------------------------
def analyze_data(path, original_name=None):
    findings = []
    counts = {"prefs": 0, "databases": 0, "other_files": 0, "total_files": 0}
    other_secret_raw, other_pii = [], []

    try:
        entries = list(_iter_entries(path))
    except ValueError as e:
        return {"ok": False, "kind": "datadir", "error": str(e)}
    except Exception as e:
        return {"ok": False, "kind": "datadir", "error": "Could not read archive: %s" % e}

    if not entries:
        return {"ok": False, "kind": "datadir",
                "error": "No files found. Provide a .ab backup, or a .tar/.zip of the data dir."}

    for name, data in entries:
        counts["total_files"] += 1
        low = name.lower()
        base = os.path.basename(low)

        is_db = low.endswith(_DB_EXT) or data[:16] == _SQLITE_MAGIC
        is_prefs = ("shared_prefs/" in low) or (low.endswith(".xml") and b"<map" in data[:200])

        if is_db:
            counts["databases"] += 1
            f = storage.parse_bundled_db(name, data, masvs.scan_secrets, masvs.scan_pii)
            if f:
                # re-title for the data-dir context
                f["title"] = f["title"].replace("Bundled SQLite database", "Database") \
                                       .replace("Bundled database", "Database")
                findings.append(f)
        elif is_prefs:
            counts["prefs"] += 1
            f = _scan_prefs(name, data)
            if f:
                findings.append(f)
        elif low.endswith(_TEXT_EXT):
            counts["other_files"] += 1
            other_secret_raw += masvs.scan_secrets(data, name)
            try:
                other_pii += masvs.scan_pii(data.decode("utf-8", "replace"), name)
            except Exception:
                pass

    findings += masvs.build_secret_findings(other_secret_raw)
    if other_pii:
        grouped = {}
        for p in other_pii:
            grouped.setdefault(p["kind"], []).append(p)
        for kind, items in grouped.items():
            locs = sorted({i["location"] for i in items})
            vals = sorted({i["value"] for i in items})[:15]
            findings.append({
                "id": "pii-" + re.sub(r"\W+", "-", kind.lower()),
                "title": "PII found: %s (%d)" % (kind, len(vals)),
                "severity": "medium", "category": "pii",
                "location": locs[0] + (" (+%d more)" % (len(locs) - 1) if len(locs) > 1 else ""),
                "evidence": "\n".join(vals),
                "description": "Personal data (%s) was found in the extracted app data." % kind,
                "risk": "PII stored/cached in cleartext is a privacy exposure and can aid account "
                        "takeover or fraud if the device or a backup is accessed.",
                "reproduce": ["Open the referenced file and read the values shown."],
                "mitigation": "Minimise on-device PII; encrypt at rest; purge caches on logout.",
            })

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))
    return {
        "ok": True, "kind": "datadir",
        "source": {"name": original_name or os.path.basename(path)},
        "counts": counts,
        "findings": findings,
        "summary": ["%d file(s) scanned" % counts["total_files"],
                    "%d prefs, %d databases" % (counts["prefs"], counts["databases"]),
                    "%d finding(s)" % len(findings)],
    }

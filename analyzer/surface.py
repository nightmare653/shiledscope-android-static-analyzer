"""
Attack-surface extraction (#3).

1. URL / endpoint / IP / cloud-bucket harvesting from dex + resources (offline).
   Gives the tester the network surface to probe. Called during the single pass.

2. IPC surface enumeration from the manifest: every exported component with a
   ready-to-run adb PoC command — turning findings into testable actions.
"""

import re

_URL_RE = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+")
_WS_RE = re.compile(rb"wss?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]+")
_IP_RE = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_S3_RE = re.compile(rb"[A-Za-z0-9.\-]+\.s3[.\-][A-Za-z0-9.\-]*amazonaws\.com|s3://[A-Za-z0-9.\-/]+")
_GS_RE = re.compile(rb"gs://[A-Za-z0-9.\-_/]+|[a-z0-9.\-]+\.appspot\.com|[a-z0-9.\-]+\.firebaseio\.com")

# hosts that are almost always schema/boilerplate noise, not real endpoints
_NOISE = ("schemas.android.com", "www.w3.org", "xmlpull.org", "apache.org",
          "java.sun.com", "www.google.com/dfl", "goo.gl/", "ns.adobe.com",
          "specs.openid.net", "purl.org", "iptc.org", "whatwg.org", "example.com")

_MAX = 400


def scan(data, out):
    """Accumulate surface items into `out` (dict of sets). Call per file."""
    for rx, key in ((_URL_RE, "urls"), (_WS_RE, "urls"), (_S3_RE, "buckets"), (_GS_RE, "buckets")):
        for m in rx.finditer(data):
            if len(out.setdefault(key, set())) >= _MAX:
                break
            v = m.group(0).decode("utf-8", "replace").rstrip('".,)\\')
            if any(n in v for n in _NOISE):
                continue
            out[key].add(v[:200])
    ips = out.setdefault("ips", set())
    if len(ips) < _MAX:
        for m in _IP_RE.finditer(data):
            v = m.group(0).decode("ascii", "replace")
            if v.startswith(("0.", "127.", "255.")) or v in ("1.1.1.1",) or v.endswith(".0"):
                continue
            ips.add(v)
            if len(ips) >= _MAX:
                break


def finalize(out):
    """Turn the sets into sorted, deduped lists for the report."""
    def clean(key):
        return sorted(out.get(key, set()))
    urls = clean("urls")
    # split obvious API-ish hosts to the top
    return {"urls": urls[:_MAX], "buckets": clean("buckets")[:100],
            "ips": clean("ips")[:150],
            "counts": {"urls": len(out.get("urls", set())),
                       "buckets": len(out.get("buckets", set())),
                       "ips": len(out.get("ips", set()))}}


# ---------------------------------------------------------------------------
#  IPC surface + adb PoC
# ---------------------------------------------------------------------------
_NS = "{http://schemas.android.com/apk/res/android}"


def _filters(el):
    out = []
    for f in el.iter("intent-filter"):
        actions = [a.get(_NS + "name", "") for a in f.iter("action")]
        cats = [c.get(_NS + "name", "") for c in f.iter("category")]
        schemes = sorted({d.get(_NS + "scheme") for d in f.iter("data")
                          if d.get(_NS + "scheme") and not d.get(_NS + "scheme").startswith("@")})
        out.append({"actions": [a.split(".")[-1] for a in actions if a],
                    "categories": [c.split(".")[-1] for c in cats if c],
                    "schemes": schemes})
    return out


def ipc(a, pkg=None):
    """Return exported components with a ready adb PoC each."""
    if a is None:
        return []
    pkg = pkg or "com.pkg"
    try:
        root = a.get_android_manifest_xml()
    except Exception:
        return []

    rows = []
    tag_kind = {"activity": "activity", "activity-alias": "activity",
                "service": "service", "receiver": "receiver", "provider": "provider"}
    for tag, kind in tag_kind.items():
        for el in root.iter(tag):
            name = el.get(_NS + "name") or "?"
            exp = el.get(_NS + "exported")
            perm = el.get(_NS + "permission")
            filters = _filters(el)
            is_exp = (exp == "true") or (exp is None and filters and kind != "provider") \
                     or (exp is None and kind == "provider" and el.get(_NS + "authorities"))
            if not is_exp:
                continue
            fqn = name if name.startswith(".") is False and "." in name else (pkg + name if name.startswith(".") else pkg + "." + name)
            comp = "%s/%s" % (pkg, name)

            if kind == "activity":
                poc = "adb shell am start -n %s" % comp
                act = next((a2 for fl in filters for a2 in fl["actions"]), None)
                sch = next((s for fl in filters for s in fl["schemes"]), None)
                if sch:
                    poc = "adb shell am start -a android.intent.action.VIEW -d \"%s://HOST/PATH\" %s" % (sch, pkg)
            elif kind == "service":
                poc = "adb shell am start-foreground-service -n %s   # or startservice" % comp
            elif kind == "receiver":
                act = next((fl_a for fl in filters for fl_a in fl["actions"]), None)
                poc = "adb shell am broadcast -n %s" % comp
            else:  # provider
                auth = el.get(_NS + "authorities") or "<authority>"
                poc = "adb shell content query --uri content://%s" % auth.split(";")[0]

            rows.append({
                "type": kind, "name": name.split(".")[-1], "fqn": name,
                "exported": True, "permission": perm,
                "filters": filters, "poc": poc,
                "protected": bool(perm),
            })
    # unprotected first, providers/receivers surfaced
    rows.sort(key=lambda r: (r["protected"], r["type"]))
    return rows

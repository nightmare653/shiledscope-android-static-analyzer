"""
Unpack pipeline — the foundation of the deep engine.

Given an APK it produces, in a scratch workdir:

  raw/        the APK fully unzipped, PLUS every nested archive
              (.jar/.zip/.apk/.aar/.xapk/.tar...) recursively extracted, so a
              secret hidden inside a bundled jar/zip is on disk as a real file.
  apktool/    apktool output: decoded AndroidManifest.xml, res/values/*.xml
              (real string resources), and smali/ (obfuscation-resilient
              disassembly — you match API *calls*, not renamed class names).
  jadx/       jadx Java output: constant strings are reconstructed, so secrets
              that are base64/hex/split in the dex become greppable text.

Design goals tied to the reported failures:
  * Never hang: apktool and jadx each run under a hard timeout (tools.run kills
    the process tree). If one fails, the pipeline degrades instead of dying —
    jadx fails -> use smali; apktool fails -> use jadx; both fail -> raw bytes.
  * Go deep: nested archives are expanded and every file ends up in the tree
    that the scanners walk exhaustively (no extension allowlist).

Returns an `Unpacked` describing every artefact + a stage log for the report.
"""

import os
import zipfile
import tarfile

from . import tools as T

_NESTED_EXT = (".jar", ".zip", ".apk", ".aar", ".xapk", ".apks", ".war", ".ear")
_TAR_EXT = (".tar", ".tar.gz", ".tgz")

# zip-bomb / runaway guards
_MAX_TOTAL_BYTES = 3 * 1024 * 1024 * 1024   # 3 GB extracted ceiling
_MAX_FILES = 300_000
_MAX_DEPTH = 3


class Unpacked:
    def __init__(self, workdir):
        self.workdir = workdir
        self.raw_dir = os.path.join(workdir, "raw")
        self.apktool_dir = os.path.join(workdir, "apktool")
        self.jadx_dir = os.path.join(workdir, "jadx")
        self.manifest_path = None       # decoded AndroidManifest.xml (apktool)
        self.res_dir = None             # apktool res/
        self.smali_dirs = []            # apktool smali*/ dirs
        self.java_dir = None            # jadx sources root
        self.nested = []                # relpaths of nested archives expanded
        self.stages = []                # human-readable stage log
        self.tool_log = []              # structured tool invocations
        self.truncated = False          # hit a guard ceiling

    # ---- file enumeration for the scanners ----
    def iter_files(self):
        """Yield (abs_path, rel_path, source) for everything worth scanning."""
        seen = set()

        def walk(base, source):
            if not base or not os.path.isdir(base):
                return
            for dirpath, _dirs, files in os.walk(base):
                for fn in files:
                    ap = os.path.join(dirpath, fn)
                    if ap in seen:
                        continue
                    seen.add(ap)
                    rel = os.path.relpath(ap, base).replace("\\", "/")
                    yield ap, rel, source

        # raw first (original packaged files + nested archive contents)
        for x in walk(self.raw_dir, "package"):
            yield x
        # decoded resources / smali (only the textual, high-signal parts)
        if self.res_dir:
            for x in walk(self.res_dir, "resource"):
                yield x
        for sd in self.smali_dirs:
            for x in walk(sd, "smali"):
                yield x
        # jadx java (reconstructed constants)
        if self.java_dir:
            for x in walk(self.java_dir, "java"):
                yield x

    def summary(self):
        return {
            "have_java": bool(self.java_dir),
            "have_smali": bool(self.smali_dirs),
            "have_res": bool(self.res_dir),
            "nested_archives": len(self.nested),
            "truncated": self.truncated,
            "stages": self.stages,
            "tool_log": self.tool_log,
        }


# ---------------------------------------------------------------------------
#  safe recursive extraction
# ---------------------------------------------------------------------------
def _safe_join(base, name):
    """Reject path traversal; return abs dest or None."""
    dest = os.path.normpath(os.path.join(base, name))
    if not dest.startswith(os.path.normpath(base) + os.sep) and dest != os.path.normpath(base):
        return None
    return dest


class _Budget:
    def __init__(self):
        self.bytes = 0
        self.files = 0

    def allow(self, size):
        if self.files >= _MAX_FILES or self.bytes + size > _MAX_TOTAL_BYTES:
            return False
        self.files += 1
        self.bytes += max(size, 0)
        return True


def _extract_zip(path, dest, budget):
    os.makedirs(dest, exist_ok=True)
    try:
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                out = _safe_join(dest, info.filename)
                if not out:
                    continue
                if not budget.allow(info.file_size):
                    return True  # truncated
                os.makedirs(os.path.dirname(out), exist_ok=True)
                try:
                    with z.open(info) as src, open(out, "wb") as dst:
                        # bounded copy
                        remaining = _MAX_TOTAL_BYTES - budget.bytes + info.file_size
                        chunk = src.read(min(info.file_size or (8 << 20), 64 << 20))
                        dst.write(chunk)
                except Exception:
                    continue
    except (zipfile.BadZipFile, OSError):
        return False
    return False


def _extract_tar(path, dest, budget):
    os.makedirs(dest, exist_ok=True)
    try:
        with tarfile.open(path) as tf:
            for m in tf.getmembers():
                if not m.isfile():
                    continue
                out = _safe_join(dest, m.name)
                if not out:
                    continue
                if not budget.allow(m.size):
                    return True
                os.makedirs(os.path.dirname(out), exist_ok=True)
                try:
                    with tf.extractfile(m) as src, open(out, "wb") as dst:
                        dst.write(src.read(64 << 20))
                except Exception:
                    continue
    except (tarfile.TarError, OSError):
        return False
    return False


def _expand_nested(root, budget, unpacked, depth=1):
    """Find archives inside `root` and extract each next to itself; recurse."""
    if depth > _MAX_DEPTH:
        return
    found = []
    for dirpath, _dirs, files in os.walk(root):
        # don't descend into dirs we already created for extraction
        if dirpath.endswith("__extracted"):
            continue
        for fn in files:
            low = fn.lower()
            ap = os.path.join(dirpath, fn)
            if low.endswith(_NESTED_EXT) or low.endswith(_TAR_EXT):
                found.append(ap)
    for ap in found:
        dest = ap + "__extracted"
        if os.path.isdir(dest):
            continue
        low = ap.lower()
        trunc = (_extract_tar(ap, dest, budget) if low.endswith(_TAR_EXT)
                 else _extract_zip(ap, dest, budget))
        if os.path.isdir(dest):
            unpacked.nested.append(os.path.relpath(ap, unpacked.raw_dir).replace("\\", "/"))
            if trunc:
                unpacked.truncated = True
            _expand_nested(dest, budget, unpacked, depth + 1)
        if budget.files >= _MAX_FILES:
            unpacked.truncated = True
            return


# ---------------------------------------------------------------------------
#  entry point
# ---------------------------------------------------------------------------
def unpack(apk_path, workdir, jadx_timeout=600, apktool_timeout=300):
    """
    Run the full pipeline. Returns an Unpacked. Individual stages may be skipped
    (missing tool) or degraded (timeout) — always check `.summary()`.
    """
    up = Unpacked(workdir)
    os.makedirs(up.raw_dir, exist_ok=True)
    tools = T.get_tools()

    # 1) raw unzip + nested expansion (pure Python, always runs)
    budget = _Budget()
    trunc = _extract_zip(apk_path, up.raw_dir, budget)
    if trunc:
        up.truncated = True
    _expand_nested(up.raw_dir, budget, up)
    up.stages.append("Unzipped package + %d nested archive(s) (%d files, %s)"
                     % (len(up.nested), budget.files, _fmt(budget.bytes))
                     + (" - truncated at safety ceiling" if up.truncated else ""))

    # 2) apktool: decoded manifest + resources + smali
    if tools.have_apktool:
        r = T.apktool(["d", "-f", "-o", up.apktool_dir, apk_path],
                      timeout=apktool_timeout, log=up.tool_log)
        if r.ok and os.path.isdir(up.apktool_dir):
            man = os.path.join(up.apktool_dir, "AndroidManifest.xml")
            if os.path.isfile(man):
                up.manifest_path = man
            res = os.path.join(up.apktool_dir, "res")
            if os.path.isdir(res):
                up.res_dir = res
            for entry in os.listdir(up.apktool_dir):
                if entry.startswith("smali"):
                    p = os.path.join(up.apktool_dir, entry)
                    if os.path.isdir(p):
                        up.smali_dirs.append(p)
            up.stages.append("apktool: decoded manifest/resources + %d smali tree(s) in %ss"
                             % (len(up.smali_dirs), r.seconds))
        else:
            up.stages.append("apktool: %s - continuing without smali"
                             % ("timed out" if r.timed_out else "failed"))
    else:
        up.stages.append("apktool: not available - skipped")

    # 3) jadx: Java with reconstructed constant strings.
    #    ADAPTIVE: jadx is the slow stage. On a large multidex app it can run
    #    15-20 min and still only produce PARTIAL Java — which is both slower AND
    #    less complete than the smali apktool already gave us (smali carries every
    #    string literal). So we only run jadx when the dex is small enough to
    #    finish quickly; otherwise we skip it and the scanners use smali. jadx's
    #    sole edge is reconstructing concatenated/encoded strings, worth it on
    #    small apps, not worth a 15-min wait on big ones.
    #    Override: SHIELDSCOPE_FORCE_JADX=1 always runs it; =0 never does.
    dex_mb = _dex_megabytes(up.raw_dir)
    force = os.environ.get("SHIELDSCOPE_FORCE_JADX")
    max_dex = float(os.environ.get("SHIELDSCOPE_JADX_MAXDEX_MB", "45"))
    run_jadx = tools.have_jadx and (force == "1" or (force != "0" and dex_mb <= max_dex))

    if not tools.have_jadx:
        up.stages.append("jadx: not available - using smali for code coverage")
    elif not run_jadx:
        up.stages.append("jadx: skipped (%.0f MB dex > %.0f MB threshold) - using complete "
                         "smali instead (faster and more complete than partial jadx)"
                         % (dex_mb, max_dex))
    else:
        os.makedirs(up.jadx_dir, exist_ok=True)
        r = T.jadx(["-d", up.jadx_dir, "--no-res", "--no-debug-info",
                    "--show-bad-code", "-j", str(_threads()), apk_path],
                   timeout=jadx_timeout, log=up.tool_log)
        src = os.path.join(up.jadx_dir, "sources")
        java_root = src if os.path.isdir(src) else (up.jadx_dir if _has_java(up.jadx_dir) else None)
        if java_root and not r.timed_out:
            up.java_dir = java_root
            up.stages.append("jadx: decompiled Java sources in %ss" % r.seconds)
        elif java_root:
            # timed out with partial output — prefer complete smali, ignore partial java
            up.stages.append("jadx: timed out - discarding partial Java, using complete smali")
        else:
            up.stages.append("jadx: %s - using smali"
                             % ("timed out" if r.timed_out else "failed"))

    return up


def _dex_megabytes(raw_dir):
    total = 0
    try:
        for fn in os.listdir(raw_dir):
            if fn.startswith("classes") and fn.endswith(".dex"):
                try:
                    total += os.path.getsize(os.path.join(raw_dir, fn))
                except OSError:
                    pass
    except OSError:
        pass
    return total / (1024.0 * 1024.0)


def _threads():
    try:
        return max(2, min(8, (os.cpu_count() or 4)))
    except Exception:
        return 4


def _has_java(d):
    for dp, _dn, fs in os.walk(d):
        if any(f.endswith(".java") for f in fs):
            return True
    return False


def _fmt(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f %s" % (n, unit)
        n /= 1024.0

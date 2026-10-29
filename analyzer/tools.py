"""
External-tool layer for ShieldScope's deep engine.

Everything that shells out to a JVM tool (jadx, apktool) goes through here so
that:

  * tools are discovered once (env override -> known install paths -> PATH),
  * every invocation runs the JVM *directly* (never a .bat wrapper) with a bounded
    heap, so a hard timeout can kill the exact process instead of orphaning a
    child, and
  * a run that hangs is *killed* rather than allowed to wedge the whole request
    (this is the fix for "gave it 1 hour, no result").

Nothing here imports androguard. androguard is only used, elsewhere, for cheap
manifest attribute reads — never for the heavy DEX cross-referencing that used
to hang.

Configuration (all optional; auto-detected when unset):
  SHIELDSCOPE_JAVA         path to java(.exe)
  SHIELDSCOPE_JADX_JAR     path to jadx-*-all.jar
  SHIELDSCOPE_APKTOOL_JAR  path to apktool.jar
  SHIELDSCOPE_DEX2JAR      path to the dex-tools dir (has lib/) or a d2j wrapper
  SHIELDSCOPE_CFR_JAR      path to cfr*.jar (DEX->Java fallback decompiler)
  SHIELDSCOPE_GHIDRA       Ghidra install dir (enables native .so decompilation)
  SHIELDSCOPE_HEAP         JVM max heap for the tools (default 4g)
"""

import os
import glob
import shutil
import signal
import subprocess
import sys
import time

_IS_WIN = os.name == "nt"


# ---------------------------------------------------------------------------
#  discovery
# ---------------------------------------------------------------------------
def _first_existing(paths):
    for p in paths:
        if p and os.path.isfile(p):
            return p
    return None


def _find_java():
    if os.environ.get("SHIELDSCOPE_JAVA") and os.path.isfile(os.environ["SHIELDSCOPE_JAVA"]):
        return os.environ["SHIELDSCOPE_JAVA"]
    jh = os.environ.get("JAVA_HOME")
    if jh:
        cand = os.path.join(jh, "bin", "java.exe" if _IS_WIN else "java")
        if os.path.isfile(cand):
            return cand
    return shutil.which("java")


def _find_jadx_jar():
    env = os.environ.get("SHIELDSCOPE_JADX_JAR")
    if env and os.path.isfile(env):
        return env
    home = os.path.expanduser("~")
    globs = [
        os.path.join(home, "AppData", "Local", "jadx-cli", "lib", "jadx-*-all.jar"),
        os.path.join(home, "AppData", "Local", "jadx", "lib", "jadx-*-all.jar"),
        "C:/jadx/lib/jadx-*-all.jar",
        "/usr/share/jadx/lib/jadx-*-all.jar",
        "/opt/jadx/lib/jadx-*-all.jar",
        os.path.join(home, "jadx", "lib", "jadx-*-all.jar"),
    ]
    for g in globs:
        hits = sorted(glob.glob(g))
        if hits:
            return hits[-1]
    return None


def _find_apktool_jar():
    env = os.environ.get("SHIELDSCOPE_APKTOOL_JAR")
    if env and os.path.isfile(env):
        return env
    home = os.path.expanduser("~")
    cands = [
        "C:/Windows/apktool.jar",
        os.path.join(home, "AppData", "Local", "apktool", "apktool.jar"),
        "/usr/local/bin/apktool.jar",
        "/usr/share/apktool/apktool.jar",
    ]
    hit = _first_existing(cands)
    if hit:
        return hit
    # any apktool*.jar next to an apktool wrapper on PATH
    wrapper = shutil.which("apktool") or shutil.which("apktool.bat")
    if wrapper:
        d = os.path.dirname(wrapper)
        for g in sorted(glob.glob(os.path.join(d, "apktool*.jar"))):
            return g
    return None


def _find_dex2jar():
    """Return the dir holding dex2jar's jars (we run its CLI on the classpath),
    from env, PATH wrapper, or a known install."""
    env = os.environ.get("SHIELDSCOPE_DEX2JAR")
    if env:
        if os.path.isdir(env):
            libd = os.path.join(env, "lib")
            return libd if os.path.isdir(libd) else env
        if os.path.isfile(env):        # a jar or wrapper — use its dir
            d = os.path.dirname(env)
            libd = os.path.join(d, "lib")
            return libd if os.path.isdir(libd) else d
    wrapper = shutil.which("d2j-dex2jar") or shutil.which("d2j-dex2jar.sh")         or shutil.which("d2j-dex2jar.bat")
    if wrapper:
        d = os.path.dirname(os.path.realpath(wrapper))
        libd = os.path.join(d, "lib")
        return libd if os.path.isdir(libd) else d
    home = os.path.expanduser("~")
    for base in ("C:/dex2jar", "C:/dex-tools", "/usr/share/dex2jar",
                 "/opt/dex2jar", os.path.join(home, "dex2jar")):
        for g in sorted(glob.glob(base + "*")):
            libd = os.path.join(g, "lib")
            if os.path.isdir(libd):
                return libd
            if glob.glob(os.path.join(g, "*.jar")):
                return g
    return None


def _find_cfr_jar():
    env = os.environ.get("SHIELDSCOPE_CFR_JAR")
    if env and os.path.isfile(env):
        return env
    home = os.path.expanduser("~")
    globs = [
        "C:/cfr/cfr*.jar", os.path.join(home, "cfr*.jar"),
        os.path.join(home, "AppData", "Local", "cfr", "cfr*.jar"),
        "/usr/share/java/cfr*.jar", "/usr/local/share/cfr/cfr*.jar",
        "/opt/cfr/cfr*.jar",
    ]
    for g in globs:
        hits = sorted(glob.glob(g))
        if hits:
            return hits[-1]
    return None


def _find_ghidra():
    """Return the path to Ghidra's analyzeHeadless launcher, or None."""
    env = os.environ.get("SHIELDSCOPE_GHIDRA")
    cands = []
    if env:
        if os.path.isfile(env):
            return env
        cands += [os.path.join(env, "support", "analyzeHeadless" + (".bat" if _IS_WIN else "")),
                  os.path.join(env, "analyzeHeadless" + (".bat" if _IS_WIN else ""))]
    w = shutil.which("analyzeHeadless")
    if w:
        return w
    for g in sorted(glob.glob("C:/ghidra*/support/analyzeHeadless.bat")
                    + glob.glob("/opt/ghidra*/support/analyzeHeadless")
                    + glob.glob(os.path.expanduser("~/ghidra*/support/analyzeHeadless"))):
        cands.append(g)
    return _first_existing(cands)


def _find_rizin():
    """rizin (preferred) or radare2 — fast disassembler/symbol dumper for .so and
    Mach-O. Returns the executable path or None."""
    env = os.environ.get("SHIELDSCOPE_RIZIN")
    if env and (os.path.isfile(env) or shutil.which(env)):
        return env if os.path.isfile(env) else shutil.which(env)
    for name in ("rizin", "r2", "radare2"):
        w = shutil.which(name)
        if w:
            return w
    for g in sorted(glob.glob("C:/rizin*/bin/rizin.exe")
                    + glob.glob("C:/radare2*/bin/radare2.exe")
                    + glob.glob("/opt/rizin*/bin/rizin")):
        return g
    return None


def _find_objdump():
    """GNU objdump / llvm-objdump / gobjdump — quick symbol & disasm dump for ELF
    (.so) and Mach-O. Returns the executable path or None."""
    env = os.environ.get("SHIELDSCOPE_OBJDUMP")
    if env and (os.path.isfile(env) or shutil.which(env)):
        return env if os.path.isfile(env) else shutil.which(env)
    for name in ("objdump", "llvm-objdump", "gobjdump"):
        w = shutil.which(name)
        if w:
            return w
    return None


def _find_blutter():
    """blutter is a python script; return the path to blutter.py or None."""
    env = os.environ.get("SHIELDSCOPE_BLUTTER")
    if env:
        if os.path.isfile(env):
            return env
        cand = os.path.join(env, "blutter.py")
        if os.path.isfile(cand):
            return cand
    for g in sorted(glob.glob(os.path.expanduser("~/blutter*/blutter.py"))
                    + glob.glob("C:/blutter*/blutter.py")
                    + glob.glob("/opt/blutter*/blutter.py")):
        return g
    return None


class Tools:
    """Resolved tool paths + capability flags."""

    def __init__(self):
        self.java = _find_java()
        self.jadx_jar = _find_jadx_jar()
        self.apktool_jar = _find_apktool_jar()
        self.dex2jar_lib = _find_dex2jar()
        self.cfr_jar = _find_cfr_jar()
        self.ghidra = _find_ghidra()
        self.frida_dexdump = shutil.which("frida-dexdump")
        self.blutter = _find_blutter()          # Flutter libapp.so -> Dart dump
        self.hbctool = shutil.which("hbctool")  # React Native Hermes disassembler
        self.rizin = _find_rizin()              # .so / Mach-O symbols + disasm
        self.objdump = _find_objdump()          # .so / Mach-O symbols + disasm
        self.heap = os.environ.get("SHIELDSCOPE_HEAP", "4g")

    @property
    def have_java(self):
        return bool(self.java)

    @property
    def have_jadx(self):
        return bool(self.java and self.jadx_jar)

    @property
    def have_apktool(self):
        return bool(self.java and self.apktool_jar)

    @property
    def have_dex2jar(self):
        return bool(self.java and self.dex2jar_lib)

    @property
    def have_cfr(self):
        return bool(self.java and self.cfr_jar)

    @property
    def have_decompiler_fallback(self):
        # dex2jar (DEX->JAR) + CFR (JAR->Java): the "instead of jadx" path
        return self.have_dex2jar and self.have_cfr

    @property
    def have_ghidra(self):
        return bool(self.ghidra)

    @property
    def have_frida_dexdump(self):
        return bool(self.frida_dexdump)

    @property
    def have_blutter(self):
        return bool(self.blutter)

    @property
    def have_hbctool(self):
        return bool(self.hbctool)

    @property
    def have_rizin(self):
        return bool(self.rizin)

    @property
    def have_objdump(self):
        return bool(self.objdump)

    @property
    def have_native_symbols(self):
        # either lightweight native symbol dumper (no JVM / Ghidra needed)
        return bool(self.objdump or self.rizin)

    def summary(self):
        return {
            "java": self.java, "jadx_jar": self.jadx_jar,
            "apktool_jar": self.apktool_jar, "heap": self.heap,
            "dex2jar_lib": self.dex2jar_lib, "cfr_jar": self.cfr_jar,
            "ghidra": self.ghidra, "frida_dexdump": self.frida_dexdump,
            "blutter": self.blutter, "hbctool": self.hbctool,
            "rizin": self.rizin, "objdump": self.objdump,
            "have_jadx": self.have_jadx, "have_apktool": self.have_apktool,
            "have_decompiler_fallback": self.have_decompiler_fallback,
            "have_ghidra": self.have_ghidra,
            "have_rizin": self.have_rizin, "have_objdump": self.have_objdump,
            "have_native_symbols": self.have_native_symbols,
        }


_TOOLS = None


def get_tools():
    global _TOOLS
    if _TOOLS is None:
        _TOOLS = Tools()
    return _TOOLS


# ---------------------------------------------------------------------------
#  readiness / "will the output be accurate?" report
# ---------------------------------------------------------------------------
def _have_module(mod):
    try:
        import importlib.util
        return importlib.util.find_spec(mod) is not None
    except Exception:
        return False


# per-tool install hints, keyed by platform (win / linux / mac)
_INSTALL = {
    "java": {"win": "winget install EclipseAdoptium.Temurin.17.JDK",
             "linux": "sudo apt install openjdk-17-jre",
             "mac": "brew install temurin17"},
    "apktool": {"win": "Download apktool.jar + the wrapper from apktool.org, then set SHIELDSCOPE_APKTOOL_JAR to apktool.jar",
                "linux": "sudo apt install apktool  (or download apktool.jar)",
                "mac": "brew install apktool"},
    "jadx": {"win": "Download jadx from github.com/skylot/jadx/releases, then set SHIELDSCOPE_JADX_JAR to jadx-*-all.jar",
             "linux": "sudo apt install jadx  (or download from github.com/skylot/jadx)",
             "mac": "brew install jadx"},
    "fallback": {"win": "Download dex-tools + cfr.jar; set SHIELDSCOPE_DEX2JAR to the dex-tools dir and SHIELDSCOPE_CFR_JAR to cfr*.jar",
                 "linux": "Download dex-tools + cfr.jar; set SHIELDSCOPE_DEX2JAR and SHIELDSCOPE_CFR_JAR",
                 "mac": "Download dex-tools + cfr.jar; set SHIELDSCOPE_DEX2JAR and SHIELDSCOPE_CFR_JAR"},
    "androguard": {"win": "pip install androguard", "linux": "pip install androguard", "mac": "pip install androguard"},
    "lief": {"win": "pip install lief", "linux": "pip install lief", "mac": "pip install lief"},
    "native_symbols": {"win": "winget install LLVM.LLVM   (objdump)   — or —   winget install rizinorg.rizin",
                       "linux": "sudo apt install binutils   (objdump)   — or —   sudo apt install rizin",
                       "mac": "brew install llvm   (objdump)   — or —   brew install rizin"},
    "ghidra": {"win": "Download Ghidra (ghidra-sre.org), set SHIELDSCOPE_GHIDRA to its dir, and enable per run with SHIELDSCOPE_ENABLE_GHIDRA=1",
               "linux": "Download Ghidra, set SHIELDSCOPE_GHIDRA, enable with SHIELDSCOPE_ENABLE_GHIDRA=1",
               "mac": "Download Ghidra, set SHIELDSCOPE_GHIDRA, enable with SHIELDSCOPE_ENABLE_GHIDRA=1"},
    "blutter": {"win": "Clone github.com/worawit/blutter, then set SHIELDSCOPE_BLUTTER to blutter.py",
                "linux": "Clone github.com/worawit/blutter, set SHIELDSCOPE_BLUTTER to blutter.py",
                "mac": "Clone github.com/worawit/blutter, set SHIELDSCOPE_BLUTTER to blutter.py"},
    "hbctool": {"win": "pip install hbctool", "linux": "pip install hbctool", "mac": "pip install hbctool"},
    "frida_dexdump": {"win": "pip install frida-dexdump", "linux": "pip install frida-dexdump", "mac": "pip install frida-dexdump"},
}


def _current_os():
    if _IS_WIN:
        return "win"
    if sys.platform == "darwin":
        return "mac"
    return "linux"


def readiness():
    """Report which tools are present and whether the scan will be accurate.

    Returns {platform_os, level, headline, detail, tools:[{key,label,purpose,tier,
    present,impact,install}], missing_required, missing_recommended}. `level` is
    one of: ready / partial / insufficient."""
    t = get_tools()
    have_androguard = _have_module("androguard")
    have_lief = _have_module("lief")
    cur = _current_os()

    def row(key, label, purpose, tier, present, impact):
        return {"key": key, "label": label, "purpose": purpose, "tier": tier,
                "present": bool(present), "impact": impact,
                "install": _INSTALL.get(key, {}).get(cur, ""),
                "install_all": _INSTALL.get(key, {})}

    rows = [
        row("java", "Java (JRE/JDK 17+)", "runs apktool / jadx / dex2jar / CFR",
            "required", t.have_java,
            "Without Java the deep Android engine can't run at all."),
        row("apktool", "apktool", "smali + decoded manifest & resources",
            "recommended", t.have_apktool,
            "Manifest/IPC/resource findings and smali detection are degraded."),
        row("jadx", "jadx", "DEX -> Java with reconstructed strings",
            "recommended", t.have_jadx,
            "Best string/secret recovery; without it coverage leans on smali/fallback."),
        row("fallback", "dex2jar + CFR", "DEX -> Java fallback when jadx is absent",
            "optional", t.have_decompiler_fallback,
            "Secondary decompiler path; smali still scanned without it."),
        row("androguard", "androguard (pip)", "signing certificate + manifest reads",
            "recommended", have_androguard,
            "Signing-scheme / certificate checks and some manifest reads are unavailable."),
        row("lief", "LIEF (pip)", "Mach-O / ELF parsing + binary hardening flags",
            "recommended", have_lief,
            "iOS Mach-O parsing and native hardening (NX/PIE/canary) checks are limited."),
        row("native_symbols", "objdump or rizin", "native .so / Mach-O symbol & import analysis",
            "optional", t.have_native_symbols,
            "Native pinning / anti-debug / root detection on stripped blobs is less precise."),
        row("ghidra", "Ghidra", "native .so -> C decompile (opt-in, heavy)",
            "optional", t.have_ghidra,
            "Deep native logic/secret recovery is skipped (raw strings + symbols still scanned)."),
        row("blutter", "blutter", "Flutter libapp.so -> Dart dump",
            "optional", t.have_blutter,
            "Flutter apps are fingerprinted but their Dart code isn't dumped."),
        row("hbctool", "hbctool (pip)", "React-Native Hermes bytecode -> disasm",
            "optional", t.have_hbctool,
            "React-Native Hermes bundles aren't disassembled."),
        row("frida_dexdump", "frida-dexdump", "runtime-unpack a packed app (device needed)",
            "optional", t.have_frida_dexdump,
            "Packed/encrypted DEX can't be dumped for re-analysis."),
    ]

    missing_required = [r for r in rows if r["tier"] == "required" and not r["present"]]
    missing_recommended = [r for r in rows if r["tier"] == "recommended" and not r["present"]]
    core_ok = t.have_java and (t.have_apktool or t.have_jadx or t.have_decompiler_fallback)

    if not core_ok or missing_required:
        level = "insufficient"
        headline = "Not ready — output will be minimal / inaccurate"
        detail = ("Required tooling is missing, so the deep engine can't decompile the app. "
                  "Install the items marked REQUIRED below, then re-scan.")
    elif missing_recommended:
        level = "partial"
        names = ", ".join(r["label"] for r in missing_recommended)
        headline = "Mostly ready — some accuracy reduced"
        detail = ("Core analysis will run, but these recommended tools are missing: %s. "
                  "Findings stay reliable where they fire; the impacted areas above will be "
                  "thinner. Optional tools further improve native/framework depth." % names)
    else:
        level = "ready"
        headline = "Ready — full static accuracy"
        detail = ("All required and recommended tools are present. Optional tools, if any are "
                  "missing, only affect deep native/framework extraction, not core accuracy.")

    return {"platform_os": cur, "level": level, "headline": headline, "detail": detail,
            "tools": rows,
            "missing_required": [r["key"] for r in missing_required],
            "missing_recommended": [r["key"] for r in missing_recommended]}


# ---------------------------------------------------------------------------
#  bounded subprocess runner
# ---------------------------------------------------------------------------
class RunResult:
    def __init__(self, rc, out, err, timed_out, seconds, cmd):
        self.rc = rc
        self.out = out
        self.err = err
        self.timed_out = timed_out
        self.seconds = seconds
        self.cmd = cmd

    @property
    def ok(self):
        return (self.rc == 0) and not self.timed_out


def _kill_tree(proc):
    """Kill a process and all of its children (best effort, cross-platform)."""
    try:
        if _IS_WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run(cmd, timeout=None, cwd=None, log=None):
    """
    Run `cmd` (a list) with a hard timeout. On timeout the whole process tree is
    killed. Returns a RunResult; never raises for a tool failure/timeout.
    """
    t0 = time.time()
    popen_kw = dict(cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    universal_newlines=True, errors="replace")
    if not _IS_WIN:
        popen_kw["preexec_fn"] = os.setsid  # own process group for killpg
    try:
        proc = subprocess.Popen(cmd, **popen_kw)
    except FileNotFoundError as e:
        return RunResult(127, "", "tool not found: %s" % e, False, 0.0, cmd)
    try:
        out, _ = proc.communicate(timeout=timeout)
        rc = proc.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            out, _ = proc.communicate(timeout=10)
        except Exception:
            out = ""
        rc = -1
        timed_out = True
    secs = round(time.time() - t0, 1)
    if log is not None:
        log.append({"cmd": " ".join(os.path.basename(c) if i == 0 else c
                                    for i, c in enumerate(cmd)),
                    "rc": rc, "timed_out": timed_out, "seconds": secs})
    return RunResult(rc, out or "", "", timed_out, secs, cmd)


# ---------------------------------------------------------------------------
#  tool invocations (JVM launched directly)
# ---------------------------------------------------------------------------
def jadx(args, timeout, cwd=None, log=None, heap=None):
    t = get_tools()
    heap = heap or t.heap
    cmd = [t.java, "-Xmx%s" % heap, "-XX:+UseParallelGC",
           "-cp", t.jadx_jar, "jadx.cli.JadxCLI"] + list(args)
    return run(cmd, timeout=timeout, cwd=cwd, log=log)


def apktool(args, timeout, cwd=None, log=None, heap=None):
    t = get_tools()
    heap = heap or t.heap
    cmd = [t.java, "-Xmx%s" % heap, "-jar", t.apktool_jar] + list(args)
    return run(cmd, timeout=timeout, cwd=cwd, log=log)


def dex2jar(apk_path, out_jar, timeout, log=None, heap=None):
    """DEX -> JAR via dex2jar's CLI (run on the classpath, JVM launched directly
    so a hang is killable). Returns a RunResult."""
    t = get_tools()
    heap = heap or t.heap
    cp = os.path.join(t.dex2jar_lib, "*")
    cmd = [t.java, "-Xmx%s" % heap, "-cp", cp,
           "com.googlecode.dex2jar.tools.Dex2jarCmd", "-f", "-o", out_jar, apk_path]
    return run(cmd, timeout=timeout, log=log)


def cfr(in_jar, out_dir, timeout, log=None, heap=None):
    """JAR -> Java source tree via CFR. Returns a RunResult."""
    t = get_tools()
    heap = heap or t.heap
    cmd = [t.java, "-Xmx%s" % heap, "-jar", t.cfr_jar, in_jar,
           "--outputdir", out_dir, "--comments", "false", "--silent", "true"]
    return run(cmd, timeout=timeout, log=log)


def ghidra_headless(so_path, out_c, project_dir, script_path, timeout, log=None):
    """Decompile a single native .so to C via Ghidra headless + our postScript.

    analyzeHeadless imports the binary, auto-analyses it, then runs
    ghidra_decompile.py which writes decompiled functions + strings to `out_c`.
    Heavy and slow — callers bound the count and timeout."""
    t = get_tools()
    projname = "ss_" + str(abs(hash(so_path)) % 10_000_000)
    cmd = [t.ghidra, project_dir, projname, "-import", so_path,
           "-scriptPath", script_path, "-postScript", "ghidra_decompile.py", out_c,
           "-deleteProject", "-analysisTimeoutPerFile", str(max(30, timeout - 30))]
    return run(cmd, timeout=timeout, log=log)


def baksmali(dex_path, out_dir, timeout, log=None, heap=None):
    """DEX -> smali via dex2jar's baksmali (used to disassemble runtime-dumped
    DEX so the same smali detectors run on unpacked/decrypted code)."""
    t = get_tools()
    heap = heap or t.heap
    cp = os.path.join(t.dex2jar_lib, "*")
    cmd = [t.java, "-Xmx%s" % heap, "-cp", cp,
           "com.googlecode.d2j.smali.BaksmaliCmd", "-o", out_dir, dex_path]
    return run(cmd, timeout=timeout, log=log)


def blutter(lib_dir, out_dir, timeout, log=None):
    """Flutter libapp.so -> Dart class/method dump (text) via blutter."""
    t = get_tools()
    py = _find_python()
    cmd = [py, t.blutter, lib_dir, out_dir]
    return run(cmd, timeout=timeout, log=log)


def hbctool_disasm(bundle_path, out_dir, timeout, log=None):
    """Hermes bytecode bundle -> disassembly (text) via hbctool."""
    t = get_tools()
    cmd = [t.hbctool, "disasm", bundle_path, out_dir]
    return run(cmd, timeout=timeout, log=log)


def objdump_symbols(bin_path, timeout, log=None):
    """Dynamic symbol / import table of an ELF (.so) or Mach-O via objdump.

    `-T` is the dynamic symbol table (imports + exports) — fast, no full disasm —
    which surfaces calls like ptrace / fork / __system_property_get and pinning
    symbols that a raw-byte string grep can miss or mis-attribute. llvm-objdump
    accepts the same flag. Returns a RunResult (text in .out)."""
    t = get_tools()
    base = os.path.basename(t.objdump or "").lower()
    # llvm-objdump prefers --dynamic-syms / --syms; GNU objdump uses -T -t
    if "llvm-objdump" in base:
        cmd = [t.objdump, "--dynamic-syms", "--demangle", bin_path]
    else:
        cmd = [t.objdump, "-T", "-C", bin_path]
    return run(cmd, timeout=timeout, log=log)


def rizin_symbols(bin_path, timeout, log=None):
    """Imports + exports + symbols of an ELF (.so) or Mach-O via rizin/radare2.

    ii = imports, iE = exports, is = symbols. `-q` runs the commands and quits
    (no interactive prompt); `-e bin.relocs.apply=false` keeps it quick. radare2
    accepts the same commands. Returns a RunResult (text in .out)."""
    t = get_tools()
    cmd = [t.rizin, "-q", "-e", "scr.color=0", "-c", "ii;iE;is", bin_path]
    return run(cmd, timeout=timeout, log=log)


def native_symbols(bin_path, timeout, log=None):
    """Prefer objdump (fast, ubiquitous), fall back to rizin. Returns symbol/import
    text as a string ('' if neither tool is available or both fail)."""
    t = get_tools()
    if t.have_objdump:
        r = objdump_symbols(bin_path, timeout, log=log)
        if r.ok and r.out.strip():
            return r.out
    if t.have_rizin:
        r = rizin_symbols(bin_path, timeout, log=log)
        if r.ok and r.out.strip():
            return r.out
    return ""


def _find_python():
    return os.environ.get("SHIELDSCOPE_PYTHON") or shutil.which("python")         or shutil.which("python3") or sys.executable

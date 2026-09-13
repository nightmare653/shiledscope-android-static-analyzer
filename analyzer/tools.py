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

    def summary(self):
        return {
            "java": self.java, "jadx_jar": self.jadx_jar,
            "apktool_jar": self.apktool_jar, "heap": self.heap,
            "dex2jar_lib": self.dex2jar_lib, "cfr_jar": self.cfr_jar,
            "ghidra": self.ghidra, "frida_dexdump": self.frida_dexdump,
            "blutter": self.blutter, "hbctool": self.hbctool,
            "have_jadx": self.have_jadx, "have_apktool": self.have_apktool,
            "have_decompiler_fallback": self.have_decompiler_fallback,
            "have_ghidra": self.have_ghidra,
        }


_TOOLS = None


def get_tools():
    global _TOOLS
    if _TOOLS is None:
        _TOOLS = Tools()
    return _TOOLS


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


def _find_python():
    return os.environ.get("SHIELDSCOPE_PYTHON") or shutil.which("python")         or shutil.which("python3") or sys.executable

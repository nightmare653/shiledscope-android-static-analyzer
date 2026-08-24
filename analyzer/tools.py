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


class Tools:
    """Resolved tool paths + capability flags."""

    def __init__(self):
        self.java = _find_java()
        self.jadx_jar = _find_jadx_jar()
        self.apktool_jar = _find_apktool_jar()
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

    def summary(self):
        return {
            "java": self.java, "jadx_jar": self.jadx_jar,
            "apktool_jar": self.apktool_jar, "heap": self.heap,
            "have_jadx": self.have_jadx, "have_apktool": self.have_apktool,
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

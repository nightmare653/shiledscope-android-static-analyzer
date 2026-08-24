"""
Frida device bridge — runs a script against a real app on a device/emulator and
captures what happened. Used by the deterministic "run my generated script"
button AND by the AI bypass agent.

Requires: the `frida` python package (installed) + a device/emulator running
frida-server + the target app installed. Everything degrades gracefully with a
clear error when a prerequisite is missing — it never throws into the web layer.

SAFETY: this executes code on a device you control. Callers must pass an explicit
package + (optionally) device id; nothing runs implicitly.
"""

import os
import shutil
import subprocess
import tempfile
import time

try:
    import frida
    _HAVE_FRIDA = True
except Exception:
    frida = None
    _HAVE_FRIDA = False

_IS_WIN = os.name == "nt"


def available():
    return _HAVE_FRIDA


def list_devices():
    if not _HAVE_FRIDA:
        return {"ok": False, "error": "frida python package not installed"}
    try:
        devs = frida.enumerate_devices()
        out = []
        for d in devs:
            if d.type in ("usb", "remote"):
                out.append({"id": d.id, "name": d.name, "type": d.type})
        return {"ok": True, "devices": out}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _get_device(device_id):
    if device_id:
        return frida.get_device(device_id, timeout=8)
    return frida.get_usb_device(timeout=8)


def run_script(package, script_js, device_id=None, spawn=True, collect_seconds=6):
    """
    Inject `script_js` into `package`. Returns:
      {ok, loaded, console:[...], sends:[...], errors:[...], markers:[...], error?}
    `markers` are the "[+] ..." success lines a good bypass script prints.
    """
    if not package:
        return {"ok": False, "error": "no target package specified"}
    # frida 17 removed the built-in Java/ObjC bridges from raw create_script, so
    # we run through the frida CLI, which bundles the bridges (Java is defined).
    cli = shutil.which("frida")
    if cli:
        return _run_via_cli(cli, package, script_js, device_id, spawn, collect_seconds)
    if not _HAVE_FRIDA:
        return {"ok": False, "error": "frida CLI and python package both unavailable"}
    return _run_via_api(package, script_js, device_id, spawn, collect_seconds)


def _resolve_pid(package, device_id):
    if not _HAVE_FRIDA:
        return None
    try:
        dev = _get_device(device_id)
        for app in dev.enumerate_applications():
            if app.identifier == package and getattr(app, "pid", 0):
                return app.pid
    except Exception:
        pass
    return None


def _run_via_cli(cli, package, script_js, device_id, spawn, collect_seconds):
    """Run through the frida CLI (bundles Java/ObjC bridges), capture stdout."""
    fd, path = tempfile.mkstemp(suffix=".js", prefix="ss_frida_")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write(script_js)
    secs = max(3, min(collect_seconds, 40))
    args = [cli]
    args += (["-D", device_id] if device_id else ["-U"])
    if spawn:
        args += ["-f", package, "--kill-on-exit"]   # spawn auto-resumes by default
    else:
        args += ["-N", package]                      # attach by app identifier
    # -q -t N: run the script, wait N seconds, then quit (captures console.log)
    args += ["-l", path, "-q", "-t", str(secs)]
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                universal_newlines=True, errors="replace")
    except Exception as e:
        os.unlink(path)
        return {"ok": False, "error": "failed to launch frida CLI: %s" % e}
    out = ""
    try:
        out, _ = proc.communicate(timeout=secs + 25)
    except subprocess.TimeoutExpired:
        _kill(proc)
        try:
            out, _ = proc.communicate(timeout=8)
        except Exception:
            out = out or ""
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    lines = [l.rstrip() for l in (out or "").splitlines() if l.strip()]
    markers = [l for l in lines if l.strip().startswith("[+]")]

    def _is_err(l):
        s = l.strip()
        if s.startswith("[+]") or s.startswith("[ShieldScope"):
            return False
        low = l.lower()
        return any(k in low for k in ("error:", "traceback", "unable to", "failed to",
                                      "is not defined", "unrecognized argument", "exception:"))
    errors = [l for l in lines if _is_err(l)]
    installed = any("all hooks installed" in l for l in lines)
    return {"ok": (len(errors) == 0 and (bool(markers) or installed)),
            "loaded": True, "console": lines, "sends": [],
            "errors": errors, "markers": markers}


def _kill(proc):
    try:
        if _IS_WIN:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_via_api(package, script_js, device_id, spawn, collect_seconds):
    """Fallback path via the python binding (works on frida <17 with built-in Java)."""
    console, sends, errors = [], [], []

    def on_message(message, data):
        t = message.get("type")
        if t == "send":
            sends.append(message.get("payload"))
        elif t == "error":
            errors.append(message.get("description") or str(message))

    device = pid = session = script = None
    try:
        device = _get_device(device_id)
    except Exception as e:
        return {"ok": False, "error": "no device: %s" % e}
    try:
        if spawn:
            pid = device.spawn([package]); session = device.attach(pid)
        else:
            session = device.attach(_resolve_pid(package, device_id) or package)
        script = session.create_script(script_js)
        script.on("message", on_message)
        try:
            script.set_log_handler(lambda level, text: console.append(text))
        except Exception:
            pass
        script.load()
        if spawn and pid:
            device.resume(pid)
        time.sleep(max(1, min(collect_seconds, 30)))
    except Exception as e:
        return {"ok": False, "loaded": bool(script), "error": str(e),
                "console": console, "errors": errors}
    finally:
        try:
            if session:
                session.detach()
        except Exception:
            pass
    markers = [c for c in console if isinstance(c, str) and c.strip().startswith("[+]")]
    return {"ok": len(errors) == 0, "loaded": True, "console": console,
            "sends": sends, "errors": errors, "markers": markers}

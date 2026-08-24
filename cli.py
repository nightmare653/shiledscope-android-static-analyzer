#!/usr/bin/env python3
"""
ShieldScope CLI — headless deep analysis of an APK / IPA / extracted data dir.

Examples:
  python cli.py app.apk                      # readable summary to the terminal
  python cli.py app.apk --json out.json      # full result as JSON
  python cli.py app.apk --keep-decompiled    # keep + print the decompiled tree path
  python cli.py app.apk -q --json out.json    # quiet, machine-readable only

The GUI is the web app (`python app.py`); this is the same engine without it.
"""

import argparse
import json
import os
import sys

# findings contain Unicode (→, em-dashes); the Windows console is cp1252 by
# default and would raise UnicodeEncodeError — force UTF-8 with safe fallback.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyzer import analyze_file  # noqa: E402

# ---- tiny ANSI helpers (auto-disabled when not a TTY / on Windows w/o support) ----
_USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
def _c(code, s):
    return ("\033[%sm%s\033[0m" % (code, s)) if _USE_COLOR else s
def bold(s): return _c("1", s)
def red(s): return _c("31", s)
def yellow(s): return _c("33", s)
def green(s): return _c("32", s)
def cyan(s): return _c("36", s)
def dim(s): return _c("2", s)

_SEV_COLOR = {"high": red, "medium": yellow, "low": cyan, "info": dim}


def _print_summary(r):
    f = r.get("file", {})
    plat = r.get("platform", "?")
    print(bold("\nShieldScope — %s  (%s, %s)" % (f.get("name", "?"), plat, _fmt_size(f.get("size", 0)))))
    if f.get("sha256"):
        print(dim("sha256 " + f["sha256"]))

    if r.get("score") is not None:
        print("\n" + bold("Protection: ") + "%s / 100  — %s" % (r["score"], r.get("rating", "")))
    obf = r.get("obfuscation")
    if obf:
        print("Obfuscation: %s (%s)" % (obf.get("level"), obf.get("ratio")))
    fw = [x.get("name") for x in r.get("frameworks", [])]
    if fw:
        print("Frameworks: " + ", ".join(fw))

    for bucket, label in (("root", "Root / integrity / anti-tamper"), ("ssl", "SSL / pinning")):
        b = r.get(bucket, {})
        mechs = b.get("mechanisms", [])
        head = "%s: %d layer(s)" % (label, b.get("layers", 0)) if b.get("implemented") else "%s: none" % label
        print("\n" + bold(head))
        for m in mechs:
            tag = green("PAIRIP") if m.get("id") == "pairip" else m.get("confidence", "")
            print("  - %s  [%s %s]" % (m.get("name"), m.get("layer", ""), tag))

    extra = r.get("extra", []) or []
    if extra:
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        extra = sorted(extra, key=lambda x: order.get(x.get("severity"), 9))
        counts = {}
        for x in extra:
            counts[x["severity"]] = counts.get(x["severity"], 0) + 1
        print("\n" + bold("Findings (%d): " % len(extra))
              + "  ".join(_SEV_COLOR.get(s, str)(("%s %d" % (s, counts[s])))
                          for s in ("high", "medium", "low", "info") if s in counts))
        for x in extra[:25]:
            col = _SEV_COLOR.get(x.get("severity"), str)
            print("  " + col("[%s]" % x.get("severity")) + " %s" % x.get("title")
                  + dim("  (%s)" % x.get("location", ""))[:120])
        if len(extra) > 25:
            print(dim("  … %d more (use --json for the full list)" % (len(extra) - 25)))

    api = r.get("api", {})
    if api.get("counts", {}).get("total"):
        c = api["counts"]
        print("\n" + bold("API surface: ") + "%d endpoints, %d sensitive" % (c.get("total"), c.get("sensitive", 0)))
        for e in [e for e in api.get("endpoints", [])
                  if e.get("severity") in ("high", "medium") and e.get("category") != "third-party"][:12]:
            print("  " + _SEV_COLOR.get(e["severity"], str)("[%s]" % e["category_name"]) + " " + e["value"][:90])

    fr = r.get("frida", {})
    if fr and fr.get("command"):
        print("\n" + bold("Frida bypass: ") + fr["command"])
    if r.get("decompiled_dir"):
        print("\n" + bold("Decompiled tree kept at: ") + r["decompiled_dir"])
        print(dim("  apktool/ (smali + res + manifest), jadx/sources/ (java, when run), raw/ (unzipped)"))


def _fmt_size(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024 or u == "GB":
            return "%.1f %s" % (n, u)
        n /= 1024.0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="shieldscope", description="Deep static analyzer for APK/IPA.")
    ap.add_argument("target", help="path to an .apk / .ipa / .ab / .tar / .zip")
    ap.add_argument("--json", metavar="FILE", help="write the full result as JSON")
    ap.add_argument("--keep-decompiled", action="store_true",
                    help="keep the decompiled tree (smali/java/res) and print its path")
    ap.add_argument("-q", "--quiet", action="store_true", help="suppress the readable summary")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"],
                    help="exit non-zero if any finding at/above this severity exists (CI gate)")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.target):
        print(red("error: no such file: %s" % args.target), file=sys.stderr)
        return 2

    if not args.quiet:
        print(dim("Analyzing %s … (large apps take several minutes)" % os.path.basename(args.target)),
              file=sys.stderr, flush=True)
    r = analyze_file(args.target, original_name=os.path.basename(args.target),
                     keep_workdir=args.keep_decompiled)

    if not r.get("ok"):
        print(red("Analysis failed: " + str(r.get("error"))), file=sys.stderr)
        return 1

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(r, fh, indent=1)
        if not args.quiet:
            print(dim("wrote " + args.json), file=sys.stderr)
    if not args.quiet:
        _print_summary(r)

    if args.fail_on:
        rank = {"high": 0, "medium": 1, "low": 2}
        thr = rank[args.fail_on]
        worst = min((rank.get(x.get("severity"), 9) for x in r.get("extra", [])), default=9)
        if worst <= thr:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

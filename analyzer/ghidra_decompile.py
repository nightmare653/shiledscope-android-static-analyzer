# Ghidra headless post-script (Jython) — invoked by tools.ghidra_headless().
#
# Writes decompiled C for every function in the imported binary, plus the
# defined-string table, to the output file passed as the first script arg. The
# resulting text is then walked by ShieldScope's scanners exactly like any other
# source file, so native SSL-pinning / root logic and hardcoded secrets living
# in .so code become greppable (jadx/apktool never touch native code).
#
# Bounded so a huge library can't wedge the run: a function cap and a per-run
# decompiler timeout. Safe to fail — on any error we write what we have.
# @category ShieldScope
import time

try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
except Exception:
    DecompInterface = None

MAX_FUNCS = 6000
PER_FUNC_TIMEOUT = 30      # seconds Ghidra gives the decompiler per function
OVERALL_BUDGET = 600       # wall-clock seconds for the whole export


def _out_path():
    args = getScriptArgs()
    return args[0] if args and len(args) > 0 else "ghidra_out.c"


def main():
    out = _out_path()
    fh = open(out, "w")
    try:
        prog = currentProgram
        fh.write("// ShieldScope Ghidra decompilation of %s\n" % prog.getName())

        # defined strings first (cheap, high-signal for secrets/URLs)
        try:
            listing = prog.getListing()
            di = prog.getDataTypeManager()
            for d in listing.getDefinedData(True):
                v = d.getValue()
                if v is not None and d.hasStringValue():
                    fh.write('// str %s: %s\n' % (d.getAddress(), str(d)))
        except Exception as e:
            fh.write("// (string dump failed: %s)\n" % e)

        if DecompInterface is None:
            fh.write("// decompiler unavailable\n")
            return

        monitor = ConsoleTaskMonitor()
        dec = DecompInterface()
        dec.openProgram(prog)
        start = time.time()
        n = 0
        fm = prog.getFunctionManager()
        for func in fm.getFunctions(True):
            if n >= MAX_FUNCS or (time.time() - start) > OVERALL_BUDGET:
                fh.write("// … export truncated at budget\n")
                break
            try:
                res = dec.decompileFunction(func, PER_FUNC_TIMEOUT, monitor)
                if res is not None and res.decompileCompleted():
                    fh.write(res.getDecompiledFunction().getC())
                    fh.write("\n")
                    n += 1
            except Exception:
                continue
        fh.write("// functions decompiled: %d\n" % n)
    finally:
        fh.close()


main()

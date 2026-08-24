"""
Frida bypass-script generator (#1).

Given an analysis result, stitch together a single ready-to-run Frida script
containing ONLY the hooks relevant to the mechanisms that were actually detected,
with the app's real package / bundle id filled in.

Output:
  {"script": "<js>", "command": "frida -U -f <id> -l bypass.js",
   "filename": "shieldscope_bypass_<id>.js", "hooks": [<mechanism ids covered>]}
"""

# ---------------------------------------------------------------------------
# Android hook snippets, keyed by signature id (or a synthesised group id).
# Each snippet is a self-contained block executed inside Java.perform().
# ---------------------------------------------------------------------------
A = {}

A["rootbeer"] = r"""
  // --- RootBeer: force every check to report "not rooted" ---
  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    var falseMethods = ['isRooted','isRootedWithoutBusyBoxCheck','isRootedWithBusyBoxCheck',
      'checkForBinary','checkForDangerousProps','checkForSuBinary','checkForRWPaths',
      'detectTestKeys','checkSuExists','detectRootManagementApps','detectPotentiallyDangerousApps',
      'detectRootCloakingApps','checkForRootNative','checkForMagiskBinary','isBusyBoxAvailable'];
    falseMethods.forEach(function (m) {
      if (RootBeer[m]) {
        RootBeer[m].overloads.forEach(function (ov) {
          ov.implementation = function () { return false; };
        });
      }
    });
    console.log('[+] RootBeer neutralised');
  } catch (e) {}
"""

A["_file_hide"] = r"""
  // --- Hide su / magisk / busybox from java.io.File existence checks ---
  try {
    var needles = ['su','magisk','busybox','superuser','xposed','frida','/sbin/','/system/xbin','/system/app/Superuser'];
    var UnixFile = Java.use('java.io.File');
    UnixFile.exists.implementation = function () {
      try {
        var p = this.getAbsolutePath();
        for (var i = 0; i < needles.length; i++)
          if (p.toLowerCase().indexOf(needles[i]) !== -1) return false;
      } catch (e) {}
      return this.exists();
    };
    console.log('[+] File.exists() root-path checks hidden');
  } catch (e) {}
"""

A["_native_file_hide"] = r"""
  // --- Native libc: hide the same paths from access()/fopen()/stat() ---
  try {
    var deny = ['su','magisk','busybox','superuser','/sbin/su','xposed'];
    function bad(path) { if (!path) return false; path = path.toLowerCase();
      for (var i=0;i<deny.length;i++) if (path.indexOf(deny[i])!==-1) return true; return false; }
    ['access','fopen','stat','__xstat','lstat','open'].forEach(function (fn) {
      var p = Module.findExportByName(null, fn);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter: function (a) { this.block = false; try { this.block = bad(a[0].readCString()); } catch (e) {} },
        onLeave: function (r) { if (this.block) r.replace(ptr('-1')); }
      });
    });
    console.log('[+] native libc path checks hidden');
  } catch (e) {}
"""

A["root-packages"] = r"""
  // --- Pretend root-manager packages are not installed ---
  try {
    var rootPkgs = ['com.topjohnwu.magisk','eu.chainfire.supersu','com.noshufou.android.su',
      'com.koushikdutta.superuser','com.thirdparty.superuser'];
    var PM = Java.use('android.app.ApplicationPackageManager');
    var NNFE = Java.use('android.content.pm.PackageManager$NameNotFoundException');
    PM.getPackageInfo.overload('java.lang.String','int').implementation = function (name, flags) {
      if (rootPkgs.indexOf(name) !== -1) throw NNFE.$new(name);
      return this.getPackageInfo(name, flags);
    };
    console.log('[+] root package lookups blocked');
  } catch (e) {}
"""

A["busybox-which"] = r"""
  // --- Neutralise Runtime.exec("which su") / ProcessBuilder ---
  try {
    var Runtime = Java.use('java.lang.Runtime');
    var evil = ['su','which','busybox','magisk','id','mount'];
    function scrub(cmd) { try { var c = ('' + cmd).toLowerCase();
      for (var i=0;i<evil.length;i++) if (c.indexOf(evil[i])!==-1) return 'echo'; } catch (e) {} return cmd; }
    Runtime.exec.overload('java.lang.String').implementation = function (c) { return this.exec(scrub(c)); };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
      try { if (arr && arr.length) arr[0] = scrub(arr[0]); } catch (e) {} return this.exec(arr); };
    console.log('[+] Runtime.exec root probes neutralised');
  } catch (e) {}
"""

A["test-keys"] = r"""
  // --- Spoof Build.TAGS away from test-keys ---
  try {
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    console.log('[+] Build.TAGS spoofed to release-keys');
  } catch (e) {}
"""

A["_ssl_universal"] = r"""
  // --- Universal TrustManager / pinning bypass (covers OkHttp, TrustKit, NSC, custom TMs) ---
  try {
    var X509TM = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TM = Java.registerClass({
      name: 'com.shieldscope.TrustAll',
      implements: [X509TM],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var tms = [TM.$new()];
    var init = SSLContext.init.overload(
      '[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom');
    init.implementation = function (km, x, sr) { init.call(this, km, tms, sr); };
    console.log('[+] SSLContext pinned to permissive TrustManager');
  } catch (e) {}

  // OkHttp CertificatePinner direct stub
  try {
    var CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String','java.util.List').implementation = function () { return; };
    if (CP.check$okhttp) CP.check$okhttp.implementation = function () { return; };
    console.log('[+] OkHttp CertificatePinner.check() stubbed');
  } catch (e) {}

  // HostnameVerifier
  try {
    var HV = Java.use('javax.net.ssl.HttpsURLConnection');
    var AllowAll = Java.registerClass({
      name: 'com.shieldscope.AllowAllHV',
      implements: [Java.use('javax.net.ssl.HostnameVerifier')],
      methods: { verify: function () { return true; } }
    });
    HV.setDefaultHostnameVerifier(AllowAll.$new());
  } catch (e) {}
"""

A["webview-sslerror"] = r"""
  // --- WebView: accept SSL errors ---
  try {
    var WVC = Java.use('android.webkit.WebViewClient');
    WVC.onReceivedSslError.implementation = function (view, handler, err) {
      try { handler.proceed(); } catch (e) {}
    };
    console.log('[+] WebViewClient.onReceivedSslError -> proceed()');
  } catch (e) {}
"""

# ---------------------------------------------------------------------------
# iOS blocks (run outside Java.perform).
# ---------------------------------------------------------------------------
IOS_JB = r"""
/* --- iOS jailbreak-detection bypass --- */
try {
  var deny = ['/Applications/Cydia.app','/Applications/Sileo.app','/bin/bash','/bin/sh',
    '/usr/sbin/sshd','/etc/apt','/private/var/lib/apt','MobileSubstrate','/usr/libexec/cydia','/usr/bin/ssh'];
  function isJB(p) { if (!p) return false; for (var i=0;i<deny.length;i++) if (p.indexOf(deny[i])!==-1) return true; return false; }
  ['fopen','stat','lstat','access','open','__xstat'].forEach(function (fn) {
    var a = Module.findExportByName(null, fn); if (!a) return;
    Interceptor.attach(a, { onEnter: function (args) { this.b=false; try { this.b=isJB(args[0].readCString()); } catch(e){} },
      onLeave: function (r) { if (this.b) r.replace(ptr('-1')); } });
  });
  var fm = ObjC.classes.NSFileManager;
  if (fm) {
    var sel = ObjC.classes.NSFileManager['- fileExistsAtPath:'];
    Interceptor.attach(sel.implementation, {
      onEnter: function (a) { try { this.jb = isJB(new ObjC.Object(a[2]).toString()); } catch(e){ this.jb=false; } },
      onLeave: function (r) { if (this.jb) r.replace(ptr('0x0')); } });
  }
  console.log('[+] iOS jailbreak file/path checks hidden');
} catch (e) { console.log('jb hook err ' + e); }
"""

IOS_SSL = r"""
/* --- iOS SSL pinning bypass (SecTrust / TrustKit / AFNetworking / Alamofire) --- */
try {
  var ST = Module.findExportByName('Security','SecTrustEvaluate');
  if (ST) Interceptor.replace(ST, new NativeCallback(function (trust, result) {
    if (!result.isNull()) result.writeU32(1 /* kSecTrustResultProceed */); return 0; }, 'int', ['pointer','pointer']));
  var STE = Module.findExportByName('Security','SecTrustEvaluateWithError');
  if (STE) Interceptor.replace(STE, new NativeCallback(function (trust, err) { return 1; }, 'bool', ['pointer','pointer']));
  console.log('[+] SecTrustEvaluate forced to proceed');
} catch (e) { console.log('ssl hook err ' + e); }

/* BoringSSL custom verify (also used inside many frameworks) */
try {
  var verify = Module.findExportByName(null,'SSL_get_verify_result');
  if (verify) Interceptor.attach(verify, { onLeave: function (r) { r.replace(ptr('0')); } });
} catch (e) {}
"""

IOS_ANTIDEBUG = r"""
/* --- iOS anti-debug (ptrace PT_DENY_ATTACH) --- */
try {
  var p = Module.findExportByName(null,'ptrace');
  if (p) Interceptor.replace(p, new NativeCallback(function () { return 0; }, 'int', ['int','int','pointer','int']));
  console.log('[+] ptrace neutralised');
} catch (e) {}
"""


def _android_blocks(result):
    ids = set()
    for b in ("root", "ssl"):
        for m in result.get(b, {}).get("mechanisms", []):
            ids.add(m["id"])
    blocks, covered = [], []

    if "rootbeer" in ids:
        blocks.append(A["rootbeer"]); covered.append("rootbeer")
    if ids & {"su-path-check", "magisk-artifacts", "busybox-which"}:
        blocks.append(A["_file_hide"]); blocks.append(A["_native_file_hide"])
        covered += ["file-existence", "native-file"]
    if "root-packages" in ids:
        blocks.append(A["root-packages"]); covered.append("root-packages")
    if ids & {"busybox-which"}:
        blocks.append(A["busybox-which"]); covered.append("exec-probe")
    if "test-keys" in ids:
        blocks.append(A["test-keys"]); covered.append("test-keys")

    ssl_ids = {"okhttp-pinner", "network-security-config", "trustkit-android",
               "custom-trustmanager", "conscrypt-native-ssl"}
    if ids & ssl_ids:
        blocks.append(A["_ssl_universal"]); covered.append("ssl-universal")
    if "webview-sslerror" in ids:
        blocks.append(A["webview-sslerror"]); covered.append("webview-ssl")

    return blocks, covered


def generate(result):
    plat = result.get("platform")
    app_id = None
    warnings = []

    if plat == "android":
        app_id = (result.get("meta") or {}).get("package") or "<package.name>"
        blocks, covered = _android_blocks(result)
        # targeted hooks for the ACTUAL (possibly obfuscated) classes we found —
        # this is what makes the bypass work on renamed apps
        disc = result.get("discovered") or {}
        disc_classes = list(disc.get("trust_all", [])) + list(disc.get("custom_tm", []))
        if disc_classes:
            lines = ["\n  // --- Targeted hooks for the app's OWN TrustManager classes "
                     "(discovered by static analysis) ---"]
            for cls in disc_classes[:8]:
                lines.append(
                    "  try { var _C = Java.use('%s');\n"
                    "    if (_C.checkServerTrusted) _C.checkServerTrusted.overloads.forEach("
                    "function(o){ o.implementation = function(){ return; }; });\n"
                    "    console.log('[+] neutralised %s.checkServerTrusted'); } catch (e) {}" % (cls, cls))
            blocks.append("\n".join(lines))
            covered.append("app-trustmanagers")
        fw_ids = {f["id"] for f in result.get("frameworks", [])}
        if "flutter" in fw_ids:
            warnings.append("Flutter detected — the Java SSL hooks below will NOT bypass Flutter's "
                            "BoringSSL pinning. Use reFlutter or a libflutter.so native hook instead.")
        if not blocks:
            return {"script": None, "command": None, "hooks": [],
                    "note": "No mechanism with an auto-hook was detected."}
        body = "\n".join(blocks)
        # spawn-safe wrapper: when spawned, the script runs before ART loads, so
        # `Java` is not yet defined — wait for the runtime before hooking.
        script = ("/*\n * ShieldScope auto-generated Frida bypass\n * Target: %s\n"
                  " * Covers: %s\n * For authorized testing only.\n */\n"
                  "(function () {\n"
                  "  function _run() { Java.perform(function () {\n%s\n"
                  "    console.log('[ShieldScope] all hooks installed'); }); }\n"
                  "  if (typeof Java !== 'undefined' && Java.available) { _run(); return; }\n"
                  "  var _n = 0, _t = setInterval(function () {\n"
                  "    if (typeof Java !== 'undefined' && Java.available) { clearInterval(_t); _run(); }\n"
                  "    else if (++_n > 200) { clearInterval(_t); console.log('[!] Java runtime never came up'); }\n"
                  "  }, 50);\n"
                  "})();\n"
                  % (app_id, ", ".join(covered), body))
        cmd = "frida -U -f %s -l shieldscope_bypass.js" % app_id

    elif plat == "ios":
        app_id = (result.get("meta") or {}).get("bundle_id") or "<bundle.id>"
        ids = set()
        for b in ("root", "ssl"):
            for m in result.get(b, {}).get("mechanisms", []):
                ids.add(m["id"])
        parts, covered = [], []
        if any(m["category"] == "ssl" for b in ("ssl",) for m in result.get(b, {}).get("mechanisms", [])):
            parts.append(IOS_SSL); covered.append("ssl")
        if any(m["category"] == "root" for m in result.get("root", {}).get("mechanisms", [])):
            parts.append(IOS_JB); covered.append("jailbreak")
        if "ptrace-antidebug" in ids:
            parts.append(IOS_ANTIDEBUG); covered.append("anti-debug")
        if (result.get("meta") or {}).get("encrypted"):
            warnings.append("Binary is FairPlay-encrypted — decrypt (frida-ios-dump) before relying on symbol hooks.")
        if not parts:
            return {"script": None, "command": None, "hooks": [],
                    "note": "No mechanism with an auto-hook was detected."}
        script = ("/*\n * ShieldScope auto-generated Frida bypass (iOS)\n * Target: %s\n"
                  " * Covers: %s\n * For authorized testing only.\n */\n"
                  "if (ObjC.available) {\n%s\n} else { console.log('ObjC runtime unavailable'); }\n"
                  % (app_id, ", ".join(covered), "\n".join(parts)))
        cmd = "frida -U -f %s -l shieldscope_bypass.js" % app_id
    else:
        return {"script": None, "command": None, "hooks": [], "note": "Unknown platform."}

    return {"script": script, "command": cmd, "filename": "shieldscope_bypass.js",
            "hooks": covered, "warnings": warnings}

"""Unit tests for behavioral detection (smali worker) — no APK needed."""

from analyzer import detect


def _worker(smali_text, rel="com/app/x.smali", tmp_path=None):
    p = tmp_path / "x.smali"
    p.write_text(smali_text, encoding="utf-8")
    return detect._smali_worker([(str(p), rel)])


def test_guest_access_detected(tmp_path):
    smali = ('.class public Lcom/app/LoginActivity;\n'
             '.super Landroid/app/Activity;\n'
             '    const-string v1, "continueAsGuest"\n')
    _found, _tms, auth = _worker(smali, tmp_path=tmp_path)
    assert "guest-access" in auth


def test_clientside_flag_in_app_class_detected(tmp_path):
    smali = ('.class public Lcom/app/Billing;\n'
             '    invoke-virtual {p0}, Lcom/app/Billing;->isPremium()Z\n')
    _f, _t, auth = _worker(smali, tmp_path=tmp_path)
    assert "clientside-auth" in auth


def test_clientside_flag_in_library_ignored(tmp_path):
    smali = ('.class public Landroidx/compose/Foo;\n'
             '    invoke-virtual {p0}, Landroidx/compose/Foo;->isPremium()Z\n')
    _f, _t, auth = _worker(smali, tmp_path=tmp_path)
    assert "clientside-auth" not in auth


def test_trust_all_trustmanager_flagged(tmp_path):
    smali = ('.class public Lcom/app/MyTM;\n'
             '.implements Ljavax/net/ssl/X509TrustManager;\n'
             '.method public checkServerTrusted([Ljava/security/cert/X509Certificate;'
             'Ljava/lang/String;)V\n    .locals 0\n    return-void\n.end method\n')
    _f, tms, _a = _worker(smali, tmp_path=tmp_path)
    assert any(trust_all for _cls, trust_all in tms)


def test_real_trustmanager_not_trust_all(tmp_path):
    smali = ('.class public Lcom/app/MyTM;\n'
             '.implements Ljavax/net/ssl/X509TrustManager;\n'
             '.method public checkServerTrusted([Ljava/security/cert/X509Certificate;'
             'Ljava/lang/String;)V\n    .locals 1\n'
             '    new-instance v0, Ljava/security/cert/CertificateException;\n'
             '    throw v0\n.end method\n')
    _f, tms, _a = _worker(smali, tmp_path=tmp_path)
    assert tms and not tms[0][1]


def test_su_path_detected(tmp_path):
    smali = '.class Lcom/app/Root;\n    const-string v0, "/system/xbin/su"\n'
    found, _t, _a = _worker(smali, tmp_path=tmp_path)
    assert "su-path-check" in found


def test_webview_deeplink_taint_detected(tmp_path):
    smali = ('.class Lcom/app/DeepLinkActivity;\n'
             '    invoke-virtual {p0}, ...->getStringExtra(...)\n'
             '    invoke-virtual {v0, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n')
    found, _t, _a = _worker(smali, tmp_path=tmp_path)
    assert found.get("webview-taint") == "com.app.DeepLinkActivity"


def test_webview_taint_ignored_in_library(tmp_path):
    smali = ('.class Landroidx/web/Foo;\n    ->getIntent()\n'
             '    Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V\n')
    found, _t, _a = _worker(smali, tmp_path=tmp_path)
    assert "webview-taint" not in found


def test_mutable_pendingintent_detected(tmp_path):
    smali = ('.class Lcom/app/Notif;\n'
             '    invoke-static {...}, Landroid/app/PendingIntent;->getActivity(...)\n')
    found, _t, _a = _worker(smali, tmp_path=tmp_path)
    assert found.get("pendingintent-mutable") == "com.app.Notif"


def test_immutable_pendingintent_not_flagged(tmp_path):
    smali = ('.class Lcom/app/Notif;\n'
             '    const/high16 v2, 0x4000000\n'
             '    invoke-static {...}, Landroid/app/PendingIntent;->getActivity(...)\n')
    found, _t, _a = _worker(smali, tmp_path=tmp_path)
    assert "pendingintent-mutable" not in found


def test_pairip_detected_from_smali(tmp_path):
    smali = ('.class public Lcom/pairip/VMRunner;\n'
             '.method public static executeVM([B)Ljava/lang/Object;\n.end method\n')
    found, _t, _a = _worker(smali, rel="com/pairip/VMRunner.smali", tmp_path=tmp_path)
    assert "pairip" in found


def test_pairip_no_false_positive(tmp_path):
    found, _t, _a = _worker(".class Lcom/app/Normal;\n", tmp_path=tmp_path)
    assert "pairip" not in found


def test_hygiene_flags_collected(tmp_path):
    smali = ('.class Lcom/app/A;\n'
             '    invoke-static {}, Landroid/util/Log;->d(...)\n'
             '    invoke-virtual {}, ...->sendBroadcast(...)\n')
    found, _t, _a = _worker(smali, tmp_path=tmp_path)
    assert found.get("_hyg_debuglog") and found.get("_hyg_sendbroadcast")


def test_hygiene_findings_flag_absences():
    # empty hygiene dict => FLAG_SECURE + tapjacking flagged, plus debug/broadcast when present
    F = detect._build_hygiene_findings({"debuglog": "com.app.A", "sendbroadcast": "com.app.B"}, [])
    ids = {f["id"] for f in F}
    assert {"no-flag-secure", "tapjacking", "debug-logging", "broadcast-unprotected"} <= ids
    # when FLAG_SECURE + filterTouches are present, those two are NOT flagged
    F2 = detect._build_hygiene_findings({"flagsecure": "1", "filtertouches": "1"}, [])
    assert not any(f["id"] in ("no-flag-secure", "tapjacking") for f in F2)


def test_keyboard_cache_finding_from_kbcache_list():
    F = detect._build_hygiene_findings({"flagsecure": "1", "filtertouches": "1"},
                                       ["res/layout/login.xml"])
    assert any(f["id"] == "keyboard-cache" for f in F)


def test_pendingintent_severity_handles_string_target_sdk():
    # androguard returns target_sdk as a STRING — must not raise str>=int
    F = detect._build_code_findings(None, "com.app.Notif", "33")
    pi = [f for f in F if f["id"] == "pendingintent-mutable"][0]
    assert pi["severity"] == "medium"
    F2 = detect._build_code_findings(None, "com.app.Notif", "28")
    assert [f for f in F2 if f["id"] == "pendingintent-mutable"][0]["severity"] == "low"
    # None / garbage must not crash
    detect._build_code_findings(None, "com.app.Notif", None)
    detect._build_code_findings(None, "com.app.Notif", "unknown")

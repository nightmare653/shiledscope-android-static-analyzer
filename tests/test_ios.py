"""iOS detector tests (ipa behavioural string/symbol signals + URL schemes)."""
from analyzer import ipa


def test_ios_behavior_findings():
    blob = (b"...UIWebView...generalPasteboard...kSecAttrAccessibleAlwaysThisDeviceOnly..."
            b"LAContext...NSFileProtectionNone...JSPatch...")
    syms = {"_objc_release"}   # ARC present; no __stack_chk_fail -> canary missing
    F = ipa._ios_behavior_findings(blob, syms, pie=False, encrypted=False)
    ids = {f["id"] for f in F}
    assert {"ios-keychain-weak", "ios-local-auth", "ios-fileprotection-none",
            "ios-hotpatch", "ios-native-hardening"} <= ids
    nh = [f for f in F if f["id"] == "ios-native-hardening"][0]
    assert "PIE/ASLR" in nh["evidence"] and "stack-canary" in nh["evidence"]


def test_ios_native_hardening_skipped_when_encrypted():
    F = ipa._ios_behavior_findings(b"", set(), pie=False, encrypted=True)
    assert not any(f["id"] == "ios-native-hardening" for f in F)


def test_ios_url_schemes():
    F = ipa._ios_url_findings({"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp", "fb1"]}]})
    assert F and F[0]["id"] == "ios-url-scheme"
    assert "fb1" in F[0]["evidence"] and "myapp" in F[0]["evidence"]

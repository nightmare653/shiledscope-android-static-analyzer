"""
Pytest config for ShieldScope.

Two tiers:
  * unit tests (default) — pure logic, no APK / no external tools, run in ms.
  * integration tests (`-m integration`) — run the real engine against sample
    APKs; skipped automatically unless the APKs AND jadx/apktool are available.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# candidate locations for the sample APKs (env override wins)
_APK_DIRS = [
    os.environ.get("SHIELDSCOPE_TEST_APKS", ""),
    r"C:/Users/Flash/Downloads/MEmu Download",
    os.path.join(ROOT, "test apks"),
    os.path.join(ROOT, "tests", "apks"),
]


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: runs the full engine on real APKs (slow)")


def _find_apk(name):
    for d in _APK_DIRS:
        if d and os.path.isfile(os.path.join(d, name)):
            return os.path.join(d, name)
    return None


@pytest.fixture(scope="session")
def robo_apk():
    p = _find_apk("RoboForm.apk")
    if not p:
        pytest.skip("RoboForm.apk not found")
    return p


@pytest.fixture(scope="session")
def mobily_apk():
    p = _find_apk("Mobily.apk")
    if not p:
        pytest.skip("Mobily.apk not found")
    return p

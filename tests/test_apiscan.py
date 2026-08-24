"""Unit tests for endpoint classification + pentest playbooks."""

import pytest

from analyzer import apiscan


@pytest.mark.parametrize("value,is_url,expected", [
    ("/api/v1/login", False, "auth"),
    ("/oauth/token", False, "auth"),
    ("/user/profile", False, "idor"),
    ("/account/{id}/detail", False, "idor"),
    ("/store/order?oId=", False, "financial"),
    ("/payment/checkout", False, "financial"),
    ("/admin/config", False, "admin"),
    ("/documents/upload", False, "file"),
    ("/graphql", False, "graphql"),
    ("/otp/verify", False, "otp"),
    ("/search?q=", False, "search"),
])
def test_classification(value, is_url, expected):
    assert apiscan._classify(value, is_url)["category"] == expected


def test_third_party_hosts_not_flagged_sensitive():
    for url in ["https://www.google-analytics.com/collect",
                "https://x.firebaseio.com/u.json",
                "https://o1.ingest.sentry.io/123"]:
        assert apiscan._classify(url, True)["category"] == "third-party"


def test_first_party_login_is_auth():
    c = apiscan._classify("https://api.example.com/api/v1/login", True)
    assert c["category"] == "auth"
    assert c["severity"] == "high"
    assert c["tests"]           # has a playbook


def test_sensitive_endpoint_has_playbook():
    c = apiscan._classify("/store/order?oId=123", False)
    assert c["tests"] and c["payload"] and c["tool"]


def test_host_extraction():
    assert apiscan._host("https://shop.mobily.com.sa/pay/") == "shop.mobily.com.sa"

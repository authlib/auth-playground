from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
from werkzeug.middleware.proxy_fix import ProxyFix

from auth_playground import create_app


def get_redirect_uri(response):
    """Get the redirect URI sent to the identity provider."""
    return parse_qs(urlsplit(response.location).query)["redirect_uri"][0]


def test_forwarded_proto_is_ignored_by_default(test_client):
    """Test that X-Forwarded-Proto is ignored without PROXY_FIX."""
    res = test_client.get("/authorize", headers={"X-Forwarded-Proto": "https"})

    assert get_redirect_uri(res) == "http://client.test/authorize_callback"


@pytest.mark.parametrize("proxy_fix", [True])
def test_forwarded_proto_is_used_behind_a_proxy(test_client):
    """Test that the redirect URI uses the scheme forwarded by the proxy."""
    res = test_client.get("/authorize", headers={"X-Forwarded-Proto": "https"})

    assert get_redirect_uri(res) == "https://client.test/authorize_callback"


def test_forwarded_prefix_is_ignored_by_default(test_client):
    """Test that X-Forwarded-Prefix is ignored without PROXY_FIX."""
    res = test_client.get("/authorize", headers={"X-Forwarded-Prefix": "/playground"})

    assert get_redirect_uri(res) == "http://client.test/authorize_callback"


@pytest.mark.parametrize("proxy_fix", [True])
def test_forwarded_prefix_is_used_behind_a_proxy(test_client):
    """Test that the URLs start with the path prefix forwarded by the proxy."""
    res = test_client.get("/authorize", headers={"X-Forwarded-Prefix": "/playground"})

    assert get_redirect_uri(res) == "http://client.test/playground/authorize_callback"


@pytest.mark.parametrize("proxy_fix", [True])
def test_forwarded_host_is_ignored_behind_a_proxy(test_client):
    """Test that X-Forwarded-Host is never trusted."""
    res = test_client.get(
        "/authorize",
        base_url="http://app.internal",
        headers={"X-Forwarded-Host": "client.test", "X-Forwarded-Proto": "https"},
    )

    assert res.location == "https://client.test/authorize"


@pytest.mark.parametrize(
    "value,enabled",
    [
        (None, False),
        ("", False),
        ("0", False),
        ("false", False),
        ("1", True),
        (" True ", True),
    ],
)
def test_proxy_fix_values(monkeypatch, value, enabled):
    """Test the accepted PROXY_FIX values."""
    if value is None:
        monkeypatch.delenv("PROXY_FIX", raising=False)
    else:
        monkeypatch.setenv("PROXY_FIX", value)

    app = create_app()

    assert isinstance(app.wsgi_app, ProxyFix) is enabled


def test_invalid_proxy_fix(monkeypatch):
    """Test that an invalid PROXY_FIX value stops the startup."""
    monkeypatch.setenv("PROXY_FIX", "yes please")

    with pytest.raises(ValueError, match="PROXY_FIX"):
        create_app()

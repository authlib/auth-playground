import re
from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests

from auth_playground.endpoints import fetch_server_metadata


def test_fetch_server_metadata_oauth2_fallback():
    """Test fetching server metadata falls back to OAuth2 endpoint when OIDC 404."""
    with patch("requests.get") as mock_get:
        oidc_response = Mock()
        oidc_response.status_code = 404
        oidc_response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=oidc_response
        )

        oauth2_response = Mock()
        oauth2_response.json.return_value = {"issuer": "https://test.example.com"}
        oauth2_response.raise_for_status.return_value = None

        mock_get.side_effect = [oidc_response, oauth2_response]

        metadata, server_type = fetch_server_metadata("https://test.example.com")

        assert server_type == "oauth2"
        assert metadata["issuer"] == "https://test.example.com"


def test_fetch_server_metadata_raises_non_404_errors():
    """Test fetch_server_metadata raises non-404 HTTP errors."""
    with patch("requests.get") as mock_get:
        response = Mock()
        response.status_code = 500
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            response=response
        )

        mock_get.return_value = response

        with pytest.raises(requests.exceptions.HTTPError):
            fetch_server_metadata("https://test.example.com")


def test_handle_fetch_metadata_errors_connection_error(unconfigured_test_client):
    """Test handle_fetch_metadata_errors with connection error."""
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.side_effect = requests.exceptions.ConnectionError()

        res = unconfigured_test_client.get("/en/server")
        csrf_match = re.search(
            r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
        )
        csrf_token = csrf_match.group(1) if csrf_match else ""

        res = unconfigured_test_client.post(
            "/en/server",
            data={"issuer_url": "https://test.example.com", "csrf_token": csrf_token},
            follow_redirects=False,
        )

        assert b"Cannot connect" in res.data


def test_handle_fetch_metadata_errors_timeout(unconfigured_test_client):
    """Test handle_fetch_metadata_errors with timeout error."""
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.side_effect = requests.exceptions.Timeout()

        res = unconfigured_test_client.get("/en/server")
        csrf_match = re.search(
            r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
        )
        csrf_token = csrf_match.group(1) if csrf_match else ""

        res = unconfigured_test_client.post(
            "/en/server",
            data={"issuer_url": "https://test.example.com", "csrf_token": csrf_token},
            follow_redirects=False,
        )

        assert b"timeout" in res.data


def test_handle_fetch_metadata_errors_404(unconfigured_test_client):
    """Test handle_fetch_metadata_errors with 404 error."""
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        response = Mock()
        response.status_code = 404
        mock_fetch.side_effect = requests.exceptions.HTTPError(response=response)

        res = unconfigured_test_client.get("/en/server")
        csrf_match = re.search(
            r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
        )
        csrf_token = csrf_match.group(1) if csrf_match else ""

        res = unconfigured_test_client.post(
            "/en/server",
            data={"issuer_url": "https://test.example.com", "csrf_token": csrf_token},
            follow_redirects=False,
        )

        assert b"not support" in res.data


def test_handle_fetch_metadata_errors_non_404_http_error(unconfigured_test_client):
    """Test handle_fetch_metadata_errors with non-404 HTTP error."""
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        response = Mock()
        response.status_code = 500
        mock_fetch.side_effect = requests.exceptions.HTTPError(response=response)

        res = unconfigured_test_client.get("/en/server")
        csrf_match = re.search(
            r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
        )
        csrf_token = csrf_match.group(1) if csrf_match else ""

        res = unconfigured_test_client.post(
            "/en/server",
            data={"issuer_url": "https://test.example.com", "csrf_token": csrf_token},
            follow_redirects=False,
        )

        assert b"HTTP 500" in res.data


def test_handle_fetch_metadata_errors_request_exception(unconfigured_test_client):
    """Test handle_fetch_metadata_errors with generic request exception."""
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.side_effect = requests.RequestException()

        res = unconfigured_test_client.get("/en/server")
        csrf_match = re.search(
            r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
        )
        csrf_token = csrf_match.group(1) if csrf_match else ""

        res = unconfigured_test_client.post(
            "/en/server",
            data={"issuer_url": "https://test.example.com", "csrf_token": csrf_token},
            follow_redirects=False,
        )

        assert b"Failed to connect" in res.data


def test_handle_fetch_metadata_errors_value_error(unconfigured_test_client):
    """Test handle_fetch_metadata_errors with invalid JSON response."""
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.side_effect = ValueError()

        res = unconfigured_test_client.get("/en/server")
        csrf_match = re.search(
            r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
        )
        csrf_token = csrf_match.group(1) if csrf_match else ""

        res = unconfigured_test_client.post(
            "/en/server",
            data={"issuer_url": "https://test.example.com", "csrf_token": csrf_token},
            follow_redirects=False,
        )

        assert b"Invalid response" in res.data


def test_specs_endpoint_without_server_config(unconfigured_test_client):
    """Test specs endpoint redirects without server configuration."""
    res = unconfigured_test_client.get("/en/specs", follow_redirects=True)
    assert b"Provider URL" in res.data


def test_specs_endpoint_with_server_config(unconfigured_test_client):
    """Test specs endpoint displays server specifications."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
            "registration_endpoint": "https://test.example.com/oauth/register",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = unconfigured_test_client.get("/en/specs")
    assert res.status_code == 200
    assert b"Specifications" in res.data or b"specs" in res.data


def test_configure_client_refetches_metadata_when_missing(unconfigured_test_client):
    """Test configure_client refetches metadata when missing from session."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"

    with patch("auth_playground.endpoints.load_server_metadata") as mock_load:
        mock_load.return_value = (
            {
                "issuer": "https://test.example.com",
                "authorization_endpoint": "https://test.example.com/oauth/authorize",
                "token_endpoint": "https://test.example.com/oauth/token",
            },
            "oidc",
        )

        res = unconfigured_test_client.get("/en/client")

    assert res.status_code == 200
    assert mock_load.called


def test_configure_client_blocks_when_env_configured(app, iam_server, iam_client):
    """Test configure client is blocked when OAUTH_CLIENT_ID is in env."""
    app.config["OAUTH_AUTH_SERVER"] = iam_server.url
    app.config["OAUTH_CLIENT_ID"] = iam_client.client_id
    app.config["OAUTH_CLIENT_SECRET"] = iam_client.client_secret

    test_client = app.test_client()

    res = test_client.get("/en/client", follow_redirects=True)
    assert res.status_code == 200
    assert b"environment variables" in res.data


def test_playground_handles_metadata_fetch_exception(unconfigured_test_client):
    """Test playground handles exception when fetching metadata."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["oauth_config"] = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "auth_server": "https://test.example.com",
        }

    from auth_playground import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["SERVER_NAME"] = "client.test"
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["WTF_CSRF_ENABLED"] = False
    app.config["OAUTH_CLIENT_ID"] = "test-client"
    app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    app.config["OAUTH_AUTH_SERVER"] = "https://test.example.com"

    test_client = app.test_client()

    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.side_effect = Exception("Network error")

        res = test_client.get("/en/playground")

    assert res.status_code == 200

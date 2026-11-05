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


@pytest.mark.parametrize("document", [[], "metadata", None])
def test_fetch_server_metadata_rejects_non_object_documents(document):
    """Test fetch_server_metadata rejects metadata that is not a JSON object."""
    with patch("requests.get") as mock_get:
        mock_get.return_value.json.return_value = document

        with pytest.raises(requests.exceptions.InvalidJSONError):
            fetch_server_metadata("https://test.example.com")


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


def http_error(status_code):
    """Build an HTTP error with the given status code."""
    response = Mock()
    response.status_code = status_code
    return requests.exceptions.HTTPError(response=response)


@pytest.mark.parametrize(
    "exception,message",
    [
        (requests.exceptions.ConnectionError(), "Cannot connect"),
        (requests.exceptions.Timeout(), "timeout"),
        (http_error(404), "not support"),
        (http_error(500), "HTTP 500"),
        (requests.RequestException(), "Failed to connect"),
        (requests.exceptions.InvalidURL(), "Failed to connect"),
        (requests.JSONDecodeError("Expecting value", "", 0), "Invalid response"),
        (requests.exceptions.InvalidJSONError(), "Invalid response"),
        (KeyError("issuer"), "Cannot load the server metadata"),
    ],
)
def test_handle_fetch_metadata_errors(unconfigured_testapp, exception, message):
    """Test the error messages when the server metadata cannot be loaded."""
    form = unconfigured_testapp.get("/en/server").forms["server-form"]
    form["issuer_url"] = "https://test.example.com"
    with patch(
        "auth_playground.endpoints.fetch_server_metadata", side_effect=exception
    ):
        res = form.submit("discover")

    assert message in res.text


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


def test_playground_handles_metadata_fetch_exception(unconfigured_app):
    """Test playground handles exception when fetching metadata."""
    unconfigured_app.config["OAUTH_CLIENT_ID"] = "test-client"
    unconfigured_app.config["OAUTH_CLIENT_SECRET"] = "test-secret"
    unconfigured_app.config["OAUTH_AUTH_SERVER"] = "https://test.example.com"
    test_client = unconfigured_app.test_client()

    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.side_effect = Exception("Network error")

        res = test_client.get("/en/tokens", follow_redirects=True)

    assert res.status_code == 200
    mock_fetch.assert_called()


def test_specs_redirects_without_server_metadata(unconfigured_test_client):
    """Test specs page redirects when the server metadata is missing."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"

    res = unconfigured_test_client.get("/en/specs", follow_redirects=True)

    assert b"No server configured" in res.data


def test_session_redirects_unknown_tab(test_client):
    """Test that an unknown tab redirects to the tokens page."""
    res = test_client.get("/en/tokens/unknown")

    assert res.status_code == 302
    assert res.location.endswith("/en/tokens")


def test_session_redirects_to_authentication_when_logged_out(test_client):
    """Test that session tabs need a logged in user."""
    res = test_client.get("/en/tokens/current")

    assert res.status_code == 302
    assert res.location.endswith("/en/tokens/request")


def test_ui_locales_falls_back_to_unknown_locale_code(unconfigured_test_client):
    """Test that unknown UI locales are displayed with their raw code."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "ui_locales_supported": ["fr", "zz"],
        }
        sess["oauth_config"] = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "auth_server": "https://test.example.com",
        }

    res = unconfigured_test_client.get("/en/tokens/request")

    assert res.status_code == 200
    assert '<option value="fr">français</option>' in res.text
    assert '<option value="zz">zz</option>' in res.text

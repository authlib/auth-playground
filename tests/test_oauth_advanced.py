from unittest.mock import patch

from auth_playground.oauth import get_software_id
from auth_playground.oauth import get_software_version


def test_get_software_id_with_repository_url():
    """Test software ID generation from repository URL."""
    software_id = get_software_id()
    assert software_id is not None
    assert len(software_id) == 36


def test_get_software_version():
    """Test software version retrieval."""
    version = get_software_version()
    assert version is not None
    assert isinstance(version, str)


def test_dynamic_registration_success(iam_server, unconfigured_test_client, csrf_token):
    """Test dynamic registration against the identity provider."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = iam_server.url
        sess["server_metadata"] = {
            "issuer": iam_server.url,
            "authorization_endpoint": f"{iam_server.url}/oauth/authorize",
            "token_endpoint": f"{iam_server.url}/oauth/token",
            "registration_endpoint": f"{iam_server.url}/oauth/register",
        }
        sess["server_type"] = "oidc"

    res = unconfigured_test_client.post(
        "/client/dynamic-registration",
        data={"csrf_token": csrf_token(unconfigured_test_client)},
    )
    assert res.status_code == 302
    assert "/en/session" in res.location


def test_dynamic_registration_rejects_missing_csrf_token(unconfigured_test_client):
    """Test dynamic registration rejects a request without CSRF token."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "registration_endpoint": "https://test.example.com/oauth/register",
        }

    with patch("requests.post") as mock_post:
        res = unconfigured_test_client.post(
            "/client/dynamic-registration", data={}, follow_redirects=True
        )

    assert b"Invalid request" in res.data
    mock_post.assert_not_called()


def test_dynamic_registration_without_server_metadata(
    unconfigured_test_client, csrf_token
):
    """Test dynamic registration fails without server metadata."""
    res = unconfigured_test_client.post(
        "/client/dynamic-registration",
        data={"csrf_token": csrf_token(unconfigured_test_client)},
        follow_redirects=True,
    )
    assert b"Provider URL" in res.data


def test_dynamic_registration_request_exception(
    iam_server, unconfigured_test_client, csrf_token
):
    """Test dynamic registration handles request exceptions."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": iam_server.url,
            "authorization_endpoint": f"{iam_server.url}/oauth/authorize",
            "token_endpoint": f"{iam_server.url}/oauth/token",
            "registration_endpoint": "http://invalid-server.test/register",
        }
        sess["issuer_url"] = iam_server.url

    res = unconfigured_test_client.post(
        "/client/dynamic-registration",
        data={"csrf_token": csrf_token(unconfigured_test_client)},
        follow_redirects=True,
    )
    assert b"failed" in res.data


def test_dynamic_registration_with_initial_access_token(
    iam_server, unconfigured_test_client, csrf_token
):
    """Test dynamic registration with initial access token."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": iam_server.url,
            "authorization_endpoint": f"{iam_server.url}/oauth/authorize",
            "token_endpoint": f"{iam_server.url}/oauth/token",
            "registration_endpoint": f"{iam_server.url}/oauth/register",
        }
        sess["issuer_url"] = iam_server.url

    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "new-client-id",
            "client_secret": "new-client-secret",
            "registration_access_token": "reg-token",
            "registration_client_uri": f"{iam_server.url}/oauth/register/new-client",
        }
        mock_post.return_value.raise_for_status = lambda: None

        unconfigured_test_client.post(
            "/client/dynamic-registration",
            data={
                "initial_access_token": "test-token",
                "csrf_token": csrf_token(unconfigured_test_client),
            },
            follow_redirects=True,
        )

    assert mock_post.call_args[1]["headers"]["Authorization"] == "Bearer test-token"


def test_unregister_client_rejects_missing_csrf_token(test_client):
    """Test unregister client rejects a request without CSRF token."""
    with test_client.session_transaction() as sess:
        sess["registration_access_token"] = "test-token"
        sess["registration_client_uri"] = "https://test.example.com/oauth/register/123"

    with patch("requests.delete") as mock_delete:
        res = test_client.post("/unregister-client", data={}, follow_redirects=True)

    assert b"Invalid request" in res.data
    mock_delete.assert_not_called()


def test_unregister_client_without_credentials(unconfigured_test_client, csrf_token):
    """Test unregister client fails without registration credentials."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"
        sess["oauth_config"] = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "auth_server": "https://test.example.com",
        }

    res = unconfigured_test_client.post(
        "/unregister-client",
        data={"csrf_token": csrf_token(unconfigured_test_client)},
        follow_redirects=True,
    )
    assert b"credentials not found" in res.data


def test_unregister_client_request_exception(unconfigured_test_client, csrf_token):
    """Test unregister client handles request exceptions."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"
        sess["oauth_config"] = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "auth_server": "https://test.example.com",
        }
        sess["registration_access_token"] = "test-token"
        sess["registration_client_uri"] = "http://invalid-server.test/client"

    res = unconfigured_test_client.post(
        "/unregister-client",
        data={"csrf_token": csrf_token(unconfigured_test_client)},
        follow_redirects=True,
    )
    assert b"failed" in res.data


def test_unregister_client_success(unconfigured_test_client, csrf_token):
    """Test successful client unregistration."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"
        sess["oauth_config"] = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "auth_server": "https://test.example.com",
        }
        sess["registration_access_token"] = "test-token"
        sess["registration_client_uri"] = "https://test.example.com/oauth/register/123"
        sess["user"] = {"sub": "testuser"}
        sess["token"] = {"access_token": "test"}

    with patch("requests.delete") as mock_delete:
        mock_delete.return_value.raise_for_status = lambda: None

        res = unconfigured_test_client.post(
            "/unregister-client",
            data={"csrf_token": csrf_token(unconfigured_test_client)},
            follow_redirects=True,
        )

    assert b"successfully unregistered" in res.data

    with unconfigured_test_client.session_transaction() as sess:
        assert "oauth_config" not in sess
        assert "user" not in sess
        assert "token" not in sess


def test_refresh_rejects_missing_csrf_token(test_client):
    """Test refresh rejects a request without CSRF token."""
    token = {"access_token": "test-access", "refresh_token": "test-refresh"}
    with test_client.session_transaction() as sess:
        sess["token"] = token

    res = test_client.post("/refresh", data={}, follow_redirects=True)

    assert b"Invalid request" in res.data
    with test_client.session_transaction() as sess:
        assert sess["token"] == token


def test_logout_local_rejects_missing_csrf_token(test_client):
    """Test local logout rejects a request without CSRF token."""
    with test_client.session_transaction() as sess:
        sess["user"] = {"sub": "testuser"}

    res = test_client.post("/logout/local", data={}, follow_redirects=True)

    assert b"Invalid request" in res.data
    with test_client.session_transaction() as sess:
        assert sess["user"] == {"sub": "testuser"}

import re
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


def test_dynamic_registration_invalid_form(test_client):
    """Test dynamic registration with invalid form data."""
    res = test_client.post("/client/dynamic-registration", data={})
    assert res.status_code == 302
    assert "/en/client" in res.location


def test_dynamic_registration_without_server_metadata(unconfigured_test_client):
    """Test dynamic registration fails without server metadata."""
    res = unconfigured_test_client.get("/en/client")
    csrf_match = re.search(
        r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

    res = unconfigured_test_client.post(
        "/client/dynamic-registration",
        data={"csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert b"Server metadata not found" in res.data


def test_dynamic_registration_request_exception(iam_server, unconfigured_test_client):
    """Test dynamic registration handles request exceptions."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": iam_server.url,
            "authorization_endpoint": f"{iam_server.url}/oauth/authorize",
            "token_endpoint": f"{iam_server.url}/oauth/token",
            "registration_endpoint": "http://invalid-server.test/register",
        }
        sess["issuer_url"] = iam_server.url

    res = unconfigured_test_client.get("/en/client")
    csrf_match = re.search(
        r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

    res = unconfigured_test_client.post(
        "/client/dynamic-registration",
        data={"csrf_token": csrf_token},
        follow_redirects=True,
    )
    assert b"failed" in res.data


def test_dynamic_registration_with_initial_access_token(iam_server, iam_client):
    """Test dynamic registration with initial access token."""
    from auth_playground import create_app

    app = create_app()
    app.config["TESTING"] = True
    app.config["SERVER_NAME"] = "client.test"
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["WTF_CSRF_ENABLED"] = False

    test_client = app.test_client()

    with test_client.session_transaction() as sess:
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

        test_client.post(
            "/client/dynamic-registration",
            data={"initial_access_token": "test-token"},
            follow_redirects=True,
        )

    assert mock_post.call_args[1]["headers"]["Authorization"] == "Bearer test-token"


def test_unregister_client_invalid_form(test_client):
    """Test unregister client with invalid form data."""
    res = test_client.post("/unregister-client", data={})
    assert res.status_code == 302


def test_unregister_client_without_credentials(unconfigured_test_client):
    """Test unregister client fails without registration credentials."""
    res = unconfigured_test_client.get("/en/playground")
    csrf_match = re.search(
        r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

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
        "/unregister-client", data={"csrf_token": csrf_token}, follow_redirects=True
    )
    assert b"credentials not found" in res.data


def test_unregister_client_request_exception(unconfigured_test_client):
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

    res = unconfigured_test_client.get("/en/playground")
    csrf_match = re.search(
        r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

    res = unconfigured_test_client.post(
        "/unregister-client", data={"csrf_token": csrf_token}, follow_redirects=True
    )
    assert b"failed" in res.data


def test_unregister_client_success(unconfigured_test_client):
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

    res = unconfigured_test_client.get("/en/playground")
    csrf_match = re.search(
        r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

    with patch("requests.delete") as mock_delete:
        mock_delete.return_value.raise_for_status = lambda: None

        res = unconfigured_test_client.post(
            "/unregister-client", data={"csrf_token": csrf_token}, follow_redirects=True
        )

    assert b"successfully unregistered" in res.data

    with unconfigured_test_client.session_transaction() as sess:
        assert "oauth_config" not in sess
        assert "user" not in sess
        assert "token" not in sess


def test_refresh_invalid_form(test_client):
    """Test refresh token with invalid form data."""
    res = test_client.post("/refresh", data={})
    assert res.status_code == 302

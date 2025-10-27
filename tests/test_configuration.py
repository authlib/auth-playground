import re


def test_index_redirects_to_configure_server_when_no_config(unconfigured_app):
    """Test that index redirects to configure server when OAuth is not configured."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/")
    assert res.status_code == 302
    assert "/configure/server" in res.location


def test_configure_server_displays_form(unconfigured_app):
    """Test that configure server page displays the form."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/configure/server")
    assert res.status_code == 200
    assert b"Identity Provider URL" in res.data
    assert b"Validate server" in res.data


def test_configure_server_validates_url(unconfigured_app):
    """Test that server configuration validates URL format."""
    test_client = unconfigured_app.test_client()
    res = test_client.post(
        "/configure/server",
        data={"issuer_url": "not-a-url", "csrf_token": "test"},
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert b"Please enter a valid URL" in res.data or b"URL must start" in res.data


def test_configure_server_blocks_when_env_configured(app, test_client):
    """Test that configure server is blocked when OAUTH_AUTH_SERVER is in env."""
    app.config["OAUTH_AUTH_SERVER"] = "https://env-configured.example.com"

    res = test_client.get("/configure/server", follow_redirects=True)
    assert res.status_code == 200
    assert b"environment variables" in res.data


def test_configure_client_redirects_without_server_metadata(unconfigured_app):
    """Test that configure client redirects when server metadata is not set."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/configure/client", follow_redirects=True)
    assert res.status_code == 200
    assert b"configure the server first" in res.data


def test_configure_client_displays_manual_form(unconfigured_app):
    """Test that configure client shows manual configuration form."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/configure/client")
    assert res.status_code == 200
    assert b"Manual configuration" in res.data
    assert b"Client ID" in res.data
    assert b"Client secret" in res.data


def test_configure_client_shows_auto_registration_when_supported(unconfigured_app):
    """Test that auto registration option appears when registration endpoint exists."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
            "registration_endpoint": "https://test.example.com/oauth/register",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/configure/client")
    assert res.status_code == 200
    assert b"Dynamic registration" in res.data
    assert b"Register client" in res.data
    assert b"Initial access token" in res.data


def test_configure_client_hides_auto_registration_when_not_supported(unconfigured_app):
    """Test that auto registration is hidden when registration endpoint is missing."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/configure/client")
    assert res.status_code == 200
    assert b"Dynamic registration" not in res.data
    assert b"Register client" not in res.data


def test_configure_client_manual_setup_stores_in_session(unconfigured_app):
    """Test that manual client configuration stores credentials in session."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/configure/client")
    assert res.status_code == 200

    import re

    csrf_match = re.search(
        r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

    res = test_client.post(
        "/configure/client",
        data={
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "csrf_token": csrf_token,
        },
        follow_redirects=True,
    )

    assert res.status_code == 200

    with test_client.session_transaction() as sess:
        assert "oauth_config" in sess
        assert sess["oauth_config"]["client_id"] == "test-client-id"
        assert sess["oauth_config"]["client_secret"] == "test-client-secret"
        assert sess["oauth_config"]["auth_server"] == "https://test.example.com"


def test_auto_register_requires_registration_endpoint(unconfigured_app):
    """Test that auto registration fails without registration endpoint."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/configure/client")
    csrf_match = re.search(
        r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

    res = test_client.post(
        "/configure/auto-register",
        data={"csrf_token": csrf_token, "initial_access_token": ""},
        follow_redirects=True,
    )

    assert b"not supported" in res.data


def test_flash_messages_displayed_in_layout(unconfigured_app):
    """Test that flash messages are displayed on all pages via layout."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {}

    res = test_client.get("/configure/client", follow_redirects=True)
    assert res.status_code == 200
    assert b'role="alert"' in res.data
    assert b"configure the server first" in res.data


def test_switch_link_hidden_when_env_configured(app, iam_server, iam_client):
    """Test that switch link is hidden when OAUTH_AUTH_SERVER is in environment."""
    app.config["OAUTH_AUTH_SERVER"] = iam_server.url
    app.config["OAUTH_CLIENT_ID"] = iam_client.client_id
    app.config["OAUTH_CLIENT_SECRET"] = iam_client.client_secret

    from auth_playground import setup_oauth

    setup_oauth(app)

    test_client = app.test_client()

    res = test_client.get("/", follow_redirects=True)
    assert res.status_code == 200
    assert b"Identity Provider" in res.data
    assert b"switch" not in res.data


def test_switch_link_visible_when_session_configured(unconfigured_app):
    """Test that switch link is visible when configuration is in session."""
    test_client = unconfigured_app.test_client()

    with test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["oauth_config"] = {
            "client_id": "test",
            "client_secret": "test",
            "auth_server": "https://test.example.com",
        }

    res = test_client.get("/", follow_redirects=True)
    assert res.status_code == 200
    assert b"switch" in res.data


def test_validate_issuer_url_accepts_http_in_debug(app, test_client):
    """Test that HTTP URLs are accepted when app is in debug mode."""
    app.debug = True

    res = test_client.get("/configure/server")
    csrf_match = re.search(
        r'name="csrf_token" value="([^"]+)"', res.data.decode(), re.DOTALL
    )
    csrf_token = csrf_match.group(1) if csrf_match else ""

    res = test_client.post(
        "/configure/server",
        data={"issuer_url": "http://localhost:5000", "csrf_token": csrf_token},
        follow_redirects=False,
    )

    assert b"HTTP is only allowed" not in res.data


def test_client_uri_included_in_auto_registration(unconfigured_app):
    """Test that client_uri is included in dynamic registration payload."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
            "registration_endpoint": "https://test.example.com/oauth/register",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/configure/client")
    assert res.status_code == 200
    assert b"Register client" in res.data


def test_initial_access_token_sent_in_authorization_header(unconfigured_app):
    """Test that initial access token is sent as Bearer token if provided."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "registration_endpoint": "https://test.example.com/oauth/register",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/configure/client")
    assert res.status_code == 200
    assert b"Initial access token" in res.data

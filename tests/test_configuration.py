from unittest.mock import patch

from flask_webtest import TestApp


def test_root_redirects_to_default_language(unconfigured_app):
    """Test that root URL redirects to default language when no Accept-Language header."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/")
    assert res.status_code == 302
    assert res.location.startswith("/en/")


def test_root_redirects_to_browser_language(unconfigured_app):
    """Test that root URL redirects to browser preferred language."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/", headers={"Accept-Language": "fr,en;q=0.5"})
    assert res.status_code == 302
    assert res.location.startswith("/fr/")


def test_root_redirects_to_default_when_unsupported_language(unconfigured_app):
    """Test that root URL redirects to default language for unsupported browser language."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/", headers={"Accept-Language": "de,es;q=0.5"})
    assert res.status_code == 302
    assert res.location.startswith("/en/")


def test_index_redirects_to_configure_server_when_no_config(unconfigured_app):
    """Test that index redirects to configure server when OAuth is not configured."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/en/")
    assert res.status_code == 302
    assert "/en/server" in res.location


def test_configure_server_displays_form(unconfigured_app):
    """Test that configure server page displays the form."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/en/server")
    assert res.status_code == 200
    assert b"issuer_url" in res.data
    assert b"Continue" in res.data


def test_configure_server_validates_url(unconfigured_testapp):
    """Test that server configuration validates URL format."""
    form = unconfigured_testapp.get("/en/server").forms["server-form"]
    form["issuer_url"] = "not-a-url"
    res = form.submit("discover")

    assert res.status_int == 200
    assert "URL must start with http:// or https://" in res.text


def test_configure_server_blocks_when_env_configured(app, test_client):
    """Test that configure server is blocked when OAUTH_AUTH_SERVER is in env."""
    app.config["OAUTH_AUTH_SERVER"] = "https://env-configured.example.com"

    res = test_client.get("/en/server", follow_redirects=True)
    assert res.status_code == 200
    assert b"environment variables" in res.data


def test_fixed_server_without_client_shows_client_page(unconfigured_app):
    """Test that a server set in the environment works before a client is set."""
    unconfigured_app.config["OAUTH_AUTH_SERVER"] = "https://env-configured.example.com"
    test_client = unconfigured_app.test_client()

    with patch("auth_playground.endpoints.load_server_metadata"):
        res = test_client.get("/en/client")

    assert res.status_code == 200


def test_session_redirects_to_client_when_server_configured(unconfigured_app):
    """Test that the session page redirects to /client when server is configured but not client."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }

    res = test_client.get("/en/session")
    assert res.status_code == 302
    assert "/en/client" in res.location


def test_configure_client_redirects_without_server_metadata(unconfigured_app):
    """Test that configure client redirects when server metadata is not set."""
    test_client = unconfigured_app.test_client()
    res = test_client.get("/en/client", follow_redirects=True)
    assert res.status_code == 200
    assert b"Provider URL" in res.data


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

    res = test_client.get("/en/client")
    assert res.status_code == 200
    assert b"Manual configuration" in res.data
    assert b"Client ID" in res.data
    assert b"Client secret" in res.data


def test_configure_client_shows_dynamic_registration_when_supported(unconfigured_app):
    """Test that dynamic registration option appears when registration endpoint exists."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
            "registration_endpoint": "https://test.example.com/oauth/register",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/en/client")
    assert res.status_code == 200
    assert b"Dynamic registration" in res.data
    assert b"Register client" in res.data
    assert b"Initial access token" in res.data


def test_configure_client_hides_dynamic_registration_when_not_supported(
    unconfigured_app,
):
    """Test that dynamic registration is hidden when registration endpoint is missing."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.get("/en/client")
    assert res.status_code == 200
    assert b"Dynamic registration" not in res.data
    assert b"Register client" not in res.data


def test_configure_client_manual_setup_stores_in_session(unconfigured_testapp):
    """Test that manual client configuration stores credentials in session."""
    with unconfigured_testapp.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"

    form = unconfigured_testapp.get("/en/client").forms["client-form"]
    form["client_id"] = "test-client-id"
    form["client_secret"] = "test-client-secret"
    res = form.submit("save").maybe_follow()

    assert "OAuth configuration completed successfully" in res.text

    with unconfigured_testapp.session_transaction() as sess:
        assert "oauth_config" in sess
        assert sess["oauth_config"]["client_id"] == "test-client-id"
        assert sess["oauth_config"]["client_secret"] == "test-client-secret"
        assert sess["oauth_config"]["auth_server"] == "https://test.example.com"


def test_dynamic_registration_requires_registration_endpoint(
    unconfigured_app, csrf_token
):
    """Test that dynamic client registration fails without registration endpoint."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["issuer_url"] = "https://test.example.com"

    res = test_client.post(
        "/client/dynamic-registration",
        data={
            "csrf_token": csrf_token(test_client),
            "client_type": "confidential",
            "auth_method": "client_secret_basic",
            "grant_types": "authorization_code",
            "initial_access_token": "",
        },
        follow_redirects=True,
    )

    assert b"not supported" in res.data


def test_flash_messages_displayed_in_layout(unconfigured_app):
    """Test that flash messages are displayed on all pages via layout."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["server_metadata"] = {}

    res = test_client.get("/en/client", follow_redirects=True)
    assert res.status_code == 200
    assert b"Provider URL" in res.data


def test_switch_link_hidden_when_env_configured(app, iam_server, iam_client):
    """Test that switch link is hidden when OAUTH_AUTH_SERVER is in environment."""
    app.config["OAUTH_AUTH_SERVER"] = iam_server.url
    app.config["OAUTH_CLIENT_ID"] = iam_client.client_id
    app.config["OAUTH_CLIENT_SECRET"] = iam_client.client_secret

    from auth_playground import setup_oauth

    setup_oauth(app)

    test_client = app.test_client()

    res = test_client.get("/en/", follow_redirects=True)
    assert res.status_code == 200
    assert b"set by the environment" in res.data
    assert b"switch" not in res.data


def test_server_link_visible_when_session_configured(unconfigured_app):
    """Test that the server reconfigure link is visible when configuration is in session."""
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

    res = test_client.get("/en/", follow_redirects=True)
    assert res.status_code == 200
    assert b"/en/server" in res.data


def submit_server_form(testapp, issuer_url):
    """Submit the provider URL form with a mocked metadata endpoint."""
    form = testapp.get("/en/server").forms["server-form"]
    form["issuer_url"] = issuer_url
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.return_value = ({"issuer": issuer_url.rstrip("/")}, "oidc")
        return form.submit("discover"), mock_fetch


def test_validate_issuer_url_accepts_http_in_debug(unconfigured_app):
    """Test that HTTP URLs are accepted when app is in debug mode."""
    unconfigured_app.testing = False
    unconfigured_app.debug = True

    res, _ = submit_server_form(TestApp(unconfigured_app), "http://auth.example.com")

    assert res.status_int == 302
    assert "/en/client" in res.location


def test_validate_issuer_url_accepts_http_for_localhost(unconfigured_app):
    """Test that HTTP URLs are accepted for localhost even without debug mode."""
    unconfigured_app.testing = False
    unconfigured_app.debug = False
    testapp = TestApp(unconfigured_app)

    for url in [
        "http://localhost:5000",
        "http://127.0.0.1:8000",
        "http://127.0.0.2:8000",
        "http://[::1]:8000",
    ]:
        res, _ = submit_server_form(testapp, url)

        assert res.status_int == 302
        assert "/en/client" in res.location


def test_validate_issuer_url_rejects_http_in_production(unconfigured_app):
    """Test that HTTP URLs are rejected outside debug mode and localhost."""
    unconfigured_app.testing = False
    unconfigured_app.debug = False

    res, mock_fetch = submit_server_form(
        TestApp(unconfigured_app), "http://auth.example.com"
    )

    assert res.status_int == 200
    assert "HTTP is only allowed" in res.text
    mock_fetch.assert_not_called()


def test_configure_server_stores_metadata(unconfigured_testapp):
    """Test that a valid provider URL stores the server metadata in session."""
    res, mock_fetch = submit_server_form(
        unconfigured_testapp, "https://auth.example.com/"
    )

    mock_fetch.assert_called_once_with("https://auth.example.com")
    assert "Server metadata successfully loaded" in res.maybe_follow().text
    with unconfigured_testapp.session_transaction() as sess:
        assert sess["issuer_url"] == "https://auth.example.com"
        assert sess["server_metadata"] == {"issuer": "https://auth.example.com"}
        assert sess["server_type"] == "oidc"


def test_configure_server_from_url_path(unconfigured_test_client):
    """Test that a provider domain in the URL path is loaded over HTTPS."""
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.return_value = ({"issuer": "https://auth.example.com"}, "oidc")
        res = unconfigured_test_client.get("/en/server/auth.example.com/")

    mock_fetch.assert_called_once_with("https://auth.example.com")
    assert res.status_code == 302
    assert "/en/client" in res.location


def test_configure_server_from_url_path_with_scheme(unconfigured_test_client):
    """Test that a provider URL with a scheme in the URL path is kept as is."""
    with patch("auth_playground.endpoints.fetch_server_metadata") as mock_fetch:
        mock_fetch.return_value = ({"issuer": "http://localhost:5000"}, "oidc")
        res = unconfigured_test_client.get("/en/server/http://localhost:5000")

    mock_fetch.assert_called_once_with("http://localhost:5000")
    assert res.status_code == 302
    assert "/en/client" in res.location


def test_configure_server_invites_to_change_provider(unconfigured_test_client):
    """Test that the server page clears the current provider."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {"issuer": "https://test.example.com"}

    res = unconfigured_test_client.get("/en/server")

    assert b"You can now configure a different identity provider" in res.data
    with unconfigured_test_client.session_transaction() as sess:
        assert "issuer_url" not in sess
        assert "server_metadata" not in sess


def test_index_redirects_to_configure_client_without_client(unconfigured_test_client):
    """Test that index redirects to client configuration when only the server is set."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {"issuer": "https://test.example.com"}

    res = unconfigured_test_client.get("/en/")

    assert res.status_code == 302
    assert "/en/client" in res.location


def test_get_request_redirects_to_server_name(unconfigured_test_client):
    """Test that GET requests on another host redirect to SERVER_NAME."""
    res = unconfigured_test_client.get(
        "/en/server?foo=bar", base_url="http://other.test"
    )

    assert res.status_code == 302
    assert res.location == "http://client.test/en/server?foo=bar"


def test_get_request_redirects_to_server_name_without_query(unconfigured_test_client):
    """Test that the SERVER_NAME redirection works without query string."""
    res = unconfigured_test_client.get("/en/server", base_url="http://other.test")

    assert res.status_code == 302
    assert res.location == "http://client.test/en/server"


def test_post_request_on_another_host_is_rejected(unconfigured_test_client):
    """Test that POST requests on another host are rejected."""
    res = unconfigured_test_client.post("/en/server", base_url="http://other.test")

    assert res.status_code == 400
    assert b"This request should be sent to client.test" in res.data


def test_client_uri_included_in_dynamic_registration(unconfigured_app):
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

    res = test_client.get("/en/client")
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

    res = test_client.get("/en/client")
    assert res.status_code == 200
    assert b"Initial access token" in res.data


def test_unregister_button_displayed_with_registration_token(unconfigured_app):
    """Test that unregister button is displayed when registration token exists."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["oauth_config"] = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "auth_server": "https://test.example.com",
        }
        sess["registration_access_token"] = "test-registration-token"
        sess["registration_client_uri"] = (
            "https://test.example.com/oauth/register/client-123"
        )

    res = test_client.get("/en/client")
    assert res.status_code == 200
    assert b"Unregister client" in res.data


def test_unregister_button_hidden_without_registration_token(unconfigured_app):
    """Test that unregister button is hidden when no registration token exists."""
    test_client = unconfigured_app.test_client()
    with test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
            "token_endpoint": "https://test.example.com/oauth/token",
        }
        sess["oauth_config"] = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "auth_server": "https://test.example.com",
        }

    res = test_client.get("/en/client")
    assert res.status_code == 200
    assert b"Unregister client" not in res.data

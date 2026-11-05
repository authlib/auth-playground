from unittest.mock import Mock
from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
import requests

from auth_playground.oauth import get_response_error
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


def test_dynamic_registration_success(iam_server, unconfigured_testapp):
    """Test dynamic registration against the identity provider."""
    with unconfigured_testapp.session_transaction() as sess:
        sess["issuer_url"] = iam_server.url
        sess["server_metadata"] = {
            "issuer": iam_server.url,
            "authorization_endpoint": f"{iam_server.url}/oauth/authorize",
            "token_endpoint": f"{iam_server.url}/oauth/token",
            "registration_endpoint": f"{iam_server.url}/oauth/register",
        }
        sess["server_type"] = "oidc"

    res = unconfigured_testapp.get("/en/client")
    res = res.forms["dynamic-registration-form"].submit("register")

    assert res.status_int == 302
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


def test_dynamic_registration_request_exception(unconfigured_testapp):
    """Test dynamic registration handles request exceptions."""
    registration_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client")
    with patch("requests.post", side_effect=requests.ConnectionError()):
        res = res.forms["dynamic-registration-form"].submit("register").maybe_follow()

    assert "Dynamic client registration failed" in res.text


def test_dynamic_registration_with_initial_access_token(unconfigured_testapp):
    """Test dynamic registration with initial access token."""
    registration_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client")
    form = res.forms["dynamic-registration-form"]
    form["initial_access_token"] = "test-token"
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "new-client-id",
            "client_secret": "new-client-secret",
            "registration_access_token": "reg-token",
            "registration_client_uri": "https://test.example.com/oauth/register/1",
        }
        form.submit("register")

    assert mock_post.call_args[1]["headers"]["Authorization"] == "Bearer test-token"
    with unconfigured_testapp.session_transaction() as sess:
        assert sess["registration_access_token"] == "reg-token"
        assert (
            sess["registration_client_uri"]
            == "https://test.example.com/oauth/register/1"
        )


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


def test_unregister_client_request_exception(unconfigured_testapp):
    """Test unregister client handles request exceptions."""
    unregistration_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client")
    with patch("requests.delete", side_effect=requests.ConnectionError()):
        res = res.forms["unregister-form"].submit("unregister").maybe_follow()

    assert "Client unregistration failed" in res.text


def test_unregister_client_success(unconfigured_testapp):
    """Test successful client unregistration."""
    unregistration_session(unconfigured_testapp)
    with unconfigured_testapp.session_transaction() as sess:
        sess["user"] = {"sub": "testuser"}
        sess["token"] = {"access_token": "test"}

    res = unconfigured_testapp.get("/en/client")
    with patch("requests.delete"):
        res = res.forms["unregister-form"].submit("unregister").maybe_follow()

    assert "successfully unregistered" in res.text

    with unconfigured_testapp.session_transaction() as sess:
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


def response_error(json=None, json_error=False):
    """Build an HTTP error carrying a mocked response."""
    response = Mock()
    if json_error:
        response.json.side_effect = requests.JSONDecodeError("Expecting value", "", 0)
    else:
        response.json.return_value = json
    return requests.HTTPError(response=response)


@pytest.mark.parametrize(
    "exc,expected",
    [
        (requests.ConnectionError(), None),
        (response_error(json_error=True), None),
        (response_error(json=["unexpected"]), None),
        (response_error(json={}), None),
        (response_error(json={"error_description": {"en": "Bad"}}), None),
        (response_error(json={"error": "invalid_request"}), "invalid_request"),
        (
            response_error(
                json={"error": "invalid_request", "error_description": "Bad request"}
            ),
            "Bad request",
        ),
    ],
)
def test_get_response_error(exc, expected):
    """Test the error extraction from OAuth error responses."""
    assert get_response_error(exc) == expected


def unregistration_session(client):
    """Store a dynamically registered client in the session."""
    with client.session_transaction() as sess:
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


def registration_session(client, **metadata):
    """Store a provider supporting dynamic registration in the session."""
    with client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {
            "issuer": "https://test.example.com",
            "registration_endpoint": "https://test.example.com/oauth/register",
            **metadata,
        }


def test_dynamic_registration_with_rp_initiated_logout(unconfigured_testapp):
    """Test dynamic registration sends the post logout redirect URI."""
    registration_session(
        unconfigured_testapp,
        end_session_endpoint="https://test.example.com/oauth/end_session",
    )

    res = unconfigured_testapp.get("/en/client")
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "new-client-id",
            "client_secret": "new-client-secret",
        }
        res = res.forms["dynamic-registration-form"].submit("register").maybe_follow()

    payload = mock_post.call_args.kwargs["json"]
    assert payload["post_logout_redirect_uris"] == [
        "http://client.test/logout_callback"
    ]
    assert "Client successfully registered!" in res.text
    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["client_id"] == "new-client-id"
        assert sess.get("registration_access_token") is None
        assert sess.get("registration_client_uri") is None


def test_dynamic_registration_shows_provider_error(unconfigured_testapp):
    """Test dynamic registration displays the provider error."""
    registration_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client")
    with patch("requests.post") as mock_post:
        mock_post.return_value.raise_for_status.side_effect = response_error(
            json={"error_description": "Invalid redirect URI"}
        )
        res = res.forms["dynamic-registration-form"].submit("register").maybe_follow()

    assert "Dynamic client registration failed: Invalid redirect URI" in res.text


def test_dynamic_registration_invalid_json(unconfigured_testapp):
    """Test dynamic registration handles a response that is not JSON."""
    registration_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client")
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.side_effect = requests.JSONDecodeError(
            "Expecting value", "", 0
        )
        res = res.forms["dynamic-registration-form"].submit("register").maybe_follow()

    assert "Invalid JSON response from registration endpoint" in res.text


def test_unregister_client_shows_provider_error(unconfigured_testapp):
    """Test unregister client displays the provider error."""
    unregistration_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client")
    with patch("requests.delete") as mock_delete:
        mock_delete.return_value.raise_for_status.side_effect = response_error(
            json={"error": "invalid_token"}
        )
        res = res.forms["unregister-form"].submit("unregister").maybe_follow()

    assert "Client unregistration failed: invalid_token" in res.text


def check_scopes(form, scopes):
    """Check only the given scopes in the authorization form."""
    for checkbox in form.fields["scopes"]:
        # WebTest only exposes the value of a checked checkbox.
        checkbox.checked = True
        checkbox.checked = checkbox.value in scopes


def test_authorize_with_custom_parameters(testapp):
    """Test authorization request with the parameters from the form."""
    form = testapp.get("/en/session/authentication").forms["auth-params-form"]
    check_scopes(form, ["openid", "profile"])
    form["prompt"] = "consent"
    form["ui_locales"] = "fr"
    form["max_age"] = "0"
    form["acr_values"] = "urn:example:acr"
    form["login_hint"] = "user@example.com"
    form["claims"] = '{"id_token": {"email": null}}'
    res = form.submit("sign_in")

    assert res.status_int == 302
    params = parse_qs(urlsplit(res.location).query)
    assert params["scope"] == ["openid profile"]
    assert params["prompt"] == ["consent"]
    assert params["ui_locales"] == ["fr"]
    assert params["max_age"] == ["0"]
    assert params["acr_values"] == ["urn:example:acr"]
    assert params["login_hint"] == ["user@example.com"]
    assert params["claims"] == ['{"id_token": {"email": null}}']


def test_authorize_ignores_parameters_without_csrf_token(test_client):
    """Test authorization request ignores the form without CSRF token."""
    fields = ("ui_locales", "max_age", "acr_values", "login_hint", "claims")
    res = test_client.post(
        "/authorize", data={"prompt": "consent", **dict.fromkeys(fields, "")}
    )

    assert res.status_code == 302
    params = parse_qs(urlsplit(res.location).query)
    assert "prompt" not in params


def test_authorize_callback_shows_provider_error(test_client):
    """Test authorization callback displays the provider error."""
    res = test_client.get(
        "/authorize_callback?error=access_denied&error_description=Access+denied",
        follow_redirects=True,
    )

    assert b"An error happened during login: Access denied" in res.data


def logout_form(testapp):
    """Get the RP-Initiated Logout form of a logged in user."""
    with testapp.session_transaction() as sess:
        sess["user"] = {"sub": "testuser"}
        sess["token"] = {"access_token": "test-access", "id_token": "test-id-token"}

    return testapp.get("/en/session/logout").forms["logout-params-form"]


def test_logout_with_custom_parameters(testapp):
    """Test logout request with the parameters from the form."""
    form = logout_form(testapp)
    form["client_id"] = "custom-client"
    form["logout_hint"] = "user@example.com"
    form["ui_locales"] = "fr"
    res = form.submit("server_logout")

    assert res.status_int == 302
    params = parse_qs(urlsplit(res.location).query)
    assert params["id_token_hint"] == ["test-id-token"]
    assert params["client_id"] == ["custom-client"]
    assert params["post_logout_redirect_uri"] == ["http://client.test/logout_callback"]
    assert params["logout_hint"] == ["user@example.com"]
    assert params["ui_locales"] == ["fr"]


def test_logout_ignores_parameters_without_csrf_token(test_client):
    """Test logout request ignores the form without CSRF token."""
    fields = ("id_token_hint", "client_id", "post_logout_redirect_uri", "ui_locales")
    res = test_client.post(
        "/logout",
        data={"logout_hint": "user@example.com", **dict.fromkeys(fields, "")},
    )

    assert res.status_code == 302
    params = parse_qs(urlsplit(res.location).query)
    assert "logout_hint" not in params


def test_refresh_shows_provider_error(testapp):
    """Test token refresh displays the provider error."""
    with testapp.session_transaction() as sess:
        sess["token"] = {"access_token": "test-access", "refresh_token": "invalid"}

    res = testapp.get("/en/session/tokens")
    res = res.forms["refresh-form"].submit("refresh").maybe_follow()

    assert "An error happened during token refresh" in res.text


def test_authorize_with_empty_parameters(testapp):
    """Test authorization request without optional parameters."""
    form = testapp.get("/en/session/authentication").forms["auth-params-form"]
    check_scopes(form, [])
    res = form.submit("sign_in")

    assert res.status_int == 302
    params = parse_qs(urlsplit(res.location).query)
    assert params["scope"] == ["openid profile email phone address groups"]
    fields = ("prompt", "ui_locales", "max_age", "acr_values", "login_hint", "claims")
    for field in fields:
        assert field not in params


def test_logout_with_empty_parameters(testapp):
    """Test logout request without optional parameters."""
    fields = (
        "id_token_hint",
        "client_id",
        "post_logout_redirect_uri",
        "logout_hint",
        "ui_locales",
    )
    form = logout_form(testapp)
    for field in fields:
        form[field] = ""
    res = form.submit("server_logout")

    assert res.status_int == 302
    params = parse_qs(urlsplit(res.location).query)
    for field in fields:
        assert field not in params

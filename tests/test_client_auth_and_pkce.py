from types import SimpleNamespace
from unittest.mock import patch

import pytest

from auth_playground.forms import disable_for_public_client

METADATA = {
    "issuer": "https://test.example.com",
    "authorization_endpoint": "https://test.example.com/oauth/authorize",
    "token_endpoint": "https://test.example.com/oauth/token",
    "registration_endpoint": "https://test.example.com/oauth/register",
    "scopes_supported": ["openid", "profile"],
    "code_challenge_methods_supported": ["S256", "plain"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
}


@pytest.fixture(autouse=True)
def provider_metadata():
    """Serve the provider metadata without network."""
    with patch(
        "authlib.integrations.base_client.sync_app.OAuth2Mixin.load_server_metadata",
        return_value=METADATA,
    ):
        yield


def server_session(client, oauth_config=None):
    """Store a configured server, and optionally a client, in the session."""
    with client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = METADATA
        if oauth_config:
            sess["oauth_config"] = {
                "auth_server": "https://test.example.com",
                **oauth_config,
            }


def test_manual_public_client(unconfigured_testapp):
    """Test a client without secret is configured as a public client."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client").forms["client-form"]
    form["client_id"] = "public-client"
    form["token_endpoint_auth_method"] = "none"
    form.submit("save")

    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["client_secret"] is None
        assert sess["oauth_config"]["token_endpoint_auth_method"] == "none"


@pytest.mark.parametrize(
    "method,secret,message",
    [
        ("client_secret_basic", "", "needs a client secret"),
        ("none", "secret", "A public client has no secret"),
    ],
)
def test_manual_client_secret_must_match_method(
    unconfigured_testapp, method, secret, message
):
    """Test the client secret is required exactly when the method uses one."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client").forms["client-form"]
    form["client_id"] = "client"
    form["client_secret"] = secret
    form["token_endpoint_auth_method"] = method
    res = form.submit("save")

    assert message in res.text


def test_manual_client_marks_methods_not_advertised(unconfigured_testapp):
    """Test the methods the server does not advertise are labelled."""
    server_session(unconfigured_testapp)
    res = unconfigured_testapp.get("/en/client")

    assert "client_secret_post (not advertised)" in res.text
    assert "client_secret_basic (not advertised)" not in res.text


def test_dynamic_registration_public_client(unconfigured_testapp):
    """Test the registration of a public client."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client").forms["dynamic-registration-form"]
    form["client_type"] = "public"
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {"client_id": "public-client"}
        form.submit("register")

    sent = mock_post.call_args.kwargs["json"]
    assert sent["token_endpoint_auth_method"] == "none"
    assert sent["grant_types"] == ["authorization_code", "refresh_token"]
    assert sent["response_types"] == ["code"]
    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["client_secret"] is None
        assert sess["oauth_config"]["token_endpoint_auth_method"] == "none"


def test_dynamic_registration_keeps_the_method_of_the_server(unconfigured_testapp):
    """Test the method returned by the server wins over the requested one."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client").forms["dynamic-registration-form"]
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "client",
            "client_secret": "secret",
            "token_endpoint_auth_method": "client_secret_post",
        }
        form.submit("register")

    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["token_endpoint_auth_method"] == (
            "client_secret_post"
        )


def test_dynamic_registration_without_grant_types(unconfigured_testapp):
    """Test the registration needs at least one grant type."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client").forms["dynamic-registration-form"]
    for checkbox in form.fields["grant_types"]:
        checkbox.checked = False
    with patch("requests.post") as mock_post:
        res = form.submit("register").maybe_follow()

    assert "Choose at least one grant type." in res.text
    mock_post.assert_not_called()


def test_dynamic_registration_only_refresh_token(unconfigured_testapp):
    """Test no response type is registered without authorization_code."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client").forms["dynamic-registration-form"]
    form.fields["grant_types"][0].checked = False
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "c",
            "client_secret": "s",
        }
        form.submit("register")

    sent = mock_post.call_args.kwargs["json"]
    assert sent["grant_types"] == ["refresh_token"]
    assert sent["response_types"] == []


@pytest.mark.parametrize("client_type,disabled", [("public", True), ("x", False)])
def test_disable_for_public_client(client_type, disabled):
    """Test the authentication method is disabled for a public client."""
    target = SimpleNamespace(render_kw={"class": "x"})
    disable_for_public_client(None, SimpleNamespace(data=client_type), target)

    assert target.render_kw == {"class": "x", "disabled": disabled}


def test_new_client_forgets_the_previous_tokens(unconfigured_testapp):
    """Test configuring a client forgets the tokens of the previous one."""
    server_session(unconfigured_testapp, {"client_id": "old", "client_secret": "s"})
    with unconfigured_testapp.session_transaction() as sess:
        sess["user"] = {"sub": "jane"}
        sess["token"] = {"access_token": "a", "refresh_token": "r"}

    form = unconfigured_testapp.get("/en/client").forms["client-form"]
    form["client_id"] = "new"
    form["client_secret"] = "secret"
    form.submit("save")

    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["client_id"] == "new"
        assert not {"user", "token"} & set(sess)


def test_dynamic_registration_with_unsupported_method(unconfigured_testapp):
    """Test a client registered with an unsupported method is refused."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client").forms["dynamic-registration-form"]
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "client",
            "client_secret": "secret",
            "token_endpoint_auth_method": "private_key_jwt",
        }
        res = form.submit("register").maybe_follow()

    assert "private_key_jwt" in res.text
    assert "does not support" in res.text
    with unconfigured_testapp.session_transaction() as sess:
        assert "oauth_config" not in sess


def test_invalid_manual_form_keeps_the_registration_form(unconfigured_testapp):
    """Test a refused manual configuration keeps the registration defaults."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client").forms["client-form"]
    form["client_id"] = "client"
    res = form.submit("save")

    registration = res.forms["dynamic-registration-form"]
    assert [box.checked for box in registration.fields["grant_types"]] == [True, True]

from unittest.mock import patch

import pytest
import requests
from joserfc.errors import InvalidClaimError

from tests.fake_provider import server_session

PASSWORD = "correct horse battery staple"


@pytest.fixture
def password_user(iam_server):
    """Create a user with a known password."""
    return iam_server.random_user(password=PASSWORD)


def request_tokens(testapp, **fields):
    """Fill the password form and submit it."""
    res = testapp.get("/en/tokens/request?grant=password")
    form = res.forms["password-form"]
    for name, value in fields.items():
        form[name] = value
    return form.submit("request_tokens")


def test_password_grant_obtains_tokens(iam_server, iam_client, password_user, testapp):
    """Test the user's credentials give tokens.

    Canaille issues no ID token with this grant type.
    """
    res = request_tokens(
        testapp, username=password_user.user_name, password=PASSWORD
    ).follow()

    assert f"Tokens obtained for {password_user.user_name}." in res.text
    assert "<code>password</code>" in res.text
    assert "forget-tokens-form" in res.forms
    assert "/en/tokens/logout" not in res.text
    res = testapp.get("/en/tokens/request?grant=authorization_code")
    assert "Sign in again" not in res.text
    with testapp.session_transaction() as sess:
        assert sess["token"]["access_token"]
        assert sess["token_info"]["grant"] == "password"


def test_password_grant_reads_the_id_token(testapp):
    """Test the user of the ID token is signed in."""
    with (
        patch(
            "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token",
            return_value={"access_token": "a", "token_type": "Bearer", "id_token": "i"},
        ),
        patch(
            "auth_playground.oauth_client.PlaygroundOAuth2App.parse_id_token",
            return_value={"sub": "jane"},
        ) as parse,
    ):
        res = request_tokens(testapp, username="jane", password=PASSWORD).follow()

    assert parse.call_args.kwargs == {"nonce": None}
    assert "You have been successfully logged in." in res.text
    assert "Signed in as jane" in res.text


def test_password_grant_shows_a_wrong_password(
    iam_server, iam_client, password_user, testapp
):
    """Test the error of the provider is shown, without the password."""
    res = request_tokens(
        testapp, username=password_user.user_name, password="wrong password"
    )

    assert "The token request failed:" in res.text
    form = res.forms["password-form"]
    assert form["username"].value == password_user.user_name
    assert form["password"].value == ""
    with testapp.session_transaction() as sess:
        assert "token" not in sess


@pytest.mark.parametrize(
    "error, message",
    [
        (InvalidClaimError("iss"), "The ID token is not valid:"),
        (
            requests.ConnectionError("Connection refused"),
            "The signing keys of the provider could not be fetched:",
        ),
    ],
)
def test_password_grant_rejects_an_id_token_it_cannot_validate(testapp, error, message):
    """Test the tokens are not kept when the ID token cannot be validated."""
    with (
        patch(
            "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token",
            return_value={"access_token": "a", "token_type": "Bearer", "id_token": "i"},
        ),
        patch(
            "auth_playground.oauth_client.PlaygroundOAuth2App.parse_id_token",
            side_effect=error,
        ),
    ):
        res = request_tokens(testapp, username="jane", password=PASSWORD)

    assert "The tokens are not kept." in res.text
    assert message in res.text
    assert "Tokens obtained for jane." not in res.text
    assert "password-form" in res.forms
    with testapp.session_transaction() as sess:
        assert "token" not in sess


def test_password_grant_sends_the_credentials_and_the_scope(testapp):
    """Test the username, the password and the scope go to the token request."""
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token",
        return_value={"access_token": "a", "token_type": "Bearer"},
    ) as fetch:
        request_tokens(
            testapp,
            username="jane",
            password=PASSWORD,
            other_scopes="api:read",
            extra_params="resource=https://a.example",
        )

    kwargs = fetch.call_args.kwargs
    assert kwargs["grant_type"] == "password"
    assert kwargs["username"] == "jane"
    assert kwargs["password"] == PASSWORD
    assert kwargs["scope"].endswith("api:read")
    assert kwargs["body"] == "resource=https%3A%2F%2Fa.example"


def test_password_grant_needs_the_credentials(testapp):
    """Test the username and the password are required."""
    res = request_tokens(testapp)

    assert res.forms["password-form"]["username"].attrs.get("aria-invalid") == "true"
    assert res.forms["password-form"]["password"].attrs.get("aria-invalid") == "true"


@pytest.mark.parametrize("name", ["username", "password", "grant_type"])
def test_password_grant_refuses_reserved_params(testapp, name):
    """Test the extra parameters cannot override the credentials."""
    res = request_tokens(
        testapp, username="jane", password=PASSWORD, extra_params=f"{name}=x"
    )

    assert f"does not set itself: {name}" in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_password_grant_preview_leaves_out_empty_credentials(unconfigured_test_client):
    """Test the preview shows no credentials until they are typed."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.get("/en/tokens/request?grant=password")

    assert "grant_type=password" in res.text
    assert "username=" not in res.text
    assert "password=[hidden]" not in res.text
    assert 'autocomplete="new-password"' in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_password_grant_is_marked_deprecated(unconfigured_test_client):
    """Test the selector and the panel say the grant type is deprecated."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.get("/en/tokens/request?grant=password")

    assert "Password (ROPC) (deprecated, not advertised)" in res.text
    assert "advises against this grant type" in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_password_preview_updates_with_htmx(unconfigured_test_client, csrf_token):
    """Test the password request preview is rendered alone for an htmx request."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.post(
        "/token/password",
        data={
            "csrf_token": csrf_token(unconfigured_test_client),
            "username": "jane",
            "password": PASSWORD,
        },
        headers={
            "HX-Request": "true",
            "HX-Source": "article#preview",
            "HX-Target": "article#preview",
        },
    )

    assert res.status_code == 200
    assert "<html" not in res.text
    assert "&amp;username=jane" in res.text
    assert "&amp;password=[hidden]" in res.text
    assert PASSWORD not in res.text

import html
import time
from unittest.mock import patch

import pytest
import requests
from joserfc.errors import InvalidClaimError

from tests.fake_provider import server_session


def sign_in(iam_server, iam_client, user, testapp):
    """Sign the user in with the authorization code flow."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)
    res = testapp.get("/authorize")
    res = iam_server.test_client.get(res.location)
    testapp.get(res.location)


def userinfo_form(testapp):
    """Return the UserInfo form of the current tokens tab."""
    return testapp.get("/en/tokens").forms["userinfo-form"]


def get_userinfo(testapp):
    """Submit the UserInfo form of the current tokens tab."""
    return userinfo_form(testapp).submit("userinfo").maybe_follow()


def test_userinfo_shows_the_response(iam_server, iam_client, user, testapp):
    """Test the UserInfo response is shown under the tokens."""
    sign_in(iam_server, iam_client, user, testapp)

    res = get_userinfo(testapp)

    assert "Received at:" in res.text
    assert "UserInfo response" in res.text
    assert f"{iam_server.url}oauth/userinfo" in res.text
    with testapp.session_transaction() as sess:
        assert sess["userinfo"]["claims"]["sub"] == user.user_name


def test_userinfo_rejects_another_sub(iam_server, iam_client, user, testapp):
    """Test a UserInfo response for another user than the ID token is rejected."""
    sign_in(iam_server, iam_client, user, testapp)
    with testapp.session_transaction() as sess:
        sess["user"] = {**sess["user"], "sub": "someone-else"}

    res = get_userinfo(testapp)

    assert "The UserInfo sub does not match the ID token sub." in res.text
    assert "Received at:" not in res.text
    with testapp.session_transaction() as sess:
        assert "userinfo" not in sess


def test_userinfo_without_id_token(iam_server, iam_client, user, testapp):
    """Test the UserInfo response is shown when there is no ID token to compare with.

    For instance, the password grant of the provider gives no ID token.
    """
    sign_in(iam_server, iam_client, user, testapp)
    with testapp.session_transaction() as sess:
        sess["user"] = None

    res = get_userinfo(testapp)

    assert "Received at:" in res.text


def test_userinfo_sends_an_expired_token_as_it_is(
    iam_server, iam_client, user, testapp
):
    """Test the token is sent even when the client thinks it expired.

    The provider decides, and the refresh token is not used behind the scenes.
    """
    sign_in(iam_server, iam_client, user, testapp)
    with testapp.session_transaction() as sess:
        sess["token"] = {**sess["token"], "expires_at": int(time.time()) - 3600}
        token = sess["token"]

    res = get_userinfo(testapp)

    assert "Received at:" in res.text
    with testapp.session_transaction() as sess:
        assert sess["token"] == token


def test_new_tokens_forget_the_userinfo_response(iam_server, iam_client, user, testapp):
    """Test a refresh forgets the response obtained with the previous access token."""
    sign_in(iam_server, iam_client, user, testapp)
    res = get_userinfo(testapp)

    res = res.forms["refresh-form"].submit("refresh").maybe_follow()

    assert "Token successfully refreshed" in res.text
    assert "Received at:" not in res.text
    with testapp.session_transaction() as sess:
        assert "userinfo" not in sess


def test_local_logout_forgets_the_userinfo_response(
    iam_server, iam_client, user, testapp
):
    """Test forgetting the tokens also forgets the UserInfo response."""
    sign_in(iam_server, iam_client, user, testapp)
    get_userinfo(testapp)

    res = testapp.get("/en/tokens/logout")
    res.forms["logout-local-form"].submit("logout")

    with testapp.session_transaction() as sess:
        assert "userinfo" not in sess


def test_userinfo_shows_the_provider_error(iam_server, iam_client, user, testapp):
    """Test an access token refused by the provider shows an error."""
    sign_in(iam_server, iam_client, user, testapp)
    with testapp.session_transaction() as sess:
        sess["token"] = {**sess["token"], "access_token": "invalid"}

    res = get_userinfo(testapp)

    assert "An error happened during the UserInfo request" in res.text
    with testapp.session_transaction() as sess:
        assert "userinfo" not in sess


def test_userinfo_with_an_unsupported_token_type(iam_server, iam_client, user, testapp):
    """Test a token type that Authlib cannot send shows an error."""
    sign_in(iam_server, iam_client, user, testapp)
    with testapp.session_transaction() as sess:
        sess["token"] = {**sess["token"], "token_type": "DPoP"}

    res = get_userinfo(testapp)

    assert "An error happened during the UserInfo request" in res.text
    assert "Unsupported token_type" in res.text


def provider_response(status, body, headers=None):
    """Build the HTTP response the provider sends to the UserInfo request."""
    response = requests.Response()
    response.status_code = status
    response.reason = "Unauthorized" if status == 401 else "OK"
    response.url = "https://provider.test/userinfo"
    response._content = body
    response.headers.update(headers or {})
    return response


@pytest.mark.parametrize(
    "error",
    [InvalidClaimError("aud"), RuntimeError('Missing "jwks_uri" in metadata')],
)
def test_userinfo_with_an_invalid_signed_response(
    iam_server, iam_client, user, testapp, error
):
    """Test a signed response that cannot be validated shows an error."""
    sign_in(iam_server, iam_client, user, testapp)
    form = userinfo_form(testapp)

    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.userinfo",
        side_effect=error,
    ):
        res = form.submit("userinfo").maybe_follow()

    assert f"The signed response is not valid: {error}" in html.unescape(res.text)
    with testapp.session_transaction() as sess:
        assert "userinfo" not in sess


@pytest.mark.parametrize(
    "body,error",
    [
        (b"eyJhbGciOiJSUzI1NiJ9.e30.c2ln", "The response is not JSON."),
        (b'"text"', "The response is not a JSON object."),
        (b"null", "The response is not a JSON object."),
    ],
)
def test_userinfo_response_that_is_not_a_json_object(
    iam_server, iam_client, user, testapp, body, error
):
    """Test a response that is not a JSON object, like a signed response."""
    sign_in(iam_server, iam_client, user, testapp)
    form = userinfo_form(testapp)

    with patch(
        "auth_playground.oauth_client.TokenSession.send",
        return_value=provider_response(200, body),
    ):
        res = form.submit("userinfo").maybe_follow()

    assert f"An error happened during the UserInfo request: {error}" in res.text
    with testapp.session_transaction() as sess:
        assert "userinfo" not in sess


def test_userinfo_shows_the_www_authenticate_error(
    iam_server, iam_client, user, testapp
):
    """Test the error of the WWW-Authenticate header is shown (RFC 6750 §3)."""
    sign_in(iam_server, iam_client, user, testapp)
    header = 'Bearer error="insufficient_scope"'
    form = userinfo_form(testapp)

    with patch(
        "auth_playground.oauth_client.TokenSession.send",
        return_value=provider_response(401, b"", {"WWW-Authenticate": header}),
    ):
        res = form.submit("userinfo").maybe_follow()

    assert "insufficient_scope" in res.text


def test_userinfo_rejects_client_tokens(test_client, csrf_token):
    """Test tokens issued to the client itself are not sent to the UserInfo endpoint."""
    with test_client.session_transaction() as sess:
        sess["token"] = {"access_token": "test-access"}
        sess["token_info"] = {"grant": "client_credentials", "obtained_at": 0}

    res = test_client.post(
        "/userinfo",
        data={"csrf_token": csrf_token(test_client)},
        follow_redirects=True,
    )

    assert b"These tokens are not tied to a user." in res.data


def test_userinfo_rejects_missing_csrf_token(test_client):
    """Test the UserInfo request needs a CSRF token."""
    with test_client.session_transaction() as sess:
        sess["token"] = {"access_token": "test-access"}

    res = test_client.post("/userinfo", data={}, follow_redirects=True)

    assert b"Invalid request" in res.data


def test_userinfo_without_access_token(test_client, csrf_token):
    """Test the UserInfo request needs an access token."""
    res = test_client.post(
        "/userinfo",
        data={"csrf_token": csrf_token(test_client)},
        follow_redirects=True,
    )

    assert b"No access token available" in res.data


def test_userinfo_without_endpoint(provider_metadata, csrf_token, unconfigured_app):
    """Test the UserInfo request needs a UserInfo endpoint."""
    client = unconfigured_app.test_client()
    server_session(client, {"client_id": "client", "client_secret": "secret"})
    with client.session_transaction() as sess:
        sess["token"] = {"access_token": "test-access"}

    res = client.post(
        "/userinfo",
        data={"csrf_token": csrf_token(client)},
        follow_redirects=True,
    )

    assert b"The provider has no UserInfo endpoint." in res.data


@pytest.mark.parametrize(
    "grant,shown",
    [("authorization_code", True), ("client_credentials", False)],
)
def test_userinfo_button_only_for_user_tokens(test_client, grant, shown):
    """Test tokens issued to the client itself have no user to ask about."""
    with test_client.session_transaction() as sess:
        sess["token"] = {"access_token": "test-access"}
        sess["token_info"] = {"grant": grant, "obtained_at": 0}

    res = test_client.get("/en/tokens")

    assert (b"userinfo-form" in res.data) is shown


def test_userinfo_with_an_unreachable_provider(iam_server, iam_client, user, testapp):
    """Test a network failure during the UserInfo request shows an error."""
    sign_in(iam_server, iam_client, user, testapp)
    form = userinfo_form(testapp)

    with patch(
        "auth_playground.oauth_client.TokenSession.send",
        side_effect=requests.ConnectionError("Connection refused"),
    ):
        res = form.submit("userinfo").maybe_follow()

    assert (
        "An error happened during the UserInfo request: Connection refused" in res.text
    )

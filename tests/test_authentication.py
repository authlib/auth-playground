from unittest.mock import patch

import requests
from authlib.integrations.base_client import OAuthError
from joserfc.errors import InvalidClaimError


def test_index_shows_signin_when_unauthenticated(iam_server, test_client):
    """Test that unauthenticated users see signin button."""
    res = test_client.get("/en/tokens", follow_redirects=True)
    assert res.status_code == 200
    assert b"Sign in" in res.data


def test_index_shows_signup_when_server_supports_prompt_create(iam_server, test_client):
    """Test that registration option appears in prompt selector when server supports prompt=create."""
    res = test_client.get("/en/tokens", follow_redirects=True)
    assert res.status_code == 200
    assert b"Create - Registration" in res.data


def test_registration_redirects_to_iam(iam_server, iam_client, test_client):
    """Test that the authorization parameters form includes create option."""
    res = test_client.get("/en/tokens", follow_redirects=True)
    assert res.status_code == 200
    # Verify that the prompt select includes the create option
    assert b'value="create"' in res.data
    assert b"Create - Registration" in res.data


def test_login_flow_fast(iam_server, iam_client, user, test_client):
    """Test login flow using iam_server helpers."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    assert res.status_code == 302

    res = iam_server.test_client.get(res.location)
    assert res.status_code == 302

    res = test_client.get(res.location)
    assert res.status_code == 302

    with test_client.session_transaction() as sess:
        assert "user" in sess
        assert sess["user"]["sub"] == user.user_name


def test_authorize_callback_stores_user_in_session(
    iam_server, iam_client, user, test_client
):
    """Test that authorize callback stores user info in session."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    with test_client.session_transaction() as sess:
        assert "user" in sess
        assert "token" in sess
        assert "id_token" in sess["token"]
        assert sess["user"]["sub"] == user.user_name


def test_authorize_callback_rejects_an_invalid_id_token(
    iam_server, iam_client, user, test_client
):
    """Test an ID token that fails validation shows an error."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.parse_id_token",
        side_effect=InvalidClaimError("nonce"),
    ):
        res = test_client.get(res.location, follow_redirects=True)

    assert "The ID token is not valid:" in res.text
    with test_client.session_transaction() as sess:
        assert "token" not in sess


def test_authorize_callback_reports_an_unreachable_provider(
    iam_server, iam_client, user, test_client
):
    """Test a network failure during the token request shows an error."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token",
        side_effect=requests.ConnectionError("Connection refused"),
    ):
        res = test_client.get(res.location, follow_redirects=True)

    assert "An error happened during login: Connection refused" in res.text
    with test_client.session_transaction() as sess:
        assert "token" not in sess


def test_consent_redirects_with_prompt(iam_server, test_client):
    """Test that the authorization parameters form includes consent option."""
    res = test_client.get("/en/tokens", follow_redirects=True)
    assert res.status_code == 200
    # Verify that the prompt select includes the consent option
    assert b'value="consent"' in res.data
    assert b"Consent - Consent page" in res.data


def test_logout_redirects_to_end_session(iam_server, iam_client, user, test_client):
    """Test that logout redirects to end_session_endpoint."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    with test_client.session_transaction() as sess:
        assert "user" in sess
        assert "token" in sess

    res = test_client.get("/logout")
    assert res.status_code == 302
    assert "end" in res.location.lower()


def test_logout_callback_clears_session(test_client):
    """Test that logout callback clears user and token from session."""
    with test_client.session_transaction() as sess:
        sess["user"] = {"sub": "testuser"}
        sess["token"] = {"id_token": "test_token"}

    res = test_client.get("/logout_callback")
    assert res.status_code == 302

    with test_client.session_transaction() as sess:
        assert "user" not in sess
        assert "token" not in sess


def test_logout_local_clears_session_without_contacting_provider(testapp):
    """Test that local logout clears session without redirecting to provider."""
    with testapp.session_transaction() as sess:
        sess["user"] = {"sub": "testuser"}
        sess["token"] = {"id_token": "test_token", "access_token": "test_access"}

    res = testapp.get("/en/tokens/logout")
    res = res.forms["logout-local-form"].submit("logout")
    assert res.status_int == 302
    assert res.location.endswith("/tokens")

    with testapp.session_transaction() as sess:
        assert "user" not in sess
        assert "token" not in sess


def test_authenticated_user_can_access_index(iam_server, iam_client, user, test_client):
    """Test that authenticated users can access the index page."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    res = test_client.get("/en/tokens", follow_redirects=True)
    assert res.status_code == 200
    assert b"Auth Playground" in res.data


def test_login_with_prompt_login(iam_server, iam_client, user, test_client):
    """Test login with prompt=login when already logged in."""
    with test_client.session_transaction() as sess:
        sess["user"] = {"sub": user.user_name}

    res = test_client.get("/authorize")
    assert res.status_code == 302
    assert "prompt=login" in res.location


def test_tos_route(iam_server, iam_client, user, test_client):
    """Test that /tos route works and shows index template."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    res = test_client.get("/en/tos")
    assert res.status_code == 200
    assert b"Auth Playground" in res.data


def test_policy_route(iam_server, iam_client, user, test_client):
    """Test that /policy route works and shows index template."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    res = test_client.get("/en/policy")
    assert res.status_code == 200
    assert b"Auth Playground" in res.data


def test_refresh_token_form_displays_when_refresh_token_present(test_client):
    """Test that refresh token form is displayed when user has refresh token."""
    # Manually set a session with a refresh token
    with test_client.session_transaction() as sess:
        sess["token"] = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "id_token": "test_id_token",
        }
        sess["user"] = {"sub": "testuser"}

    res = test_client.get("/en/tokens", follow_redirects=True)
    assert res.status_code == 200
    assert b"Renew tokens" in res.data


def test_refresh_token_without_token_in_session(test_client, csrf_token):
    """Test that refresh fails when no refresh token in session."""
    with test_client.session_transaction() as sess:
        sess["token"] = {}

    res = test_client.post(
        "/refresh",
        data={"csrf_token": csrf_token(test_client)},
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert b"No refresh token available" in res.data


def test_refresh_token_success(iam_server, iam_client, user, testapp):
    """Test successful token refresh."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = testapp.get("/authorize")
    res = iam_server.test_client.get(res.location)
    res = testapp.get(res.location)

    with testapp.session_transaction() as sess:
        old_access_token = sess["token"]["access_token"]
        old_id_token = sess["token"].get("id_token")
        old_refresh_token = sess["token"].get("refresh_token")
        assert old_refresh_token is not None, "Refresh token should exist after login"

    res = testapp.get("/en/tokens/current")
    res = res.forms["refresh-form"].submit("refresh").maybe_follow()

    assert "Token successfully refreshed" in res.text

    with testapp.session_transaction() as sess:
        new_access_token = sess["token"]["access_token"]
        new_id_token = sess["token"].get("id_token")

        assert new_access_token != old_access_token, "Access token should be renewed"

        assert old_id_token is not None, "Old ID token should exist"
        assert new_id_token is not None, "ID token should still be present"
        assert sess["token_info"]["grant_type"] == "refresh_token"
        assert sess["token_info"]["grant"] == "authorization_code"

    res = testapp.get("/en/tokens/current")
    assert "First obtained with:" in res.text


def test_tokens_tab_shows_how_tokens_were_obtained(
    iam_server, iam_client, user, test_client
):
    """Test the tokens tab shows the grant, the PKCE method and the response."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    test_client.get(res.location)
    res = test_client.get("/en/tokens/current")

    assert "How these tokens were obtained" in res.text
    assert "<code>authorization_code</code>" in res.text
    assert "<code>client_secret_basic</code>" in res.text
    assert "<code>S256</code>" in res.text
    assert "Token response" in res.text
    with test_client.session_transaction() as sess:
        assert "userinfo" not in sess["token_info"]["response"]


def test_refresh_token_error_without_description(test_client, csrf_token):
    """Test the error code is shown when the provider gives no description."""
    with test_client.session_transaction() as sess:
        sess["token"] = {"access_token": "a", "refresh_token": "stale"}

    with patch(
        "authlib.integrations.base_client.sync_app.OAuth2Mixin.fetch_access_token",
        side_effect=OAuthError(error="invalid_grant"),
    ):
        res = test_client.post(
            "/refresh",
            data={"csrf_token": csrf_token(test_client)},
            follow_redirects=True,
        )

    assert "An error happened during token refresh: invalid_grant" in res.text


def sign_in_and_get_refresh_form(iam_server, iam_client, user, testapp):
    """Sign the user in, then return the refresh form and the tokens."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)
    res = testapp.get("/authorize")
    res = iam_server.test_client.get(res.location)
    testapp.get(res.location)
    with testapp.session_transaction() as sess:
        token = dict(sess["token"])
    return testapp.get("/en/tokens/current").forms["refresh-form"], token


def refresh_response(token):
    """Answer the refresh request with ``token``.

    The provider of the tests sends no ID token in refresh responses.
    """
    return patch(
        "authlib.integrations.base_client.sync_app.OAuth2Mixin.fetch_access_token",
        return_value=token,
    )


def test_refresh_reads_the_new_id_token(iam_server, iam_client, user, testapp):
    """Test the claims shown are those of the ID token of the refresh response."""
    form, token = sign_in_and_get_refresh_form(iam_server, iam_client, user, testapp)
    with testapp.session_transaction() as sess:
        sess["user"] = {"sub": "old"}

    with refresh_response(token):
        res = form.submit("refresh").maybe_follow()

    assert "Token successfully refreshed" in res.text
    assert "The ID token is not valid" not in res.text
    with testapp.session_transaction() as sess:
        assert sess["user"]["sub"] == user.user_name


def test_refresh_with_an_invalid_id_token(iam_server, iam_client, user, testapp):
    """Test an invalid ID token in the refresh response shows a warning.

    The new tokens are kept, but the user claims are not trusted anymore.
    """
    form, token = sign_in_and_get_refresh_form(iam_server, iam_client, user, testapp)
    new_token = {**token, "access_token": "new"}

    with (
        refresh_response(new_token),
        patch(
            "auth_playground.oauth_client.PlaygroundOAuth2App.parse_id_token",
            side_effect=InvalidClaimError("iss"),
        ),
    ):
        res = form.submit("refresh").maybe_follow()

    assert "Token successfully refreshed" in res.text
    assert "The ID token is not valid:" in res.text
    with testapp.session_transaction() as sess:
        assert sess["token"]["access_token"] == "new"
        assert sess["user"] is None


def test_refresh_without_id_token_keeps_the_user(test_client, csrf_token):
    """Test a refresh response without ID token keeps the claims of the previous one."""
    with test_client.session_transaction() as sess:
        sess["token"] = {"access_token": "a", "refresh_token": "r", "id_token": "i"}
        sess["user"] = {"sub": "testuser"}

    with patch(
        "authlib.integrations.base_client.sync_app.OAuth2Mixin.fetch_access_token",
        return_value={"access_token": "b", "token_type": "Bearer"},
    ):
        test_client.post("/refresh", data={"csrf_token": csrf_token(test_client)})

    with test_client.session_transaction() as sess:
        assert sess["user"] == {"sub": "testuser"}
        assert sess["token"]["id_token"] == "i"

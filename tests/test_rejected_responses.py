from unittest.mock import Mock

import pytest
from flask import session

from auth_playground.oauth import keep_failure
from auth_playground.pages import GRANT_FORM_DATA
from auth_playground.pages import REJECTED_RESPONSE
from tests.fake_provider import server_session


def test_a_response_that_is_not_json_is_shown_as_text(unconfigured_app):
    """Test a body the playground cannot read as JSON is shown as it is."""
    response = Mock(
        ok=False, status_code=502, reason="Bad Gateway", text="<h1>Bad Gateway</h1>"
    )
    response.json.side_effect = ValueError("Not JSON")
    response.request.method = "POST"
    response.request.url = "https://test.example.com/oauth/token"

    with unconfigured_app.test_request_context():
        keep_failure("token", "Failed", [response])

        assert session[REJECTED_RESPONSE] == {
            "kind": "token",
            "message": "Failed",
            "request": "POST https://test.example.com/oauth/token",
            "status": "502 Bad Gateway",
            "body": "<h1>Bad Gateway</h1>",
        }


def test_an_authorization_error_is_shown(unconfigured_test_client):
    """Test the error the provider sends back to the callback is shown."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    res = unconfigured_test_client.get(
        "/authorize_callback",
        query_string={"error": "login_required", "state": "unknown"},
        follow_redirects=True,
    )

    assert b"Authorization response" in res.data
    assert b"&#34;error&#34;: &#34;login_required&#34;" in res.data


def test_a_response_with_tokens_is_not_kept(unconfigured_app):
    """Test a token response is not shown when the request fails after it."""
    response = Mock(ok=True, status_code=200)
    response.json.return_value = {"access_token": "secret", "token_type": "Bearer"}

    with unconfigured_app.test_request_context():
        keep_failure("token", "Failed", [response])

        assert session[REJECTED_RESPONSE] == {"kind": "token", "message": "Failed"}


def test_the_response_keeps_its_accents(unconfigured_app):
    """Test the error of the provider is shown with its own characters."""
    response = Mock(ok=False, status_code=400, reason="Bad Request")
    response.json.return_value = {"error_description": "Mot de passe érroné"}
    response.request.method = "POST"
    response.request.url = "https://test.example.com/oauth/token"

    with unconfigured_app.test_request_context():
        keep_failure("token", "Failed", [response])

        assert "érroné" in session[REJECTED_RESPONSE]["body"]


def test_changing_the_client_forgets_the_rejected_response(unconfigured_testapp):
    """Test the response and the input of the previous client are not shown again."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    with unconfigured_testapp.session_transaction() as sess:
        sess[REJECTED_RESPONSE] = {
            "kind": "token",
            "request": "",
            "status": "",
            "body": "",
        }
        sess[GRANT_FORM_DATA] = {"grant": "password", "data": [("username", "jane")]}

    res = unconfigured_testapp.get("/en/client")
    res.forms["change-client-form"].submit("change")

    with unconfigured_testapp.session_transaction() as sess:
        assert REJECTED_RESPONSE not in sess
        assert GRANT_FORM_DATA not in sess


def failure_page(client, kind):
    """Return the tokens page after a failed request of the given kind."""
    with client.session_transaction() as sess:
        sess["token"] = {"access_token": "a", "refresh_token": "r"}
        sess["user"] = {"sub": "jane"}
        sess[REJECTED_RESPONSE] = {
            "kind": kind,
            "message": "The request failed: invalid_token",
            "request": "POST https://test.example.com/endpoint",
            "status": "401 Unauthorized",
            "body": '{"error": "invalid_token"}',
        }
    return client.get("/en/tokens").text


def test_a_refused_refresh_is_shown_in_the_refresh_card(unconfigured_test_client):
    """Test the refused refresh request is shown next to the renew button."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    text = failure_page(unconfigured_test_client, "refresh")

    refresh_card = text.split("<h3>Refresh token</h3>", 1)[1]
    assert '<header role="alert">The request failed: invalid_token</header>' in (
        refresh_card
    )
    assert "Response of the token endpoint" in refresh_card


def test_a_refused_userinfo_request_is_shown_in_its_card(unconfigured_test_client):
    """Test the refused UserInfo request is shown in the UserInfo card."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    with unconfigured_test_client.session_transaction() as sess:
        sess["server_metadata"] = {
            **sess["server_metadata"],
            "userinfo_endpoint": "https://test.example.com/oauth/userinfo",
        }

    text = failure_page(unconfigured_test_client, "userinfo")

    userinfo_card = text.split("<h3>UserInfo response</h3>", 1)[1].split("</article>")[
        0
    ]
    assert "The request failed: invalid_token" in userinfo_card
    assert "Response of the UserInfo endpoint" in userinfo_card


def test_a_failure_without_response_shows_its_message(unconfigured_test_client):
    """Test a request that got no response shows why it failed."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    with unconfigured_test_client.session_transaction() as sess:
        sess[REJECTED_RESPONSE] = {
            "kind": "token",
            "grant": "client_credentials",
            "message": "Connection refused",
        }

    res = unconfigured_test_client.get("/en/request/client_credentials")

    assert '<header role="alert">Connection refused</header>' in res.text
    assert "Response of the token endpoint" not in res.text


@pytest.mark.parametrize(
    "path", ["/en/request/password", "/en/tokens", "/en/request/authorization_code"]
)
def test_a_failure_stays_for_its_own_page(unconfigured_test_client, path):
    """Test a failure is only shown, and forgotten, by the page of its request."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    failure = {"kind": "token", "grant": "client_credentials", "message": "Refused"}
    with unconfigured_test_client.session_transaction() as sess:
        sess["token"] = {"access_token": "a"}
        sess[REJECTED_RESPONSE] = failure

    res = unconfigured_test_client.get(path)

    assert "Refused" not in res.text
    with unconfigured_test_client.session_transaction() as sess:
        assert sess[REJECTED_RESPONSE] == failure


@pytest.mark.parametrize(
    "category,role,title",
    [
        ("error", "alert", "Error:"),
        ("warning", "alert", "Warning:"),
        ("success", "status", "Success:"),
        ("info", "status", "Information:"),
    ],
)
def test_messages_have_a_role_and_a_title(
    unconfigured_test_client, category, role, title
):
    """Test a message is announced as urgent only for errors and warnings."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["_flashes"] = [(category, "Something happened")]

    res = unconfigured_test_client.get("/en/server/discover")

    assert f'<article role="{role}" data-type="{category}">' in res.text
    assert f"<strong>{title}</strong>" in res.text

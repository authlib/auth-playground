from unittest.mock import Mock

from flask import session

from auth_playground.oauth import keep_rejected_response
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
        keep_rejected_response([response])

        assert session[REJECTED_RESPONSE] == {
            "kind": "token",
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
        keep_rejected_response([response])

        assert REJECTED_RESPONSE not in session


def test_the_response_keeps_its_accents(unconfigured_app):
    """Test the error of the provider is shown with its own characters."""
    response = Mock(ok=False, status_code=400, reason="Bad Request")
    response.json.return_value = {"error_description": "Mot de passe érroné"}
    response.request.method = "POST"
    response.request.url = "https://test.example.com/oauth/token"

    with unconfigured_app.test_request_context():
        keep_rejected_response([response])

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

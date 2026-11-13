from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest

from auth_playground.forms import get_response_mode_choices


def authorization_response(iam_server, iam_client, user, test_client):
    """Sign in at the provider, and return the code and the state it sends back."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)
    res = test_client.get("/authorize")
    res = iam_server.test_client.get(res.location)
    query = parse_qs(urlsplit(res.location).query)
    return {"code": query["code"][0], "state": query["state"][0]}


@pytest.mark.parametrize(
    "metadata, label",
    [
        ({}, "form_post (not advertised)"),
        ({"response_modes_supported": ["query"]}, "form_post (not advertised)"),
        ({"response_modes_supported": ["query", "form_post"]}, "form_post"),
    ],
)
def test_form_post_is_labelled_when_not_advertised(app, metadata, label):
    """Test form_post is marked when the provider does not advertise it."""
    with (
        app.test_request_context(),
        patch("auth_playground.forms.server_metadata", return_value=metadata),
    ):
        labels = [str(choice.label) for choice in get_response_mode_choices()]

    assert labels == ["Default (query)", label]


def test_the_response_mode_is_sent(testapp):
    """Test the form_post response mode goes in the authorization request."""
    form = testapp.get("/en/request/authorization_code").forms["auth-params-form"]
    form["response_mode"] = "form_post"

    res = form.submit("sign_in")

    assert parse_qs(urlsplit(res.location).query)["response_mode"] == ["form_post"]


def test_the_response_mode_is_not_an_extra_param(testapp):
    """Test the response mode is set with its own field."""
    form = testapp.get("/en/request/authorization_code").forms["auth-params-form"]
    form["extra_params"] = "response_mode=form_post"

    res = form.submit("sign_in")

    assert res.status_int == 200
    assert "does not set itself: response_mode" in res.text


def test_a_posted_response_signs_the_user_in(iam_server, iam_client, user, test_client):
    """Test a response posted with the session cookie signs the user in."""
    response = authorization_response(iam_server, iam_client, user, test_client)

    res = test_client.post("/authorize_callback", data=response, follow_redirects=True)

    assert "Signed in as" in res.text
    with test_client.session_transaction() as sess:
        assert sess["user"]["sub"] == user.user_name


def test_a_response_posted_without_cookie_is_relayed(
    iam_server, iam_client, user, test_client, app
):
    """Test a response posted without the session cookie is posted again."""
    response = authorization_response(iam_server, iam_client, user, test_client)

    res = app.test_client().post("/authorize_callback", data=response)

    assert res.status_code == 200
    assert "Set-Cookie" not in res.headers
    assert res.headers["Cache-Control"] == "no-store"
    assert 'id="form-post-relay"' in res.text
    assert "js/form-post-relay.js" in res.text
    for name, value in {**response, "relayed": "1"}.items():
        assert f'name="{name}" value="{value}"' in res.text

    res = test_client.post(
        "/authorize_callback",
        data={**response, "relayed": "1"},
        follow_redirects=True,
    )

    assert "Signed in as" in res.text


def test_a_relayed_response_is_not_relayed_again(app):
    """Test a relayed response without session is handled, not relayed in a loop."""
    res = app.test_client().post(
        "/authorize_callback", data={"code": "c", "state": "s", "relayed": "1"}
    )

    assert res.status_code == 302
    assert 'id="form-post-relay"' not in res.text


def test_the_session_cookie_is_lax(test_client):
    """Test the session cookie has SameSite=Lax, which the relay relies on."""
    with test_client.session_transaction() as sess:
        sess["lang_code"] = "en"

    cookie = test_client.get_cookie("session", domain="client.test")
    assert cookie is not None
    assert cookie.same_site == "Lax"


def test_a_posted_error_is_shown(iam_server, iam_client, user, test_client):
    """Test an error posted by the provider is shown."""
    response = authorization_response(iam_server, iam_client, user, test_client)

    res = test_client.post(
        "/authorize_callback",
        data={
            "error": "access_denied",
            "error_description": "Access denied",
            "state": response["state"],
        },
        follow_redirects=True,
    )

    assert "An error happened during login: Access denied" in res.text
    with test_client.session_transaction() as sess:
        assert "token" not in sess

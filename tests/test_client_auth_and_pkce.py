from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.parse import urlsplit

import pytest
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from flask import g

from auth_playground.authorization import DEFAULT_SCOPE
from auth_playground.authorization import parse_extra_params
from auth_playground.forms import DynamicRegistrationForm
from auth_playground.forms import disable_for_public_client
from tests.fake_provider import METADATA
from tests.fake_provider import http_response
from tests.fake_provider import server_session

pytestmark = pytest.mark.usefixtures("provider_metadata")


def authorization_query(res):
    """Return the query parameters of the authorization redirection."""
    return parse_qs(urlsplit(res.location).query)


def test_manual_public_client(unconfigured_testapp):
    """Test a client without secret is configured as a public client."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
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
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["client_id"] = "client"
    form["client_secret"] = secret
    form["token_endpoint_auth_method"] = method
    res = form.submit("save")

    assert message in res.text


def test_manual_client_marks_methods_not_advertised(unconfigured_testapp):
    """Test the methods the server does not advertise are labelled."""
    server_session(unconfigured_testapp)
    res = unconfigured_testapp.get("/en/client/manual")

    assert "client_secret_post (not advertised)" in res.text
    assert "client_secret_basic (not advertised)" not in res.text


def test_dynamic_registration_public_client(unconfigured_testapp):
    """Test the registration of a public client."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
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
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
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
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    for checkbox in form.fields["grant_types"]:
        checkbox.checked = False
    with patch("requests.post") as mock_post:
        res = form.submit("register").maybe_follow()

    assert "Choose at least one grant type." in res.text
    mock_post.assert_not_called()


def test_dynamic_registration_grant_types_are_not_required(unconfigured_testapp):
    """Test the browser lets a grant type checkbox stay unchecked."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]

    assert all("required" not in box.attrs for box in form.fields["grant_types"])


def test_dynamic_registration_only_refresh_token(unconfigured_testapp):
    """Test no response type is registered without authorization_code."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
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


def test_authorize_uses_s256_by_default(unconfigured_test_client):
    """Test PKCE S256 is used when the server supports it."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.get("/authorize")

    query = authorization_query(res)
    with unconfigured_test_client.session_transaction() as sess:
        verifier = sess["authorization_requests"][query["state"][0]]["code_verifier"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [create_s256_code_challenge(verifier)]


@pytest.mark.parametrize("method", ["plain", ""])
def test_authorize_with_chosen_pkce(unconfigured_testapp, method):
    """Test the PKCE method chosen in the form."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    form = unconfigured_testapp.get("/en/request/authorization_code").forms[
        "auth-params-form"
    ]
    form["pkce"] = method
    res = form.submit("sign_in")

    query = authorization_query(res)
    with unconfigured_testapp.session_transaction() as sess:
        pending = sess["authorization_requests"][query["state"][0]]
    if not method:
        assert "code_challenge" not in query
        assert "code_verifier" not in pending
        return

    assert query["code_challenge_method"] == ["plain"]
    assert query["code_challenge"] == [pending["code_verifier"]]


def test_authorize_with_other_scopes_and_extra_params(unconfigured_testapp):
    """Test the other scopes and the extra parameters are sent."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    form = unconfigured_testapp.get("/en/request/authorization_code").forms[
        "auth-params-form"
    ]
    form["other_scopes"] = "offline_access openid"
    form["extra_params"] = "resource=https://api.example.com\n\naudience = api"
    res = form.submit("sign_in")

    query = authorization_query(res)
    assert query["scope"] == ["openid profile offline_access"]
    assert query["resource"] == ["https://api.example.com"]
    assert query["audience"] == ["api"]


@pytest.mark.parametrize(
    "field,value,message",
    [
        ("extra_params", "state=x", "state"),
        ("extra_params", "no separator", "no separator"),
        ("claims", "[1, 2]", "Claims must be a JSON object."),
        ("claims", "not json", "Claims must be a JSON object."),
    ],
)
def test_authorize_refuses_invalid_parameters(
    unconfigured_testapp, field, value, message
):
    """Test the authorization request is not sent with invalid parameters."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    form = unconfigured_testapp.get("/en/request/authorization_code").forms[
        "auth-params-form"
    ]
    form[field] = value
    res = form.submit("sign_in")

    assert res.status_int == 200
    assert message in res.text


def test_parse_extra_params():
    """Test the parsing of the extra parameters."""
    pairs, errors = parse_extra_params("a=1\n=2\nb\nnonce=3\nc = 4 ")

    assert pairs == [("a", "1"), ("c", "4")]
    assert errors == ["=2", "b", "nonce"]


def test_preview_shows_the_authorization_request(unconfigured_test_client):
    """Test the preview of the authorization request on the page."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.get("/en/request/authorization_code")

    assert "GET https://test.example.com/oauth/authorize" in res.text
    assert "code_challenge_method=S256" in res.text
    assert "nonce=[generated]" in res.text


def test_preview_updates_with_htmx(unconfigured_test_client, csrf_token):
    """Test the preview is rendered alone for an htmx request."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.post(
        "/authorize",
        data={
            "csrf_token": csrf_token(unconfigured_test_client),
            "pkce": "plain",
            "scopes": "profile",
            "login_hint": "jane",
        },
        headers={
            "HX-Request": "true",
            "HX-Source": "article#preview",
            "HX-Target": "article#preview",
        },
    )

    assert res.status_code == 200
    assert "<html" not in res.text
    assert "login_hint=jane" in res.text
    assert "code_challenge_method=plain" in res.text
    assert "nonce" not in res.text


def test_new_client_forgets_the_previous_tokens(unconfigured_testapp):
    """Test changing the client forgets the tokens of the previous one."""
    server_session(unconfigured_testapp, {"client_id": "old", "client_secret": "s"})
    with unconfigured_testapp.session_transaction() as sess:
        sess["user"] = {"sub": "jane"}
        sess["token"] = {"access_token": "a", "refresh_token": "r"}
        sess["token_info"] = {"grant_type": "authorization_code"}

    res = unconfigured_testapp.get("/en/client")
    assert "client-form" not in res.forms
    res = res.forms["change-client-form"].submit("change").follow()
    assert "Choose a configuration method" in res.text
    with unconfigured_testapp.session_transaction() as sess:
        assert "oauth_config" not in sess
        assert not {"user", "token", "token_info"} & set(sess)

    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["client_id"] = "new"
    form["client_secret"] = "secret"
    form.submit("save")

    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["client_id"] == "new"


def test_authorization_requests_are_kept_by_state(unconfigured_test_client):
    """Test each authorization request keeps its own PKCE verifier."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    states = [
        authorization_query(unconfigured_test_client.get("/authorize"))["state"][0]
        for _ in range(7)
    ]

    with unconfigured_test_client.session_transaction() as sess:
        pending = sess["authorization_requests"]
    assert list(pending) == states[-5:]
    assert len({request["code_verifier"] for request in pending.values()}) == 5


def test_callback_sends_the_verifier_of_its_state(unconfigured_test_client):
    """Test the callback uses the PKCE verifier of its own request."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    first = authorization_query(unconfigured_test_client.get("/authorize"))
    unconfigured_test_client.get("/authorize")
    with unconfigured_test_client.session_transaction() as sess:
        verifier = sess["authorization_requests"][first["state"][0]]["code_verifier"]

    with patch(
        "authlib.integrations.flask_client.apps.FlaskOAuth2App.authorize_access_token",
        return_value={"access_token": "a", "token_type": "Bearer"},
    ) as mock_token:
        unconfigured_test_client.get(
            "/authorize_callback",
            query_string={"code": "x", "state": first["state"][0]},
        )

    assert mock_token.call_args.kwargs["code_verifier"] == verifier
    with unconfigured_test_client.session_transaction() as sess:
        assert first["state"][0] not in sess["authorization_requests"]
        assert sess["token_info"]["pkce"] == "S256"


def test_repeated_extra_params_are_all_sent(unconfigured_testapp):
    """Test an extra parameter given on several lines is sent several times."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    form = unconfigured_testapp.get("/en/request/authorization_code").forms[
        "auth-params-form"
    ]
    form["extra_params"] = "resource=https://a.example\nresource=https://b.example"
    res = form.submit("sign_in")

    assert authorization_query(res)["resource"] == [
        "https://a.example",
        "https://b.example",
    ]


def test_preview_lists_repeated_extra_params(unconfigured_test_client, csrf_token):
    """Test the preview shows every value of a repeated extra parameter."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.post(
        "/authorize",
        data={
            "csrf_token": csrf_token(unconfigured_test_client),
            "extra_params": "resource=https://a.example\nresource=https://b.example",
        },
        headers={
            "HX-Request": "true",
            "HX-Source": "article#preview",
            "HX-Target": "article#preview",
        },
    )

    assert "resource=https://a.example" in res.text
    assert "resource=https://b.example" in res.text


def test_authorize_without_scope_sends_the_default_scope(unconfigured_testapp):
    """Test the default scope is sent and shown when no scope is chosen."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    page = unconfigured_testapp.get("/en/request/authorization_code")
    form = page.forms["auth-params-form"]
    for checkbox in form.fields["scopes"]:
        checkbox.checked = False
    res = form.submit("sign_in")

    assert authorization_query(res)["scope"] == [DEFAULT_SCOPE]


@pytest.mark.parametrize("name", ["url", "uri", "code_verifier"])
def test_authorize_refuses_authlib_argument_names(unconfigured_testapp, name):
    """Test the extra parameters cannot use the names of Authlib arguments."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    form = unconfigured_testapp.get("/en/request/authorization_code").forms[
        "auth-params-form"
    ]
    form["extra_params"] = f"{name}=x"
    res = form.submit("sign_in")

    assert res.status_int == 200
    assert "does not set itself" in res.text


def test_dynamic_registration_with_unsupported_method(unconfigured_testapp):
    """Test a client registered with an unsupported method is refused."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    with patch("requests.post") as mock_post:
        mock_post.return_value = http_response(
            201,
            json={
                "client_id": "client",
                "client_secret": "secret",
                "token_endpoint_auth_method": "tls_client_auth",
            },
            url="https://test.example.com/oauth/register",
        )
        res = form.submit("register").maybe_follow()

    assert "tls_client_auth" in res.text
    assert "does not support" in res.text
    with unconfigured_testapp.session_transaction() as sess:
        assert "oauth_config" not in sess


@pytest.mark.parametrize(
    "method,expected", [("none", "S256"), ("client_secret_basic", "")]
)
def test_pkce_default_without_advertised_methods(
    unconfigured_test_client, method, expected
):
    """Test a public client uses S256 even when the server advertises nothing."""
    metadata = {**METADATA}
    del metadata["code_challenge_methods_supported"]
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = metadata
        sess["oauth_config"] = {
            "client_id": "c",
            "client_secret": None if method == "none" else "s",
            "auth_server": "https://test.example.com",
            "token_endpoint_auth_method": method,
        }

    query = authorization_query(unconfigured_test_client.get("/authorize"))

    assert query.get("code_challenge_method", [""]) == [expected]


def test_invalid_field_is_marked_for_blades(unconfigured_testapp):
    """Test an invalid field gets aria-invalid and its message right after it."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    form = unconfigured_testapp.get("/en/request/authorization_code").forms[
        "auth-params-form"
    ]
    form["claims"] = "[1]"
    res = form.submit("sign_in")

    assert 'aria-invalid="true"' in res.text
    assert 'aria-describedby="claims-error"' in res.text
    assert '</textarea>\n            <small id="claims-error">' in res.text


def test_invalid_checkbox_list_is_marked_for_blades(unconfigured_app):
    """Test an invalid list of checkboxes marks its fieldset as invalid."""
    with unconfigured_app.test_request_context():
        g.server_config = None
        form = DynamicRegistrationForm(formdata=None)
        form.grant_types.errors = ["Choose at least one grant type."]
        html = str(form.grant_types())

    assert '<fieldset aria-invalid="true" aria-describedby="grant_types-error">' in html
    assert '</fieldset>\n        <small id="grant_types-error">' in html


def test_htmx_partial_uses_the_browsing_language(unconfigured_test_client, csrf_token):
    """Test a route without language prefix answers in the session language."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    unconfigured_test_client.get("/fr/request")
    res = unconfigured_test_client.post(
        "/authorize",
        data={"csrf_token": csrf_token(unconfigured_test_client), "max_age": "-1"},
        headers={
            "HX-Request": "true",
            "HX-Source": "input#max_age",
            "HX-Target": "div#wrap-max_age",
        },
    )

    assert "Âge maximum (secondes)" in res.text
    assert "<html" not in res.text


def test_redirect_flash_uses_the_browsing_language(
    unconfigured_test_client, csrf_token
):
    """Test a flash message from a route without prefix is translated."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    unconfigured_test_client.get("/fr/request")
    res = unconfigured_test_client.post(
        "/refresh",
        data={"csrf_token": csrf_token(unconfigured_test_client)},
        follow_redirects=True,
    )

    assert "Aucun jeton de rafraîchissement disponible" in res.text

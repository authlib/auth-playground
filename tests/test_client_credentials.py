from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests
from authlib.integrations.base_client import OAuthError

from auth_playground.grants import GRANTS
from auth_playground.oauth_client import TokenSession
from auth_playground.pages import GRANT_FORMS
from auth_playground.preview import RequestPreview
from auth_playground.token_request import client_auth_preview
from tests.fake_provider import server_session


def request_tokens(testapp, **fields):
    """Fill the client credentials form and submit it."""
    res = testapp.get("/en/request/client_credentials")
    form = res.forms["client-credentials-form"]
    for name, value in fields.items():
        form[name] = value
    return form.submit("request_tokens")


def test_client_credentials_obtains_tokens(iam_server, iam_client, testapp):
    """Test the client obtains tokens for itself from the provider."""
    res = request_tokens(testapp).follow()

    assert "The client obtained tokens." in res.text
    assert "<code>client_credentials</code>" in res.text
    assert "there are no user claims to show" in res.text
    with testapp.session_transaction() as sess:
        assert sess["token"]["access_token"]
        assert sess["token_info"]["grant_type"] == "client_credentials"
        assert sess["token_info"]["requested_scope"] is None
        assert "user" not in sess


def test_client_credentials_replaces_the_user_tokens(iam_server, iam_client, testapp):
    """Test the tokens of the client replace the tokens of the user."""
    with testapp.session_transaction() as sess:
        sess["user"] = {"sub": "jane"}
        sess["token"] = {"access_token": "a", "id_token": "i", "refresh_token": "r"}

    request_tokens(testapp)

    with testapp.session_transaction() as sess:
        assert "user" not in sess
        assert sess["token"]["access_token"] != "a"
        assert sess["token"]["id_token"] is None


def test_client_credentials_sends_scope_and_extra_params(testapp):
    """Test the scope and the extra parameters go to the token request."""
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token",
        return_value={"access_token": "a", "token_type": "Bearer"},
    ) as fetch:
        request_tokens(
            testapp,
            other_scopes="api:read api:write",
            extra_params="resource=https://a.example\nresource=https://b.example",
        )

    kwargs = fetch.call_args.kwargs
    assert kwargs.pop("hooks")
    assert kwargs == {
        "grant_type": "client_credentials",
        "scope": "api:read api:write",
        "body": "resource=https%3A%2F%2Fa.example&resource=https%3A%2F%2Fb.example",
    }


def test_client_credentials_shows_the_provider_error(testapp):
    """Test the error of the provider is shown with the form."""
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token",
        side_effect=OAuthError(error="unauthorized_client", description="Nope"),
    ):
        res = request_tokens(testapp, other_scopes="api:read").follow()

    assert "The token request failed: Nope" in res.text
    assert res.forms["client-credentials-form"]["other_scopes"].value == "api:read"


@pytest.mark.parametrize(
    "error,message",
    [
        (requests.ConnectionError("Connection refused"), "Connection refused"),
        (ValueError("Not JSON"), "Not JSON"),
    ],
)
def test_client_credentials_shows_request_errors(testapp, error, message):
    """Test a failure to reach or read the token endpoint is shown with the form."""
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token",
        side_effect=error,
    ):
        res = request_tokens(testapp).follow()

    assert f"The token request failed: {message}" in res.text
    assert "client-credentials-form" in res.forms


def test_client_credentials_keeps_pending_authorizations(
    iam_server, iam_client, testapp
):
    """Test a sign-in started in another tab still completes."""
    with testapp.session_transaction() as sess:
        sess["authorization_requests"] = {"state": {"code_verifier": "v"}}

    request_tokens(testapp)

    with testapp.session_transaction() as sess:
        assert sess["authorization_requests"] == {"state": {"code_verifier": "v"}}


def test_client_tokens_hide_the_user_parts(iam_server, iam_client, testapp):
    """Test the pages do not talk about a user for client credentials tokens."""
    request_tokens(testapp)

    res = testapp.get("/en/tokens/logout")
    assert res.location.endswith("/en/tokens")
    res = testapp.get("/en/request/authorization_code")
    assert "Sign in again" not in res.text
    res = testapp.get("/en/tokens")
    assert "on behalf of the client" in res.text
    assert "Client tokens" in res.text
    assert "/en/tokens/logout" not in res.text

    res = res.forms["forget-tokens-form"].submit().maybe_follow()
    assert "The tokens were forgotten" in res.text
    with testapp.session_transaction() as sess:
        assert "token" not in sess


def test_client_credentials_refuses_reserved_params(testapp):
    """Test the extra parameters cannot override the parameters of the request."""
    res = request_tokens(testapp, extra_params="grant_type=password")

    assert "does not set itself: grant_type" in res.text
    with testapp.session_transaction() as sess:
        assert "token" not in sess


def test_token_session_sends_repeated_params():
    """Test every value of a repeated parameter is sent."""
    client = TokenSession("client", "secret")
    response = Mock(status_code=200)
    response.json.return_value = {"access_token": "a", "token_type": "Bearer"}
    with patch.object(client, "post", return_value=response) as post:
        client.fetch_token(
            "https://test.example.com/oauth/token",
            grant_type="client_credentials",
            body="resource=a&resource=b",
        )

    assert post.call_args.kwargs["data"] == [
        ("resource", "a"),
        ("resource", "b"),
        ("grant_type", "client_credentials"),
    ]


def test_request_preview_lines():
    """Test a GET request shows a query string and a POST request a body."""
    get = RequestPreview("GET", "https://a.example", [("a", "1"), ("b", "2")])
    post = RequestPreview(
        "POST", "https://a.example", [("a", "1"), ("b", "2")], [("H", "v")]
    )

    assert get.lines() == ["GET https://a.example", "  ?a=1", "  &b=2"]
    assert post.lines() == ["POST https://a.example", "H: v", "", "a=1", "&b=2"]


@pytest.mark.parametrize(
    "method,headers,params",
    [
        ("client_secret_basic", [("Authorization", "Basic [hidden]")], []),
        ("client_secret_post", [], [("client_id", "c"), ("client_secret", "[hidden]")]),
        (
            "client_secret_jwt",
            [],
            [
                (
                    "client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                ),
                ("client_assertion", "[generated]"),
            ],
        ),
        ("none", [], [("client_id", "c")]),
    ],
)
def test_client_auth_preview(method, headers, params):
    """Test the preview shows how the client authenticates, without its secret."""
    assert client_auth_preview(method, "c") == (headers, params)


@pytest.mark.usefixtures("provider_metadata")
def test_preview_shows_the_token_request(unconfigured_test_client):
    """Test the preview of the client credentials request on the page."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.get("/en/request/client_credentials")

    assert "POST https://test.example.com/oauth/token" in res.text
    assert "Accept: application/json" in res.text
    assert "Authorization: Basic [hidden]" in res.text
    assert "grant_type=client_credentials" in res.text
    assert "scope=" not in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_token_preview_updates_with_htmx(unconfigured_test_client, csrf_token):
    """Test the token request preview is rendered alone for an htmx request."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.post(
        "/token/client-credentials",
        data={
            "csrf_token": csrf_token(unconfigured_test_client),
            "other_scopes": "api:read",
        },
        headers={
            "HX-Request": "true",
            "HX-Source": "article#preview",
            "HX-Target": "article#preview",
        },
    )

    assert res.status_code == 200
    assert "<html" not in res.text
    assert "&amp;scope=api:read" in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_grants_not_advertised_are_marked(unconfigured_test_client):
    """Test the grants missing from grant_types_supported are labelled and warned."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_test_client.get("/en/request")
    assert '<small class="marks">Not advertised</small>' in res.text

    res = unconfigured_test_client.get("/en/request/client_credentials")
    assert "does not advertise the Client credentials grant type" in res.text
    assert "for confidential clients" not in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_client_credentials_warns_a_public_client(unconfigured_test_client):
    """Test a public client is warned that the grant needs a confidential client."""
    server_session(
        unconfigured_test_client,
        {"client_id": "c", "token_endpoint_auth_method": "none"},
    )
    res = unconfigured_test_client.get("/en/request/client_credentials")

    assert "for confidential clients" in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_the_grant_of_the_current_tokens_is_marked(unconfigured_testapp):
    """Test the choice of grant types says which one gave the current tokens."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    res = unconfigured_testapp.get("/en/request")
    assert "It gave the current tokens." not in res.text

    with unconfigured_testapp.session_transaction() as sess:
        sess["token"] = {"access_token": "a"}
        sess["token_info"] = {
            "grant_type": "refresh_token",
            "grant": "client_credentials",
        }
    res = unconfigured_testapp.get("/en/request")
    card = res.text.split("<h4>Client credentials</h4>", 1)[1].split("</article>")[0]
    assert "It gave the current tokens." in card


def test_an_unknown_grant_type_shows_the_choice(unconfigured_test_client):
    """Test an unknown grant type in the URL leads to the choice of grant types."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    res = unconfigured_test_client.get("/en/request/unknown")

    assert res.location.endswith("/en/request")


def test_every_grant_has_a_form_and_a_template(app):
    """Test each grant type of the selector can be rendered."""
    for grant in GRANTS:
        assert grant.name in GRANT_FORMS
        app.jinja_env.get_template(f"_grant_{grant.name}.html")


def test_client_credentials_refuses_a_missing_csrf_token(app):
    """Test a request without CSRF token is refused."""
    app.config["WTF_CSRF_ENABLED"] = True
    res = app.test_client().post("/token/client-credentials", data={})

    assert "Invalid request" in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_client_credentials_needs_a_token_endpoint(unconfigured_testapp):
    """Test a provider without token endpoint is reported before any request."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    with unconfigured_testapp.session_transaction() as sess:
        sess["server_metadata"] = {**sess["server_metadata"], "token_endpoint": None}

    res = request_tokens(unconfigured_testapp).follow()

    assert "The provider has no token endpoint." in res.text


def test_client_credentials_shows_http_errors(testapp):
    """Test an HTTP error without OAuth error body is shown with the form."""
    response = Mock(status_code=502)
    response.json.side_effect = requests.JSONDecodeError("Expecting value", "", 0)
    error = requests.HTTPError("502 Server Error: Bad Gateway", response=response)
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token",
        side_effect=error,
    ):
        res = request_tokens(testapp).follow()

    assert "The token request failed: 502 Server Error: Bad Gateway" in res.text


def test_token_session_runs_the_response_hooks():
    """Test the access token response hooks still run."""
    client = TokenSession("client", "secret")
    response = Mock(status_code=200)
    response.json.return_value = {"access_token": "a", "token_type": "Bearer"}
    hook = Mock(side_effect=lambda resp: resp)
    client.register_compliance_hook("access_token_response", hook)
    with patch.object(client, "post", return_value=response):
        client.fetch_token("https://test.example.com/oauth/token", grant_type="x")

    hook.assert_called_once_with(response)


def test_token_session_keeps_get_token_requests():
    """Test a GET token request goes through Authlib unchanged."""
    client = TokenSession("client", "secret")
    response = Mock(status_code=200)
    response.json.return_value = {"access_token": "a", "token_type": "Bearer"}
    with patch.object(client, "request", return_value=response) as request:
        client.fetch_token(
            "https://test.example.com/oauth/token", method="GET", grant_type="x"
        )

    assert request.call_args.args[0] == "GET"
    assert "grant_type=x" in request.call_args.args[1]

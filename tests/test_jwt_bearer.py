import base64
import json
import time
from unittest.mock import patch

import pytest
import requests
from joserfc import jwt
from joserfc.errors import InvalidClaimError
from joserfc.errors import JoseError
from joserfc.jwk import OctKey

from auth_playground.client_key import generate_key
from auth_playground.client_key import load_key
from auth_playground.grants import JWT_BEARER
from tests.fake_provider import server_session

SECRET = "a client secret that is long enough"

FETCH = "auth_playground.oauth_client.PlaygroundOAuth2App.fetch_access_token"
TOKEN = {"access_token": "a", "token_type": "Bearer"}


def unsigned_jwt(claims, header=None):
    """Return a JWT with the claims, signed with a throwaway key."""
    return jwt.encode(
        header or {"alg": "HS256"}, claims, OctKey.import_key("throwaway key " * 4)
    )


@pytest.fixture
def secret_client(unconfigured_testapp, provider_metadata):
    """Configure a client that has a secret."""
    server_session(
        unconfigured_testapp, {"client_id": "client", "client_secret": SECRET}
    )
    return unconfigured_testapp


@pytest.fixture
def client_key():
    """Return a generated client key."""
    return generate_key("ES256")


@pytest.fixture
def key_client(unconfigured_testapp, provider_metadata, client_key):
    """Configure a private_key_jwt client."""
    server_session(
        unconfigured_testapp,
        {
            "client_id": "client",
            "token_endpoint_auth_method": "private_key_jwt",
            "client_key": client_key,
            "token_endpoint_auth_signing_alg": "ES256",
        },
    )
    return unconfigured_testapp


def jwt_bearer_form(testapp):
    """Return the JWT bearer form of the tokens page."""
    return testapp.get("/en/request/jwt_bearer").forms["jwt-bearer-form"]


def request_tokens(testapp, token=None, **fields):
    """Fill the JWT bearer form, submit it, and return the response and the call."""
    form = jwt_bearer_form(testapp)
    for name, value in fields.items():
        form[name] = value
    with patch(FETCH, return_value=token or TOKEN) as fetch:
        res = form.submit("request_tokens")
    return res, fetch


def test_secret_client_signs_the_assertion_with_its_secret(secret_client):
    """Test the assertion is a JWT signed with the client secret."""
    res, fetch = request_tokens(
        secret_client,
        subject="jane",
        lifetime="120",
        extra_claims='{"act": {"sub": "admin"}}',
        other_scopes="api:read",
    )

    kwargs = fetch.call_args.kwargs
    assert kwargs["grant_type"] == JWT_BEARER
    assert kwargs["scope"].endswith("api:read")
    token = jwt.decode(kwargs["assertion"], OctKey.import_key(SECRET))
    assert token.header == {"typ": "JWT", "alg": "HS256"}
    assert token.claims["iss"] == "client"
    assert token.claims["sub"] == "jane"
    assert token.claims["aud"] == "https://test.example.com"
    assert token.claims["exp"] - token.claims["iat"] == 120
    assert token.claims["act"] == {"sub": "admin"}
    assert token.claims["jti"]

    res = res.follow()
    assert "Tokens obtained for jane." in res.text
    assert "forget-tokens-form" in res.forms
    with secret_client.session_transaction() as sess:
        assert sess["token_info"]["grant"] == JWT_BEARER


def test_key_client_signs_the_assertion_with_its_key(key_client, client_key):
    """Test the assertion is signed with the client key, and carries its kid."""
    _res, fetch = request_tokens(key_client, subject="jane", audience="token_endpoint")

    assertion = fetch.call_args.kwargs["assertion"]
    token = jwt.decode(assertion, load_key(client_key))
    assert token.header == {"typ": "JWT", "alg": "ES256", "kid": client_key["kid"]}
    assert token.claims["aud"] == "https://test.example.com/oauth/token"


def test_the_key_is_the_default_source(key_client, client_key):
    """Test a client with a key signs with it, and cannot use a secret."""
    form = jwt_bearer_form(key_client)

    assert form["source"].value == "key"
    res = key_client.get("/en/request/jwt_bearer")
    assert "Sign with the client key: ES256" in res.text
    assert "Sign with the client secret: this client has none." in res.text
    assert '"kid": "' + client_key["kid"] in res.text.replace("&#34;", '"')


def test_a_public_client_pastes_the_assertion(unconfigured_testapp, provider_metadata):
    """Test a client without a secret or a key can only paste an assertion."""
    server_session(unconfigured_testapp, {"client_id": "client"})
    res = unconfigured_testapp.get("/en/request/jwt_bearer")

    assert res.forms["jwt-bearer-form"]["source"].value == "paste"
    assert 'disabled id="source-0"' in res.text
    assert 'disabled id="source-1"' in res.text
    assert 'id="wrap-subject" hidden' in res.text
    assert 'id="wrap-assertion" hidden' not in res.text


def test_the_subject_is_the_signed_in_user(secret_client):
    """Test the subject is filled with the sub of the signed-in user."""
    with secret_client.session_transaction() as sess:
        sess["user"] = {"sub": "jane"}

    assert jwt_bearer_form(secret_client)["subject"].value == "jane"


def test_the_subject_is_required(secret_client):
    """Test the playground does not sign an assertion for nobody."""
    res, fetch = request_tokens(secret_client, subject="")

    assert "Enter who the tokens are for." in res.text
    fetch.assert_not_called()


@pytest.mark.parametrize("extra_claims", ["[1]", "{", '{"exp": NaN}'])
def test_the_extra_claims_must_be_an_object(secret_client, extra_claims):
    """Test the extra claims are a JSON object."""
    res, fetch = request_tokens(
        secret_client, subject="jane", extra_claims=extra_claims
    )

    assert "The extra claims must be a JSON object." in res.text
    fetch.assert_not_called()


def test_the_extra_claims_cannot_replace_the_form_claims(secret_client):
    """Test the extra claims cannot replace the claims the form sets."""
    res, fetch = request_tokens(
        secret_client,
        subject="jane",
        extra_claims='{"sub": "bob", "exp": 1, "jti": "j"}',
    )

    assert "The form already sets these claims: sub, exp." in res.text
    fetch.assert_not_called()


def test_the_assertion_cannot_be_an_extra_param(secret_client):
    """Test the extra parameters cannot override the assertion."""
    res, fetch = request_tokens(
        secret_client, subject="jane", extra_params="assertion=x"
    )

    assert "does not set itself: assertion" in res.text
    fetch.assert_not_called()


def test_a_client_without_a_key_cannot_sign_with_it(secret_client):
    """Test the source of the assertion must be one the client has."""
    res = secret_client.post(
        "/token/jwt-bearer",
        {
            "csrf_token": jwt_bearer_form(secret_client)["csrf_token"].value,
            "source": "key",
            "subject": "jane",
            "issuer": "client",
            "audience": "issuer",
            "lifetime": "300",
        },
    )

    assert "This client cannot sign the assertion this way." in res.text


def test_the_pasted_assertion_is_sent_as_is(secret_client):
    """Test the pasted assertion is sent without the spaces of the copy."""
    assertion = unsigned_jwt({"sub": "jane", "aud": "https://test.example.com"})
    res, fetch = request_tokens(
        secret_client, source="paste", assertion=f"  {assertion[:20]}\n{assertion[20:]}"
    )

    assert fetch.call_args.kwargs["assertion"] == assertion
    assert "Tokens obtained for jane." in res.follow().text


@pytest.mark.parametrize("assertion", ["", " \n "])
def test_a_pasted_assertion_must_be_given(secret_client, assertion):
    """Test the pasted assertion is required."""
    res, fetch = request_tokens(
        secret_client, source="paste", subject="", assertion=assertion
    )

    assert "Paste the assertion." in res.text
    fetch.assert_not_called()


def test_tokens_for_an_unknown_subject(secret_client):
    """Test the tokens are kept when the assertion does not say who they are for."""
    res, _fetch = request_tokens(secret_client, source="paste", assertion="opaque")

    assert "Tokens obtained." in res.follow().text


def test_the_id_token_signs_the_user_in(secret_client):
    """Test the user of the ID token is signed in."""
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.parse_id_token",
        return_value={"sub": "jane"},
    ):
        res, _fetch = request_tokens(
            secret_client, token={**TOKEN, "id_token": "i"}, subject="jane"
        )

    res = res.follow()
    assert "You have been successfully logged in." in res.text
    assert "Signed in as jane" in res.text


def test_an_invalid_id_token_rejects_the_tokens(secret_client):
    """Test the tokens are not kept when the ID token is not valid."""
    with patch(
        "auth_playground.oauth_client.PlaygroundOAuth2App.parse_id_token",
        side_effect=InvalidClaimError("iss"),
    ):
        res, _fetch = request_tokens(
            secret_client, token={**TOKEN, "id_token": "i"}, subject="jane"
        )
    res = res.follow()

    assert "The tokens are not kept. The ID token is not valid:" in res.text
    assert "jwt-bearer-form" in res.forms
    with secret_client.session_transaction() as sess:
        assert "token" not in sess


def test_a_signing_failure_is_shown(secret_client):
    """Test the form is shown again when the assertion cannot be signed."""
    with patch(
        "auth_playground.oauth.sign_assertion", side_effect=JoseError("bad key")
    ):
        res, fetch = request_tokens(secret_client, subject="jane")

    assert "The assertion could not be signed:" in res.text
    assert "bad key" in res.text
    fetch.assert_not_called()


def test_a_refused_request_is_shown(secret_client):
    """Test the form is shown again when the token request fails."""
    form = jwt_bearer_form(secret_client)
    form["subject"] = "jane"
    with patch(FETCH, side_effect=requests.ConnectionError("Connection refused")):
        res = form.submit("request_tokens").follow()

    assert "The token request failed: Connection refused" in res.text
    assert res.forms["jwt-bearer-form"]["subject"].value == "jane"


def preview(testapp, **data):
    """Return the assertion preview rendered by htmx for the form data."""
    form = jwt_bearer_form(testapp)
    res = testapp.post(
        "/token/jwt-bearer",
        {
            "csrf_token": form["csrf_token"].value,
            "issuer": "client",
            "audience": "issuer",
            "lifetime": "300",
            **data,
        },
        headers={
            "HX-Request": "true",
            "HX-Source": "article#assertion_preview",
            "HX-Target": "article#assertion_preview",
        },
    )
    assert "<html" not in res.text
    return res.text.replace("&#34;", '"')


def test_the_preview_shows_the_signed_claims(secret_client):
    """Test the preview shows the claims the playground signs."""
    text = preview(
        secret_client,
        source="secret",
        subject="jane",
        lifetime="60",
        extra_claims='{"jti": "mine"}',
    )

    assert "Signed with HS256 when the request is sent" in text
    assert '"sub": "jane"' in text
    assert '"exp": "[now + 60 s]"' in text
    assert '"jti": "mine"' in text
    assert "[generated]" not in text


def test_the_preview_shows_the_claims_in_the_signed_order(secret_client):
    """Test the extra claims come after the generated jti, as Authlib signs them."""
    text = preview(
        secret_client, source="secret", subject="jane", extra_claims='{"act": {}}'
    )

    assert text.index('"jti"') < text.index('"act"')


def test_the_preview_of_an_unavailable_source(secret_client):
    """Test the preview says the client cannot sign with a key it does not have."""
    text = preview(secret_client, source="key", subject="jane")

    assert "This client cannot sign the assertion." in text
    assert "Claims" not in text


def test_the_preview_decodes_the_pasted_assertion(secret_client):
    """Test the preview decodes the pasted assertion, and shows its dates."""
    now = int(time.time())
    assertion = unsigned_jwt(
        {
            "sub": "jane",
            "aud": ["https://test.example.com"],
            "iat": now,
            "exp": now + 60,
        },
        header={"alg": "HS256", "kid": "corp"},
    )
    text = preview(secret_client, source="paste", assertion=assertion)

    assert "Decoded, the signature is not checked" in text
    assert '"kid": "corp"' in text
    assert '"sub": "jane"' in text
    assert "iat: " in text
    assert "exp: " in text
    assert "notice" not in text


def test_the_preview_warns_about_an_expired_assertion(secret_client):
    """Test the preview says when the pasted assertion expired."""
    assertion = unsigned_jwt({"aud": "https://test.example.com", "exp": 1794040400})
    text = preview(secret_client, source="paste", assertion=assertion)

    assert "The assertion expired on Nov 7, 2026" in text


def test_the_preview_accepts_the_token_endpoint_as_audience(secret_client):
    """Test the token endpoint is an audience RFC 10070 §4 allows for a grant."""
    assertion = unsigned_jwt({"aud": "https://test.example.com/oauth/token"})
    text = preview(secret_client, source="paste", assertion=assertion)

    assert "notice" not in text


@pytest.mark.parametrize(
    "claims",
    [{"aud": "https://elsewhere.example"}, {"aud": {"x": 1}}, {"aud": [{"x": 1}]}],
)
def test_the_preview_warns_about_another_audience(secret_client, claims):
    """Test the preview warns about an audience the provider will likely refuse."""
    assertion = unsigned_jwt(claims)
    text = preview(secret_client, source="paste", assertion=assertion)

    assert "The audience is neither the issuer nor the token endpoint." in text


def test_the_preview_warns_about_a_missing_audience(secret_client):
    """Test the preview warns about a missing audience, even without token endpoint."""
    assertion = unsigned_jwt({"sub": "jane"})
    with patch(
        "auth_playground.jwt_bearer.server_metadata",
        return_value={"issuer": "https://test.example.com"},
    ):
        text = preview(secret_client, source="paste", assertion=assertion)

    assert "The audience is neither the issuer nor the token endpoint." in text


@pytest.mark.parametrize(
    "assertion", ["opaque", unsigned_jwt({}).split(".")[0] + ".WzFd.x"]
)
def test_the_preview_of_an_assertion_it_cannot_decode(secret_client, assertion):
    """Test the preview says when the pasted assertion is not a JWT."""
    text = preview(secret_client, source="paste", assertion=assertion)

    assert "This is not a JWT the playground can decode." in text


def test_the_preview_of_an_empty_pasted_assertion(secret_client):
    """Test the token request leaves out the assertion until it is pasted."""
    text = preview(secret_client, source="paste")

    assert "Decoded, the signature is not checked" in text
    assert "Header" not in text
    res = secret_client.get("/en/request/jwt_bearer")
    assert "assertion=[generated]" in res.text


def test_the_grant_type_can_be_registered(unconfigured_testapp, provider_metadata):
    """Test the JWT bearer grant type is offered at registration."""
    server_session(unconfigured_testapp)
    res = unconfigured_testapp.get("/en/client/dynamic")

    assert f'value="{JWT_BEARER}"' in res.text


def test_the_token_request_shows_the_pasted_assertion(secret_client):
    """Test the token request preview shows the pasted assertion."""
    form = jwt_bearer_form(secret_client)
    res = secret_client.post(
        "/token/jwt-bearer",
        {
            "csrf_token": form["csrf_token"].value,
            "source": "paste",
            "assertion": "header.claims.signature",
        },
        headers={
            "HX-Request": "true",
            "HX-Source": "article#preview",
            "HX-Target": "article#preview",
        },
    )

    assert "&amp;assertion=header.claims.signature" in res.text
    assert json.dumps(JWT_BEARER)[1:-1] in res.text


def test_the_issuer_is_required(secret_client):
    """Test the playground does not sign an assertion without an issuer."""
    res, fetch = request_tokens(secret_client, subject="jane", issuer="")

    assert "Enter who issues the assertion." in res.text
    fetch.assert_not_called()


@pytest.mark.parametrize(
    ("lifetime", "error"),
    [
        ("0", "Enter a number of seconds, 1 or more."),
        ("", "Not a valid integer value."),
    ],
)
def test_the_lifetime_must_be_positive(secret_client, lifetime, error):
    """Test the assertion lives at least a second."""
    res, fetch = request_tokens(secret_client, subject="jane", lifetime=lifetime)

    assert error in res.text
    fetch.assert_not_called()


def test_the_lifetime_does_not_matter_for_a_pasted_assertion(secret_client):
    """Test the hidden lifetime does not block a pasted assertion."""
    _res, fetch = request_tokens(
        secret_client, source="paste", assertion="opaque", lifetime=""
    )

    assert fetch.call_args.kwargs["assertion"] == "opaque"


def test_the_preview_ignores_another_audience_choice(secret_client):
    """Test the audience can only be the issuer or the token endpoint."""
    text = preview(secret_client, source="secret", subject="jane", audience="jwks_uri")

    assert '"aud": ""' in text


@pytest.mark.parametrize("exp", ["true", "1e300", "NaN", "99999999999999"])
def test_the_preview_ignores_dates_it_cannot_show(secret_client, exp):
    """Test a claim that is not a NumericDate is not shown as a date."""
    header = unsigned_jwt({}).split(".")[0]
    claims = base64.urlsafe_b64encode(f'{{"exp": {exp}}}'.encode()).rstrip(b"=")
    text = preview(
        secret_client, source="paste", assertion=f"{header}.{claims.decode()}.x"
    )

    assert "Claims" in text
    assert "Dates" not in text
    assert "expired" not in text

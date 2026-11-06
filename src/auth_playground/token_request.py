"""Build the token requests the client sends without a user."""

import json

from authlib.oauth2.client import DEFAULT_HEADERS
from authlib.oauth2.rfc7523.client import ASSERTION_TYPE
from flask import current_app

import auth_playground
from auth_playground.authorization import parse_extra_params
from auth_playground.authorization import requested_scope
from auth_playground.client_auth import KEY_METHOD
from auth_playground.preview import GENERATED
from auth_playground.preview import HIDDEN
from auth_playground.preview import IN_AN_HOUR
from auth_playground.preview import NOW
from auth_playground.preview import RequestPreview
from auth_playground.session import server_metadata

# The methods that authenticate the client with a signed assertion.
JWT_METHODS = ("client_secret_jwt", KEY_METHOD)

# Parameters the playground sets itself in a token request.
TOKEN_RESERVED_PARAMS = frozenset(
    {
        "grant_type",
        "scope",
        "client_id",
        "client_secret",
        "client_assertion",
        "client_assertion_type",
    }
)


def extra_token_params(form):
    """Return the extra parameters of the form, as a list of pairs."""
    pairs, _errors = parse_extra_params(form.extra_params.data, form.reserved_params)
    return pairs


def client_auth_preview(method, client_id):
    """Return the headers and the body parameters that authenticate the client."""
    if method == "client_secret_basic":
        return [("Authorization", f"Basic {HIDDEN}")], []
    if method == "client_secret_post":
        return [], [("client_id", client_id), ("client_secret", HIDDEN)]
    if method in JWT_METHODS:
        return [], [
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", GENERATED),
        ]
    return [], [("client_id", client_id)]


def client_assertion_preview(oauth_config, token_endpoint):
    """Return the header and the claims of the client assertion, or ``None``.

    They are the ones Authlib signs: the assertion lives for an hour.
    """
    method = oauth_config.get("token_endpoint_auth_method")
    if method not in JWT_METHODS:
        return None

    header = {"alg": "HS256", "typ": "JWT"}
    if method == KEY_METHOD:
        header = {
            "alg": oauth_config["token_endpoint_auth_signing_alg"],
            "kid": oauth_config["client_key"]["kid"],
            "typ": "JWT",
        }
    client_id = oauth_config.get("client_id", "")
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "jti": GENERATED,
        "iat": NOW,
        "exp": IN_AN_HOUR,
    }
    return {
        "header": json.dumps(header),
        "claims": json.dumps(claims, indent=2),
    }


def token_preview(form, grant_type, params):
    """Return the token request of ``grant_type`` built from the form.

    The parameters are in the order Authlib sends them.
    """
    oauth_config = auth_playground.get_oauth_config(current_app)
    headers, auth_params = client_auth_preview(
        oauth_config.get("token_endpoint_auth_method"),
        oauth_config.get("client_id", ""),
    )
    params = [*extra_token_params(form), ("grant_type", grant_type), *params]
    if scope := requested_scope(form):
        params.append(("scope", scope))

    token_endpoint = server_metadata().get("token_endpoint", "")
    return RequestPreview(
        "POST",
        token_endpoint,
        params + auth_params,
        [*DEFAULT_HEADERS.items(), *headers],
        assertion=client_assertion_preview(oauth_config, token_endpoint),
    )


def client_credentials_preview(form):
    """Return the client credentials token request built from the form."""
    return token_preview(form, "client_credentials", [])


def password_preview(form):
    """Return the password token request built from the form.

    Like Authlib, it leaves out the empty credentials.
    """
    params = []
    if form.username.data:
        params.append(("username", form.username.data))
    if form.password.data:
        params.append(("password", HIDDEN))
    return token_preview(form, "password", params)

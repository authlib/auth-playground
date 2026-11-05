"""Build the token requests the client sends without a user."""

from authlib.oauth2.client import DEFAULT_HEADERS
from authlib.oauth2.rfc7523.client import ASSERTION_TYPE
from flask import current_app

import auth_playground
from auth_playground.authorization import parse_extra_params
from auth_playground.authorization import requested_scope
from auth_playground.preview import GENERATED
from auth_playground.preview import HIDDEN
from auth_playground.preview import RequestPreview
from auth_playground.session import server_metadata

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
    if method == "client_secret_jwt":
        return [], [
            ("client_assertion_type", ASSERTION_TYPE),
            ("client_assertion", GENERATED),
        ]
    return [], [("client_id", client_id)]


def client_credentials_preview(form):
    """Return the client credentials token request built from the form.

    The parameters are in the order Authlib sends them.
    """
    oauth_config = auth_playground.get_oauth_config(current_app)
    headers, auth_params = client_auth_preview(
        oauth_config.get("token_endpoint_auth_method"),
        oauth_config.get("client_id", ""),
    )
    params = [*extra_token_params(form), ("grant_type", "client_credentials")]
    if scope := requested_scope(form):
        params.append(("scope", scope))

    return RequestPreview(
        "POST",
        server_metadata().get("token_endpoint", ""),
        params + auth_params,
        [*DEFAULT_HEADERS.items(), *headers],
    )

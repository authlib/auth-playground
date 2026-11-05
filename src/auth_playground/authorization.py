"""Build the authorization request from the authorization form."""

from authlib.common.security import generate_token
from authlib.oauth2.rfc7636 import create_s256_code_challenge
from flask import current_app
from flask import url_for

import auth_playground
from auth_playground.preview import GENERATED
from auth_playground.preview import RequestPreview
from auth_playground.session import server_metadata

PKCE_METHODS = ("S256", "plain")

# Sent when the form requests no scope.
DEFAULT_SCOPE = "openid profile email phone address groups"

# Parameters the playground sets itself, from the form or from the protocol.
RESERVED_PARAMS = frozenset(
    {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "prompt",
        "ui_locales",
        "max_age",
        "acr_values",
        "login_hint",
        "claims",
        # Argument names of the Authlib functions that build the request.
        "url",
        "uri",
        "client",
        "authorization_endpoint",
        "code_verifier",
        "self",
    }
)


def parse_extra_params(text, reserved=RESERVED_PARAMS):
    """Parse ``name=value`` lines into a list of pairs and a list of errors.

    A name can appear on several lines, as RFC 8707 ``resource`` does. The
    ``reserved`` names are errors.
    """
    pairs = []
    errors = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue

        name, separator, value = line.partition("=")
        name = name.strip()
        if not separator or not name:
            errors.append(line)
            continue

        if name in reserved:
            errors.append(name)
            continue

        pairs.append((name, value.strip()))

    return pairs, errors


def requested_scope(form):
    """Join the checked scopes and the other scopes, without duplicates."""
    scopes = list(form.scopes.data or [])
    scopes += (form.other_scopes.data or "").split()
    return " ".join(dict.fromkeys(scopes))


def authorization_params(form):
    """Return the parameters the form adds to the authorization request.

    A name given on several extra parameter lines gets a list of values.
    """
    params = {"scope": requested_scope(form) or DEFAULT_SCOPE}

    for name in ("prompt", "ui_locales", "acr_values", "login_hint", "claims"):
        if value := form[name].data:
            params[name] = value

    if form.max_age.data is not None:
        params["max_age"] = form.max_age.data

    pairs, _errors = parse_extra_params(form.extra_params.data)
    extra = {}
    for name, value in pairs:
        extra.setdefault(name, []).append(value)
    params.update(
        {
            name: values[0] if len(values) == 1 else values
            for name, values in extra.items()
        }
    )
    return params


def pkce_params(method, code_verifier):
    """Return the PKCE parameters of the authorization request (RFC 7636 §4.3)."""
    if method == "S256":
        challenge = create_s256_code_challenge(code_verifier)
    else:
        challenge = code_verifier

    return {"code_challenge": challenge, "code_challenge_method": method}


def new_code_verifier():
    """Generate a code verifier (RFC 7636 §4.1)."""
    return generate_token(48)


def authorization_preview(form):
    """Return the authorization request built from the form."""
    params = list(preview_lines(preview_params(form)))
    return RequestPreview("GET", authorization_endpoint(), params)


def preview_params(form):
    """Return the parameters of the authorization request, in the sent order.

    The values generated when the request is sent are shown as placeholders.
    """
    oauth_config = auth_playground.get_oauth_config(current_app)
    params = {
        "response_type": "code",
        "client_id": oauth_config.get("client_id", ""),
        "redirect_uri": url_for("oauth.authorize_callback", _external=True),
        **authorization_params(form),
        "state": GENERATED,
    }
    if "openid" in params["scope"].split():
        params["nonce"] = GENERATED

    if form.pkce.data:
        params["code_challenge"] = GENERATED
        params["code_challenge_method"] = form.pkce.data

    return params


def authorization_endpoint():
    """Return the authorization endpoint of the configured server."""
    return server_metadata().get("authorization_endpoint", "")


def preview_lines(params):
    """Flatten the parameters into name and value pairs, one per value."""
    for name, value in params.items():
        for item in value if isinstance(value, list) else [value]:
            yield name, item

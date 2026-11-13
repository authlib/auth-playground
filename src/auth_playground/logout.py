"""Build the RP-Initiated Logout request from the logout form."""

from auth_playground.preview import GENERATED
from auth_playground.preview import RequestPreview
from auth_playground.session import server_metadata

LOGOUT_PARAMS = (
    "id_token_hint",
    "post_logout_redirect_uri",
    "client_id",
    "logout_hint",
    "ui_locales",
)


def logout_params(form):
    """Return the parameters of the form that have a value."""
    return {name: form[name].data for name in LOGOUT_PARAMS if form[name].data}


def logout_preview(form):
    """Return the logout request built from the form.

    The parameters come in the order of Authlib ``create_logout_url``, which
    adds a state when there is a post_logout_redirect_uri.
    """
    params = logout_params(form)
    pairs = []
    for name in LOGOUT_PARAMS:
        if name not in params:
            continue
        pairs.append((name, params[name]))
        if name == "post_logout_redirect_uri":
            pairs.append(("state", GENERATED))

    endpoint = server_metadata().get("end_session_endpoint", "")
    return RequestPreview("GET", endpoint, pairs)

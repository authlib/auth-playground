"""Pages rendered by several views."""

from flask import current_app
from flask import render_template
from flask import session
from flask import url_for
from werkzeug.datastructures import MultiDict

import auth_playground
from auth_playground.client_auth import PUBLIC_METHOD
from auth_playground.forms import AuthorizationParamsForm
from auth_playground.forms import ClientCredentialsForm
from auth_playground.forms import JwtBearerForm
from auth_playground.forms import LogoutLocalForm
from auth_playground.forms import LogoutParamsForm
from auth_playground.forms import PasswordForm
from auth_playground.forms import RefreshTokenForm
from auth_playground.forms import UserInfoForm
from auth_playground.grants import GRANT_GROUPS
from auth_playground.grants import GRANTS
from auth_playground.grants import registered_grant_types
from auth_playground.grants import tokens_grant
from auth_playground.session import server_metadata

# The session key of the last response that did not give tokens.
REJECTED_RESPONSE = "rejected_response"

# The session key of what the user entered in a grant form that did not give tokens.
GRANT_FORM_DATA = "grant_form_data"

GRANT_FORMS = {
    "authorization_code": AuthorizationParamsForm,
    "client_credentials": ClientCredentialsForm,
    "password": PasswordForm,
    "jwt_bearer": JwtBearerForm,
}


def render_request_page():
    """Render the grant types the client can use to obtain tokens."""
    return render_template(
        "request.html",
        grant_groups=GRANT_GROUPS,
        grants=GRANTS,
        tokens_grant=tokens_grant() if session.get("token") else None,
        public_client=is_public_client(),
        rejected_response=session.pop(REJECTED_RESPONSE, None),
    )


def render_grant_page(grant, grant_form=None):
    """Render the form of a grant type, with what the user entered before, if any."""
    return render_template(
        "grant.html",
        grant=grant,
        grant_form=grant_form or grant_form_again(grant.name),
        registered_grant_types=registered_grant_types() or [],
        tokens_grant=tokens_grant(),
        public_client=is_public_client(),
        rejected_response=session.pop(REJECTED_RESPONSE, None),
    )


def render_tokens_page(tab):
    """Render a tab of the tokens page: the current tokens, or the logout."""
    oauth_config = auth_playground.get_oauth_config(current_app)
    logout_params_form = LogoutParamsForm(
        data={
            "id_token_hint": session.get("token", {}).get("id_token", ""),
            "client_id": oauth_config["client_id"] if oauth_config else "",
            "post_logout_redirect_uri": url_for(
                "oauth.logout_callback", _external=True
            ),
        }
    )
    return render_template(
        "tokens.html",
        tab=tab,
        refresh_form=RefreshTokenForm(),
        userinfo_form=UserInfoForm(),
        userinfo_endpoint=server_metadata().get("userinfo_endpoint"),
        userinfo_alg=oauth_config.get("userinfo_signed_response_alg"),
        tokens_grant=tokens_grant(),
        logout_local_form=LogoutLocalForm(),
        logout_params_form=logout_params_form,
        rejected_response=session.pop(REJECTED_RESPONSE, None),
    )


def is_public_client():
    """Tell whether the client has no credentials of its own."""
    oauth_config = auth_playground.get_oauth_config(current_app)
    return oauth_config.get("token_endpoint_auth_method") == PUBLIC_METHOD


def grant_form_again(name):
    """Return the form of the grant type, with what the user entered before, if any."""
    saved = session.pop(GRANT_FORM_DATA, None)
    if not saved or saved["grant"] != name:
        return GRANT_FORMS[name]()
    return GRANT_FORMS[name](formdata=MultiDict(saved["data"]))

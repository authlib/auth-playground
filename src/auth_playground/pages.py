"""Pages rendered by several views."""

from flask import current_app
from flask import render_template
from flask import request
from flask import session
from flask import url_for

import auth_playground
from auth_playground.client_auth import PUBLIC_METHOD
from auth_playground.forms import AuthorizationParamsForm
from auth_playground.forms import ClientCredentialsForm
from auth_playground.forms import GrantForm
from auth_playground.forms import JwtBearerForm
from auth_playground.forms import LogoutLocalForm
from auth_playground.forms import LogoutParamsForm
from auth_playground.forms import PasswordForm
from auth_playground.forms import RefreshTokenForm
from auth_playground.forms import UserInfoForm
from auth_playground.grants import get_grant
from auth_playground.grants import tokens_grant
from auth_playground.session import server_metadata

GRANT_FORMS = {
    "authorization_code": AuthorizationParamsForm,
    "client_credentials": ClientCredentialsForm,
    "password": PasswordForm,
    "jwt_bearer": JwtBearerForm,
}


def render_tokens_page(tab, grant=None, grant_form=None):
    """Render a tab of the tokens page.

    The grant type is called ``grant``, or else is in the query string.
    """
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
    grant = get_grant(grant or request.args.get("grant"))
    grant_forms = {}
    if tab == "request":
        grant_forms = {
            "grant_selector": GrantForm(data={"grant": grant.name}),
            "grant_form": grant_form or GRANT_FORMS[grant.name](),
        }

    return render_template(
        "tokens.html",
        tab=tab,
        refresh_form=RefreshTokenForm(),
        userinfo_form=UserInfoForm(),
        userinfo_endpoint=server_metadata().get("userinfo_endpoint"),
        grant=grant,
        tokens_grant=tokens_grant(),
        public_client=oauth_config.get("token_endpoint_auth_method") == PUBLIC_METHOD,
        **grant_forms,
        logout_local_form=LogoutLocalForm(),
        logout_params_form=logout_params_form,
    )

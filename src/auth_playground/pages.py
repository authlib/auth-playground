"""Pages rendered by several views."""

from flask import current_app
from flask import render_template
from flask import session
from flask import url_for

import auth_playground
from auth_playground.forms import AuthorizationParamsForm
from auth_playground.forms import LogoutLocalForm
from auth_playground.forms import LogoutParamsForm
from auth_playground.forms import RefreshTokenForm


def render_session_page(tab, auth_params_form=None):
    """Render a tab of the session page."""
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
    if auth_params_form is None:
        auth_params_form = AuthorizationParamsForm()

    return render_template(
        "session.html",
        tab=tab,
        refresh_form=RefreshTokenForm(),
        auth_params_form=auth_params_form,
        logout_local_form=LogoutLocalForm(),
        logout_params_form=logout_params_form,
    )

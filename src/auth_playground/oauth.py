import importlib.metadata
import uuid

import requests
from authlib.common.errors import AuthlibBaseError
from authlib.integrations.base_client import OAuthError
from flask import Blueprint
from flask import current_app
from flask import flash
from flask import g
from flask import redirect
from flask import request
from flask import session
from flask import url_for
from flask_babel import gettext as _

import auth_playground
from auth_playground.client_auth import METHODS
from auth_playground.client_auth import PUBLIC_METHOD
from auth_playground.decorators import server_config_needed
from auth_playground.forms import AuthorizationParamsForm
from auth_playground.forms import DynamicRegistrationForm
from auth_playground.forms import LogoutLocalForm
from auth_playground.forms import LogoutParamsForm
from auth_playground.forms import RefreshTokenForm
from auth_playground.forms import UnregisterClientForm

bp = Blueprint("oauth", __name__)


def get_software_id() -> str:
    """Get unique software identifier based on repository URL."""
    pkg_metadata = importlib.metadata.metadata("auth-playground")
    project_urls = dict(
        [url.split(", ", 1) for url in pkg_metadata.get_all("Project-URL") or []]
    )
    repository_url = project_urls.get("repository")
    return str(
        uuid.uuid5(uuid.NAMESPACE_URL, repository_url)
        if repository_url
        else uuid.uuid4()
    )


def get_software_version() -> str:
    """Get software version from package metadata."""
    return importlib.metadata.version("auth-playground")


def get_response_error(exc: requests.RequestException) -> str | None:
    """Get the error description, or else the error code, from an OAuth error response."""
    if exc.response is None:
        return None

    try:
        error_data = exc.response.json()
    except requests.JSONDecodeError:
        return None

    if not isinstance(error_data, dict):
        return None

    error = error_data.get("error_description") or error_data.get("error")
    return error if isinstance(error, str) else None


def clear_user_session():
    """Clear user and token data from the session."""
    for key in ("user", "token"):
        session.pop(key, None)


@bp.route("/client/dynamic-registration", methods=["POST"])
@server_config_needed(client_needed=False)
def client_dynamic_registration():
    """Automatically register OAuth client using dynamic client registration."""
    form = DynamicRegistrationForm()

    if not form.validate_on_submit():
        errors = [] if "csrf_token" in form.errors else form.grant_types.errors
        for error in errors or [_("Invalid request")]:
            flash(error, "error")
        return redirect(url_for("routes.configure_client"))

    if not g.server_config.specs.oauth_2_dynamic_client_registration:
        flash(_("Dynamic client registration not supported"), "error")
        return redirect(url_for("routes.configure_client"))

    registration_endpoint = g.server_config.metadata["registration_endpoint"]

    redirect_uris = [
        url_for("oauth.authorize_callback", _external=True),
    ]

    requested_auth_method = (
        PUBLIC_METHOD if form.client_type.data == "public" else form.auth_method.data
    )
    registration_data = {
        "client_name": "Auth Playground",
        "client_uri": url_for("routes.index", _external=True),
        "redirect_uris": redirect_uris,
        "grant_types": form.grant_types.data,
        "response_types": ["code"]
        if "authorization_code" in form.grant_types.data
        else [],
        "token_endpoint_auth_method": requested_auth_method,
        "scope": "openid profile email phone address groups",
        "tos_uri": url_for("routes.tos", _external=True),
        "policy_uri": url_for("routes.policy", _external=True),
        "software_id": get_software_id(),
        "software_version": get_software_version(),
    }

    if g.server_config.specs.oidc_rpinitiated_logout:
        registration_data["post_logout_redirect_uris"] = [
            url_for("oauth.logout_callback", _external=True),
        ]

    headers = {}
    initial_access_token = form.initial_access_token.data
    if initial_access_token:
        headers["Authorization"] = f"Bearer {initial_access_token}"

    try:
        response = requests.post(
            registration_endpoint, json=registration_data, headers=headers, timeout=10
        )
        response.raise_for_status()
        client_data = response.json()
    except requests.JSONDecodeError:
        flash(_("Invalid JSON response from registration endpoint"), "error")
        return redirect(url_for("routes.configure_client"))
    except requests.RequestException as exc:
        error = get_response_error(exc)
        if error:
            flash(
                _("Dynamic client registration failed: {error}").format(error=error),
                "error",
            )
        else:
            flash(_("Dynamic client registration failed"), "error")
        return redirect(url_for("routes.configure_client"))

    if not isinstance(client_data, dict) or not client_data.get("client_id"):
        flash(_("Invalid response from registration endpoint"), "error")
        return redirect(url_for("routes.configure_client"))

    auth_method = client_data.get("token_endpoint_auth_method", requested_auth_method)
    if auth_method not in METHODS:
        flash(
            _(
                "The server registered the client with the {auth_method} "
                "authentication method, which Auth Playground does not support. "
                "The client is still registered on the server."
            ).format(auth_method=auth_method),
            "error",
        )
        return redirect(url_for("routes.configure_client"))

    client_secret = client_data.get("client_secret")
    if auth_method != PUBLIC_METHOD and not client_secret:
        flash(
            _(
                "The server registered the client without a client secret, "
                "but its authentication method {auth_method} needs one. "
                "The client is still registered on the server."
            ).format(auth_method=auth_method),
            "error",
        )
        return redirect(url_for("routes.configure_client"))

    auth_playground.setup_oauth_runtime(
        current_app,
        client_data["client_id"],
        client_secret if auth_method != PUBLIC_METHOD else None,
        g.server_config.issuer_url,
        auth_method,
    )

    if "registration_access_token" in client_data:
        g.server_config.registration_access_token = client_data[
            "registration_access_token"
        ]
    if "registration_client_uri" in client_data:
        g.server_config.registration_client_uri = client_data["registration_client_uri"]

    flash(
        _("Client successfully registered!"),
        "success",
    )
    return redirect(url_for("routes.session"))


@bp.route("/unregister-client", methods=["POST"])
@server_config_needed
def unregister_client():
    """Unregister OAuth client using dynamic client registration management."""
    form = UnregisterClientForm()

    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.configure_client"))

    if (
        not g.server_config.registration_access_token
        or not g.server_config.registration_client_uri
    ):
        flash(_("Client registration management credentials not found"), "error")
        return redirect(url_for("routes.configure_client"))

    headers = {"Authorization": f"Bearer {g.server_config.registration_access_token}"}

    try:
        response = requests.delete(
            g.server_config.registration_client_uri, headers=headers, timeout=10
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        error = get_response_error(exc)
        if error:
            flash(
                _("Client unregistration failed: {error}").format(error=error),
                "error",
            )
        else:
            flash(_("Client unregistration failed"), "error")
        return redirect(url_for("routes.configure_client"))

    session.pop("oauth_config", None)
    clear_user_session()

    g.server_config.registration_access_token = None
    g.server_config.registration_client_uri = None

    flash(_("Client successfully unregistered"), "success")
    return redirect(url_for("routes.configure_client"))


@bp.route("/authorize", methods=["GET", "POST"])
@server_config_needed
def authorize():
    """Redirect users to the Identity Provider authorization page."""
    kwargs = {}

    if request.method == "POST":
        form = AuthorizationParamsForm()

        if form.validate_on_submit():
            if form.scopes.data:
                kwargs["scope"] = " ".join(form.scopes.data)

            if form.prompt.data:
                kwargs["prompt"] = form.prompt.data

            if form.ui_locales.data:
                kwargs["ui_locales"] = form.ui_locales.data

            if form.max_age.data is not None:
                kwargs["max_age"] = form.max_age.data

            if form.acr_values.data:
                kwargs["acr_values"] = form.acr_values.data

            if form.login_hint.data:
                kwargs["login_hint"] = form.login_hint.data

            if form.claims.data:
                kwargs["claims"] = form.claims.data

    if request.method == "GET" and "user" in session:
        kwargs["prompt"] = "login"

    return auth_playground.oauth.default.authorize_redirect(
        url_for("oauth.authorize_callback", _external=True), **kwargs
    )


@bp.route("/authorize_callback")
def authorize_callback():
    """Handle OAuth callback after user authorization."""
    try:
        token = auth_playground.oauth.default.authorize_access_token()
        session["user"] = token.get("userinfo")
        session["token"] = {
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "id_token": token.get("id_token"),
            "token_type": token.get("token_type"),
            "expires_in": token.get("expires_in"),
            "expires_at": token.get("expires_at"),
            "scope": token.get("scope"),
        }
        flash(_("You have been successfully logged in."), "success")
    except AuthlibBaseError as exc:
        flash(
            _("An error happened during login: {error}").format(error=exc.description),
            "error",
        )

    return redirect(url_for("routes.session"))


@bp.route("/logout/local", methods=["POST"])
def logout_local():
    """Log out locally without contacting the Identity Provider."""
    form = LogoutLocalForm()
    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.session"))

    clear_user_session()
    flash(_("You have been logged out"), "success")
    return redirect(url_for("routes.session"))


@bp.route("/logout", methods=["GET", "POST"])
@server_config_needed
def logout():
    """Redirect users to the Identity Provider logout page for global logout."""
    kwargs = {}

    if request.method == "POST":
        form = LogoutParamsForm()
        if form.validate_on_submit():
            if form.id_token_hint.data:
                kwargs["id_token_hint"] = form.id_token_hint.data
            if form.client_id.data:
                kwargs["client_id"] = form.client_id.data
            if form.post_logout_redirect_uri.data:
                kwargs["post_logout_redirect_uri"] = form.post_logout_redirect_uri.data
            if form.logout_hint.data:
                kwargs["logout_hint"] = form.logout_hint.data
            if form.ui_locales.data:
                kwargs["ui_locales"] = form.ui_locales.data
    else:
        id_token = session.get("token", {}).get("id_token")
        oauth_config = auth_playground.get_oauth_config(current_app)
        client_id = oauth_config["client_id"] if oauth_config else None
        kwargs = {
            "id_token_hint": id_token,
            "client_id": client_id,
            "post_logout_redirect_uri": url_for(
                "oauth.logout_callback", _external=True
            ),
        }

    return auth_playground.oauth.default.logout_redirect(**kwargs)


@bp.route("/logout_callback")
def logout_callback():
    """Handle callback after server-side logout."""
    try:
        auth_playground.oauth.default.validate_logout_response()
    except OAuthError:
        pass

    clear_user_session()
    flash(_("You have been logged out from the server"), "success")
    return redirect(url_for("routes.session"))


@bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh the access token using the refresh token."""
    form = RefreshTokenForm()
    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.session"))

    refresh_token = session.get("token", {}).get("refresh_token")
    if not refresh_token:
        flash(_("No refresh token available"), "error")
        return redirect(url_for("routes.session"))

    try:
        original_scope = session.get("token", {}).get("scope", "")
        new_token = auth_playground.oauth.default.fetch_access_token(
            grant_type="refresh_token",
            refresh_token=refresh_token,
            scope=original_scope,
        )

        old_token = session.get("token", {})
        session["token"] = {
            "access_token": new_token.get("access_token"),
            "refresh_token": new_token.get("refresh_token") or refresh_token,
            "id_token": new_token.get("id_token") or old_token.get("id_token"),
            "token_type": new_token.get("token_type"),
            "expires_in": new_token.get("expires_in"),
            "expires_at": new_token.get("expires_at"),
            "scope": new_token.get("scope"),
        }
        flash(_("Token successfully refreshed"), "success")
    except AuthlibBaseError as exc:
        flash(
            _("An error happened during token refresh: {error}").format(
                error=exc.description
            ),
            "error",
        )

    return redirect(url_for("routes.session"))

import importlib.metadata
import uuid

import requests
from authlib.common.errors import AuthlibBaseError
from authlib.common.urls import add_params_to_uri
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
from auth_playground.decorators import server_config_needed
from auth_playground.forms import AuthorizationParamsForm
from auth_playground.forms import DynamicRegistrationForm
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


def clear_user_session():
    """Clear user and token data from the session."""
    try:
        del session["user"]
    except KeyError:
        pass

    try:
        del session["token"]
    except KeyError:
        pass


@bp.route("/client/dynamic-registration", methods=["POST"])
@server_config_needed(client_needed=False)
def client_dynamic_registration():
    """Automatically register OAuth client using dynamic client registration."""
    form = DynamicRegistrationForm()

    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.configure_client"))

    if not g.server_config.specs.oauth_2_dynamic_client_registration:
        flash(_("Dynamic client registration not supported"), "error")
        return redirect(url_for("routes.configure_client"))

    registration_endpoint = g.server_config.metadata["registration_endpoint"]

    redirect_uris = [
        url_for("oauth.authorize_callback", _external=True),
    ]

    registration_data = {
        "client_name": "Auth Playground",
        "client_uri": url_for("routes.index", _external=True),
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
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
    except requests.RequestException as e:
        error_message = _("Dynamic client registration failed")
        if hasattr(e, "response") and e.response is not None:
            try:
                error_data = e.response.json()
                if "error_description" in error_data:
                    error_message = _(
                        "Dynamic client registration failed: {error}"
                    ).format(error=error_data["error_description"])
                elif "error" in error_data:
                    error_message = _(
                        "Dynamic client registration failed: {error}"
                    ).format(error=error_data["error"])
            except ValueError:
                pass  # Response is not JSON, use default message
        flash(error_message, "error")
        return redirect(url_for("routes.configure_client"))
    except ValueError:
        flash(_("Invalid JSON response from registration endpoint"), "error")
        return redirect(url_for("routes.configure_client"))

    auth_playground.setup_oauth_runtime(
        current_app,
        client_data["client_id"],
        client_data["client_secret"],
        g.server_config.issuer_url,
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
    return redirect(url_for("routes.playground"))


@bp.route("/unregister-client", methods=["POST"])
@server_config_needed
def unregister_client():
    """Unregister OAuth client using dynamic client registration management."""
    form = UnregisterClientForm()

    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.playground"))

    if (
        not g.server_config.registration_access_token
        or not g.server_config.registration_client_uri
    ):
        flash(_("Client registration management credentials not found"), "error")
        return redirect(url_for("routes.playground"))

    headers = {"Authorization": f"Bearer {g.server_config.registration_access_token}"}

    try:
        response = requests.delete(
            g.server_config.registration_client_uri, headers=headers, timeout=10
        )
        response.raise_for_status()
    except requests.RequestException as e:
        error_message = _("Client unregistration failed")
        if hasattr(e, "response") and e.response is not None:
            try:
                error_data = e.response.json()
                if "error_description" in error_data:
                    error_message = _("Client unregistration failed: {error}").format(
                        error=error_data["error_description"]
                    )
                elif "error" in error_data:
                    error_message = _("Client unregistration failed: {error}").format(
                        error=error_data["error"]
                    )
            except ValueError:
                pass  # Response is not JSON, use default message
        flash(error_message, "error")
        return redirect(url_for("routes.playground"))

    session.pop("oauth_config", None)
    session.pop("user", None)
    session.pop("token", None)

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

    return redirect(url_for("routes.tokens"))


@bp.route("/logout/local")
def logout_local():
    """Log out locally without contacting the Identity Provider."""
    clear_user_session()
    flash(_("You have been logged out"), "success")
    return redirect(url_for("routes.playground"))


@bp.route("/logout")
@server_config_needed
def logout():
    """Redirect users to the Identity Provider logout page for global logout."""
    auth_playground.oauth.default.load_server_metadata()
    end_session_endpoint = auth_playground.oauth.default.server_metadata.get(
        "end_session_endpoint"
    )
    id_token = session.get("token", {}).get("id_token")

    oauth_config = auth_playground.get_oauth_config(current_app)
    client_id = oauth_config["client_id"] if oauth_config else None

    end_session_url = add_params_to_uri(
        end_session_endpoint,
        dict(
            client_id=client_id,
            id_token_hint=id_token,
            post_logout_redirect_uri=url_for("oauth.logout_callback", _external=True),
        ),
    )
    return redirect(end_session_url)


@bp.route("/logout_callback")
def logout_callback():
    """Handle callback after server-side logout."""
    clear_user_session()
    flash(_("You have been logged out from the server"), "success")
    return redirect(url_for("routes.playground"))


@bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh the access token using the refresh token."""
    form = RefreshTokenForm()
    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.playground"))

    refresh_token = session.get("token", {}).get("refresh_token")
    if not refresh_token:
        flash(_("No refresh token available"), "error")
        return redirect(url_for("routes.playground"))

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

    return redirect(url_for("routes.playground"))

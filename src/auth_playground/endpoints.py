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
from flask import render_template
from flask import session
from flask import url_for

import auth_playground
from auth_playground.forms import ClientConfigForm
from auth_playground.forms import DynamicRegistrationForm
from auth_playground.forms import RefreshTokenForm
from auth_playground.forms import ServerConfigForm
from auth_playground.forms import UnregisterClientForm
from auth_playground.session import ServerConfig

bp = Blueprint("routes", __name__)


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


def fetch_server_metadata(issuer_url: str, timeout: int = 10) -> tuple[dict, str]:
    """Fetch server metadata from well-known OIDC or OAuth2 endpoints."""
    oidc_url = f"{issuer_url}/.well-known/openid-configuration"
    try:
        response = requests.get(oidc_url, timeout=timeout)
        response.raise_for_status()
        return response.json(), "oidc"
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 404:
            raise  # Only try OAuth2 endpoint if OIDC endpoint is not found

    oauth2_url = f"{issuer_url}/.well-known/oauth-authorization-server"
    response = requests.get(oauth2_url, timeout=timeout)
    response.raise_for_status()
    return response.json(), "oauth2"


def handle_fetch_metadata_errors(issuer_url: str, on_error):
    """Fetch server metadata and handle errors with custom error handler."""
    try:
        return fetch_server_metadata(issuer_url)
    except requests.exceptions.ConnectionError:
        flash("Cannot connect to the server. Please check the URL.", "error")
        return on_error()
    except requests.exceptions.Timeout:
        flash("Connection timeout. The server is not responding.", "error")
        return on_error()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            flash(
                "This server does not support OIDC Discovery or OAuth 2.0 Authorization Server Metadata",
                "error",
            )
        else:
            flash(f"Server returned an error: HTTP {e.response.status_code}", "error")
        return on_error()
    except requests.RequestException:
        flash("Failed to connect to the server. Please check the URL.", "error")
        return on_error()
    except ValueError:
        flash("Invalid response from server", "error")
        return on_error()


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


def clear_server_session():
    """Clear all server-related data from the session."""
    clear_user_session()
    ServerConfig.clear(session)

    try:
        del session["oauth_config"]
    except KeyError:
        pass


@bp.route("/")
def index():
    """Redirect to the appropriate configuration step or main page."""
    server_configured = auth_playground.is_oauth_server_from_env(current_app) or (
        g.server_config and g.server_config.issuer_url
    )
    client_configured = auth_playground.is_oauth_configured()

    if not server_configured:
        return redirect(url_for("routes.configure_server"))

    elif not client_configured:
        return redirect(url_for("routes.configure_client"))

    return redirect(url_for("routes.playground"))


@bp.route("/server", methods=["GET", "POST"])
def configure_server():
    """Display form to configure and validate identity provider URL."""
    if auth_playground.is_oauth_server_from_env(current_app):
        flash(
            "OAuth configuration is set via environment variables and cannot be changed",
            "warning",
        )
        return redirect(url_for("routes.playground"))

    form = ServerConfigForm()

    if not form.validate_on_submit():
        if g.server_config and g.server_config.issuer_url:
            flash("You can now configure a different identity provider", "info")
        clear_server_session()
        return render_template("configure_server.html", form=form)

    issuer_url = form.issuer_url.data.rstrip("/")

    result = handle_fetch_metadata_errors(
        issuer_url, lambda: render_template("configure_server.html", form=form)
    )
    if not isinstance(result, tuple):
        return result
    metadata, server_type = result

    g.server_config = ServerConfig(
        metadata=metadata,
        issuer_url=issuer_url,
        server_type=server_type,
    )
    g.server_config.save(session)

    flash("Server metadata successfully loaded", "success")

    return redirect(url_for("routes.configure_client"))


@bp.route("/client", methods=["GET", "POST"])
def configure_client():
    """Display options to configure OAuth client credentials."""
    if auth_playground.is_oauth_client_from_env(current_app):
        flash(
            "OAuth client is set via environment variables and cannot be changed",
            "warning",
        )
        return redirect(url_for("routes.playground"))

    issuer_url = g.server_config.issuer_url
    if not issuer_url:
        flash("Please configure a server", "warning")
        return redirect(url_for("routes.configure_server"))

    if not g.server_config.metadata:
        result = handle_fetch_metadata_errors(
            issuer_url, lambda: redirect(url_for("routes.configure_server"))
        )
        if not isinstance(result, tuple):
            return result
        metadata, server_type = result
        g.server_config.metadata = metadata
        g.server_config.issuer_url = issuer_url.rstrip("/")
        g.server_config.server_type = server_type
        g.server_config.save(session)

    client_form = ClientConfigForm()
    dynamic_registration_form = DynamicRegistrationForm()

    if not client_form.validate_on_submit():
        return render_template(
            "configure_client.html",
            client_form=client_form,
            dynamic_registration_form=dynamic_registration_form,
        )

    auth_playground.setup_oauth_runtime(
        current_app,
        client_form.client_id.data,
        client_form.client_secret.data,
        issuer_url,
    )
    flash("OAuth configuration completed successfully", "success")
    return redirect(url_for("routes.playground"))


@bp.route("/client/dynamic-registration", methods=["POST"])
def client_dynamic_registration():
    """Automatically register OAuth client using dynamic client registration."""
    form = DynamicRegistrationForm()

    if not form.validate_on_submit():
        flash("Invalid request", "error")
        return redirect(url_for("routes.configure_client"))

    if not g.server_config or not g.server_config.metadata:
        flash("Server metadata not found", "error")
        return redirect(url_for("routes.configure_client"))

    if not g.server_config.specs.oauth_2_dynamic_client_registration:
        flash("Dynamic client registration not supported", "error")
        return redirect(url_for("routes.configure_client"))

    registration_endpoint = g.server_config.metadata["registration_endpoint"]

    redirect_uris = [
        url_for("routes.login_callback", _external=True),
        url_for("routes.register_callback", _external=True),
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
            url_for("routes.logout_callback", _external=True),
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
        error_message = "Dynamic client registration failed"
        if hasattr(e, "response") and e.response is not None:
            try:
                error_data = e.response.json()
                if "error_description" in error_data:
                    error_message = f"Dynamic client registration failed: {error_data['error_description']}"
                elif "error" in error_data:
                    error_message = (
                        f"Dynamic client registration failed: {error_data['error']}"
                    )
            except ValueError:
                pass  # Response is not JSON, use default message
        flash(error_message, "error")
        return redirect(url_for("routes.configure_client"))
    except ValueError:
        flash("Invalid JSON response from registration endpoint", "error")
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

    g.server_config.save(session)

    flash(
        "Client successfully registered!",
        "success",
    )
    return redirect(url_for("routes.playground"))


@bp.route("/playground")
def playground():
    """Display the main playground page with OAuth 2.0 demonstration controls."""
    server_configured = auth_playground.is_oauth_server_from_env(current_app) or (
        g.server_config and g.server_config.issuer_url
    )
    client_configured = auth_playground.is_oauth_configured()

    if not server_configured:
        return redirect(url_for("routes.configure_server"))

    elif not client_configured:
        return redirect(url_for("routes.configure_client"))

    if g.server_config and not g.server_config.metadata:
        issuer_url = current_app.config.get("OAUTH_AUTH_SERVER")
        if issuer_url:
            try:
                metadata, server_type = fetch_server_metadata(issuer_url)
                g.server_config.metadata = metadata
                g.server_config.server_type = server_type
                if not current_app.config.get("OAUTH_AUTH_SERVER"):
                    g.server_config.save(session)
            except Exception:
                pass

    refresh_form = RefreshTokenForm()
    unregister_form = UnregisterClientForm()
    return render_template(
        "index.html",
        refresh_form=refresh_form,
        unregister_form=unregister_form,
    )


@bp.route("/specs")
def specs():
    """Display server specifications."""
    if not g.server_config or not g.server_config.specs:
        flash("No server configured", "warning")
        return redirect(url_for("routes.configure_server"))

    server_specs = g.server_config.specs
    supported_specs = [
        (
            spec,
            server_specs.get_spec_display_name(spec),
            server_specs.get_spec_url(spec),
        )
        for spec in server_specs.get_supported_specs()
    ]
    unsupported_specs = [
        (
            spec,
            server_specs.get_spec_display_name(spec),
            server_specs.get_spec_url(spec),
        )
        for spec in server_specs.get_unsupported_specs()
    ]
    unknown_specs = [
        (
            spec,
            server_specs.get_spec_display_name(spec),
            server_specs.get_spec_url(spec),
        )
        for spec in server_specs.get_unknown_specs()
    ]

    return render_template(
        "specs.html",
        supported_specs=supported_specs,
        unsupported_specs=unsupported_specs,
        unknown_specs=unknown_specs,
    )


@bp.route("/unregister-client", methods=["POST"])
def unregister_client():
    """Unregister OAuth client using dynamic client registration management."""
    form = UnregisterClientForm()

    if not form.validate_on_submit():
        flash("Invalid request", "error")
        return redirect(url_for("routes.playground"))

    if (
        not g.server_config
        or not g.server_config.registration_access_token
        or not g.server_config.registration_client_uri
    ):
        flash("Client registration management credentials not found", "error")
        return redirect(url_for("routes.playground"))

    headers = {"Authorization": f"Bearer {g.server_config.registration_access_token}"}

    try:
        response = requests.delete(
            g.server_config.registration_client_uri, headers=headers, timeout=10
        )
        response.raise_for_status()
    except requests.RequestException as e:
        error_message = "Client unregistration failed"
        if hasattr(e, "response") and e.response is not None:
            try:
                error_data = e.response.json()
                if "error_description" in error_data:
                    error_message = f"Client unregistration failed: {error_data['error_description']}"
                elif "error" in error_data:
                    error_message = (
                        f"Client unregistration failed: {error_data['error']}"
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
    g.server_config.save(session)

    flash("Client successfully unregistered", "success")
    return redirect(url_for("routes.configure_client"))


@bp.route("/tos")
def tos():
    """Display the Terms of Service page."""
    return render_template("tos.html")


@bp.route("/policy")
def policy():
    """Display the Privacy Policy page."""
    return render_template("policy.html")


@bp.route("/register")
def register():
    """Redirect users to the Identity Provider registration page."""
    return auth_playground.oauth.default.authorize_redirect(
        url_for("routes.register_callback", _external=True), prompt="create"
    )


@bp.route("/register_callback")
def register_callback():
    """Handle OAuth callback after user registration."""
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
        flash("You account has been successfully created.", "success")
    except AuthlibBaseError as exc:
        flash(f"An error happened during registration: {exc.description}", "error")

    return redirect(url_for("routes.playground"))


@bp.route("/login")
def login():
    """Redirect users to the Identity Provider login page."""
    if "user" in session:
        return auth_playground.oauth.default.authorize_redirect(
            url_for("routes.login_callback", _external=True), prompt="login"
        )
    else:
        return auth_playground.oauth.default.authorize_redirect(
            url_for("routes.login_callback", _external=True)
        )


@bp.route("/consent")
def consent():
    """Redirect users to the Identity Provider consent page."""
    return auth_playground.oauth.default.authorize_redirect(
        url_for("routes.login_callback", _external=True), prompt="consent"
    )


@bp.route("/login_callback")
def login_callback():
    """Handle OAuth callback after user login."""
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
        flash("You have been successfully logged in.", "success")
    except AuthlibBaseError as exc:
        flash(f"An error happened during login: {exc.description}", "error")

    return redirect(url_for("routes.playground"))


@bp.route("/logout/local")
def logout_local():
    """Log out locally without contacting the Identity Provider."""
    clear_user_session()
    flash("You have been logged out", "success")
    return redirect(url_for("routes.playground"))


@bp.route("/logout")
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
            post_logout_redirect_uri=url_for("routes.logout_callback", _external=True),
        ),
    )
    return redirect(end_session_url)


@bp.route("/logout_callback")
def logout_callback():
    """Handle callback after server-side logout."""
    clear_user_session()
    flash("You have been logged out from the server", "success")
    return redirect(url_for("routes.playground"))


@bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh the access token using the refresh token."""
    form = RefreshTokenForm()
    if not form.validate_on_submit():
        flash("Invalid request", "error")
        return redirect(url_for("routes.playground"))

    refresh_token = session.get("token", {}).get("refresh_token")
    if not refresh_token:
        flash("No refresh token available", "error")
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
        flash("Token successfully refreshed", "success")
    except AuthlibBaseError as exc:
        flash(f"An error happened during token refresh: {exc.description}", "error")

    return redirect(url_for("routes.playground"))

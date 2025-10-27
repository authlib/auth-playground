import requests
from authlib.common.errors import AuthlibBaseError
from authlib.common.urls import add_params_to_uri
from flask import Blueprint
from flask import current_app
from flask import flash
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for

import auth_playground
from auth_playground.forms import AutoRegisterForm
from auth_playground.forms import ClientConfigForm
from auth_playground.forms import RefreshTokenForm
from auth_playground.forms import ServerConfigForm
from auth_playground.forms import UnregisterClientForm
from auth_playground.metadata import ServerSpecs

bp = Blueprint("routes", __name__)


def get_server_display_name(server_type: str | None) -> str:
    """Get display name for the server type.

    :param server_type: Server type ('oidc' or 'oauth2')
    :return: Human-readable server name
    """
    if server_type == "oidc":
        return "OpenID Provider"
    else:
        return "OAuth 2.0 Authorization Server"


def fetch_server_metadata(issuer_url: str, timeout: int = 10) -> tuple[dict, str]:
    """Fetch server metadata from well-known endpoints.

    Tries OpenID Connect Discovery first, then OAuth 2.0 Authorization Server Metadata.

    :param issuer_url: The issuer URL
    :param timeout: Request timeout in seconds
    :return: Tuple of (metadata dictionary, server type: 'oidc' or 'oauth2')
    :raises requests.exceptions.RequestException: If both endpoints fail
    """
    oidc_url = f"{issuer_url}/.well-known/openid-configuration"
    try:
        response = requests.get(oidc_url, timeout=timeout)
        response.raise_for_status()
        return response.json(), "oidc"
    except requests.exceptions.RequestException:
        pass  # Try OAuth2 endpoint

    oauth2_url = f"{issuer_url}/.well-known/oauth-authorization-server"
    response = requests.get(oauth2_url, timeout=timeout)
    response.raise_for_status()
    return response.json(), "oauth2"


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
    try:
        del session["server_metadata"]
    except KeyError:
        pass

    try:
        del session["issuer_url"]
    except KeyError:
        pass

    try:
        del session["server_type"]
    except KeyError:
        pass

    try:
        del session["oauth_config"]
    except KeyError:
        pass


@bp.route("/")
def index():
    """Smart redirect to the appropriate configuration step or main page."""
    if auth_playground.oauth_configured:
        return redirect(url_for("routes.playground"))

    server_configured = auth_playground.is_oauth_config_from_env(
        current_app
    ) or session.get("issuer_url")

    if server_configured:
        return redirect(url_for("routes.configure_client"))

    return redirect(url_for("routes.configure_server"))


@bp.route("/playground")
def playground():
    """Display the main playground page with OAuth 2.0 demonstration controls."""
    oauth_fully_configured = auth_playground.oauth_configured or session.get(
        "oauth_config"
    )

    if not oauth_fully_configured:
        server_configured = session.get(
            "issuer_url"
        ) or auth_playground.is_oauth_config_from_env(current_app)

        if not server_configured:
            return redirect(url_for("routes.configure_server"))
        else:
            return redirect(url_for("routes.configure_client"))

    supports_prompt_create = False
    supports_rp_initiated_logout = False
    metadata = session.get("server_metadata")

    if not metadata:
        issuer_url = current_app.config.get("OAUTH_AUTH_SERVER")
        if issuer_url:
            try:
                metadata, _ = fetch_server_metadata(issuer_url)
                session["server_metadata"] = metadata
            except Exception:
                pass  # Ignore errors, metadata will remain None

    if metadata:
        specs = ServerSpecs(metadata)
        supports_prompt_create = specs.oidc_prompt_create or False
        supports_rp_initiated_logout = specs.oidc_rpinitiated_logout or False

    has_registration_token = bool(session.get("registration_access_token"))

    refresh_form = RefreshTokenForm()
    unregister_form = UnregisterClientForm()
    return render_template(
        "index.html",
        user=session.get("user"),
        token=session.get("token"),
        refresh_form=refresh_form,
        unregister_form=unregister_form,
        supports_prompt_create=supports_prompt_create,
        supports_rp_initiated_logout=supports_rp_initiated_logout,
        has_registration_token=has_registration_token,
    )


@bp.route("/specs")
def specs():
    """Display server specifications."""
    metadata = session.get("server_metadata")

    if not metadata:
        flash("No server configured", "warning")
        return redirect(url_for("routes.configure_server"))

    specs = ServerSpecs(metadata)
    supported_specs = [
        (spec, specs.get_spec_display_name(spec), specs.get_spec_url(spec))
        for spec in specs.get_supported_specs()
    ]
    unsupported_specs = [
        (spec, specs.get_spec_display_name(spec), specs.get_spec_url(spec))
        for spec in specs.get_unsupported_specs()
    ]
    unknown_specs = [
        (spec, specs.get_spec_display_name(spec), specs.get_spec_url(spec))
        for spec in specs.get_unknown_specs()
    ]

    return render_template(
        "specs.html",
        supported_specs=supported_specs,
        unsupported_specs=unsupported_specs,
        unknown_specs=unknown_specs,
    )


@bp.route("/server", methods=["GET", "POST"])
def configure_server():
    """Display form to configure and validate identity provider URL."""
    if auth_playground.is_oauth_config_from_env(current_app):
        flash(
            "OAuth configuration is set via environment variables and cannot be changed",
            "warning",
        )
        return redirect(url_for("routes.playground"))

    form = ServerConfigForm()

    if not form.validate_on_submit():
        if session.get("issuer_url"):
            flash("You can now configure a different identity provider", "info")
        clear_server_session()
        return render_template("configure_server.html", form=form)

    issuer_url = form.issuer_url.data.rstrip("/")

    try:
        metadata, server_type = fetch_server_metadata(issuer_url)
    except requests.exceptions.ConnectionError:
        flash("Cannot connect to the server. Please check the URL.", "error")
        return render_template("configure_server.html", form=form)
    except requests.exceptions.Timeout:
        flash("Connection timeout. The server is not responding.", "error")
        return render_template("configure_server.html", form=form)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            flash(
                "This server does not support OIDC Discovery or OAuth 2.0 Authorization Server Metadata",
                "error",
            )
        else:
            flash(f"Server returned an error: HTTP {e.response.status_code}", "error")
        return render_template("configure_server.html", form=form)
    except requests.RequestException:
        flash("Failed to connect to the server. Please check the URL.", "error")
        return render_template("configure_server.html", form=form)
    except ValueError:
        flash("Invalid response from server", "error")
        return render_template("configure_server.html", form=form)

    session["server_metadata"] = metadata
    session["issuer_url"] = issuer_url
    session["server_type"] = server_type

    flash("Server metadata successfully loaded", "success")

    if auth_playground.is_oauth_client_from_env(current_app):
        return redirect(url_for("routes.playground"))

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

    issuer_url = session.get("issuer_url") or current_app.config.get(
        "OAUTH_AUTH_SERVER"
    )
    if issuer_url:
        issuer_url = issuer_url.rstrip("/")

    if not issuer_url:
        flash("Please configure a server", "warning")
        return redirect(url_for("routes.configure_server"))

    metadata = session.get("server_metadata")

    if not metadata and issuer_url:
        try:
            metadata, server_type = fetch_server_metadata(issuer_url)
            session["server_metadata"] = metadata
            session["issuer_url"] = issuer_url
            session["server_type"] = server_type
        except requests.exceptions.ConnectionError:
            flash("Cannot connect to the server. Please check the URL.", "error")
            return redirect(url_for("routes.configure_server"))
        except requests.exceptions.Timeout:
            flash("Connection timeout. The server is not responding.", "error")
            return redirect(url_for("routes.configure_server"))
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                flash(
                    "This server does not support OIDC Discovery or OAuth 2.0 Authorization Server Metadata",
                    "error",
                )
            else:
                flash(
                    f"Server returned an error: HTTP {e.response.status_code}", "error"
                )
            return redirect(url_for("routes.configure_server"))
        except requests.RequestException:
            flash("Failed to connect to the server. Please check the URL.", "error")
            return redirect(url_for("routes.configure_server"))
        except ValueError:
            flash("Invalid response from server", "error")
            return redirect(url_for("routes.configure_server"))

    client_form = ClientConfigForm()
    auto_register_form = AutoRegisterForm()

    specs = ServerSpecs(metadata)
    has_registration = specs.oauth_2_dynamic_client_registration

    if not client_form.validate_on_submit():
        return render_template(
            "configure_client.html",
            client_form=client_form,
            auto_register_form=auto_register_form,
            metadata=metadata,
            has_registration=has_registration,
            issuer_url=issuer_url,
        )

    auth_playground.setup_oauth_runtime(
        current_app,
        client_form.client_id.data,
        client_form.client_secret.data,
        issuer_url,
    )
    flash("OAuth configuration completed successfully", "success")
    return redirect(url_for("routes.playground"))


@bp.route("/auto-register", methods=["POST"])
def auto_register_client():
    """Automatically register OAuth client using dynamic client registration."""
    form = AutoRegisterForm()

    if not form.validate_on_submit():
        flash("Invalid request", "error")
        return redirect(url_for("routes.configure_client"))

    metadata = session.get("server_metadata")
    issuer_url = session.get("issuer_url")

    if not metadata:
        flash("Server metadata not found", "error")
        return redirect(url_for("routes.configure_client"))

    specs = ServerSpecs(metadata)
    if not specs.oauth_2_dynamic_client_registration:
        flash("Dynamic client registration not supported", "error")
        return redirect(url_for("routes.configure_client"))

    registration_endpoint = metadata["registration_endpoint"]

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
    }

    if specs.oidc_rpinitiated_logout:
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
        error_message = "Auto-registration failed"
        if hasattr(e, "response") and e.response is not None:
            try:
                error_data = e.response.json()
                if "error_description" in error_data:
                    error_message = (
                        f"Auto-registration failed: {error_data['error_description']}"
                    )
                elif "error" in error_data:
                    error_message = f"Auto-registration failed: {error_data['error']}"
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
        issuer_url,
    )

    if "registration_access_token" in client_data:
        session["registration_access_token"] = client_data["registration_access_token"]
    if "registration_client_uri" in client_data:
        session["registration_client_uri"] = client_data["registration_client_uri"]

    flash(
        "Client successfully registered!",
        "success",
    )
    return redirect(url_for("routes.playground"))


@bp.route("/unregister-client", methods=["POST"])
def unregister_client():
    """Unregister OAuth client using dynamic client registration management."""
    form = UnregisterClientForm()

    if not form.validate_on_submit():
        flash("Invalid request", "error")
        return redirect(url_for("routes.playground"))

    registration_access_token = session.get("registration_access_token")
    registration_client_uri = session.get("registration_client_uri")

    if not registration_access_token or not registration_client_uri:
        flash("Client registration management credentials not found", "error")
        return redirect(url_for("routes.playground"))

    headers = {"Authorization": f"Bearer {registration_access_token}"}

    try:
        response = requests.delete(registration_client_uri, headers=headers, timeout=10)
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
    session.pop("registration_access_token", None)
    session.pop("registration_client_uri", None)
    session.pop("user", None)
    session.pop("token", None)

    auth_playground.oauth_configured = False
    if hasattr(auth_playground.oauth, "default"):
        delattr(auth_playground.oauth, "default")

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

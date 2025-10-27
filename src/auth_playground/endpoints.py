import requests
from authlib.common.errors import AuthlibBaseError
from authlib.common.urls import add_params_to_uri
from authlib.oidc.discovery import get_well_known_url
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

bp = Blueprint("routes", __name__)


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
        del session["oauth_config"]
    except KeyError:
        pass


@bp.route("/")
def index():
    """Smart redirect to the appropriate configuration step or main page."""
    if auth_playground.oauth_configured:
        return redirect(url_for("routes.home"))

    server_configured = auth_playground.is_oauth_config_from_env(
        current_app
    ) or session.get("issuer_url")

    if server_configured:
        return redirect(url_for("routes.configure_client"))

    return redirect(url_for("routes.configure_server"))


@bp.route("/home")
def home():
    if not auth_playground.oauth_configured and not session.get("oauth_config"):
        if not auth_playground.is_oauth_config_from_env(current_app):
            return redirect(url_for("routes.configure_server"))
        elif not auth_playground.is_oauth_client_from_env(current_app):
            return redirect(url_for("routes.configure_client"))

    if session.get("issuer_url") and not session.get("oauth_config"):
        return redirect(url_for("routes.configure_client"))

    refresh_form = RefreshTokenForm()
    return render_template(
        "index.html",
        user=session.get("user"),
        token=session.get("token"),
        refresh_form=refresh_form,
    )


@bp.route("/configure/server", methods=["GET", "POST"])
def configure_server():
    """Display form to configure and validate identity provider URL."""
    if auth_playground.is_oauth_config_from_env(current_app):
        flash(
            "OAuth configuration is set via environment variables and cannot be changed",
            "warning",
        )
        return redirect(url_for("routes.home"))

    form = ServerConfigForm()

    if not form.validate_on_submit():
        if session.get("issuer_url"):
            flash("You can now configure a different identity provider", "info")
        clear_server_session()
        return render_template("configure_server.html", form=form)

    issuer_url = form.issuer_url.data.rstrip("/")

    try:
        well_known_url = get_well_known_url(issuer_url, external=True)
        response = requests.get(well_known_url, timeout=10)
        response.raise_for_status()
        metadata = response.json()
    except requests.exceptions.ConnectionError:
        flash("Cannot connect to the server. Please check the URL.", "error")
        return render_template("configure_server.html", form=form)
    except requests.exceptions.Timeout:
        flash("Connection timeout. The server is not responding.", "error")
        return render_template("configure_server.html", form=form)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            flash("This server does not support OpenID Connect discovery", "error")
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

    flash("Server metadata successfully loaded", "success")

    if auth_playground.is_oauth_client_from_env(current_app):
        return redirect(url_for("routes.home"))

    return redirect(url_for("routes.configure_client"))


@bp.route("/configure/client", methods=["GET", "POST"])
def configure_client():
    """Display options to configure OAuth client credentials."""
    if auth_playground.is_oauth_client_from_env(current_app):
        flash(
            "OAuth client is set via environment variables and cannot be changed",
            "warning",
        )
        return redirect(url_for("routes.home"))

    issuer_url = session.get("issuer_url") or current_app.config.get(
        "OAUTH_AUTH_SERVER"
    )
    if issuer_url:
        issuer_url = issuer_url.rstrip("/")

    if not issuer_url:
        flash("Please configure the server first", "warning")
        return redirect(url_for("routes.configure_server"))

    metadata = session.get("server_metadata")

    if not metadata and issuer_url:
        try:
            well_known_url = get_well_known_url(issuer_url, external=True)
            response = requests.get(well_known_url, timeout=10)
            response.raise_for_status()
            metadata = response.json()
            session["server_metadata"] = metadata
            session["issuer_url"] = issuer_url
        except requests.exceptions.ConnectionError:
            flash("Cannot connect to the server. Please check the URL.", "error")
            return redirect(url_for("routes.configure_server"))
        except requests.exceptions.Timeout:
            flash("Connection timeout. The server is not responding.", "error")
            return redirect(url_for("routes.configure_server"))
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                flash("This server does not support OpenID Connect discovery", "error")
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

    has_registration = "registration_endpoint" in metadata

    client_form = ClientConfigForm()
    auto_register_form = AutoRegisterForm()

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
    return redirect(url_for("routes.home"))


@bp.route("/configure/auto-register", methods=["POST"])
def auto_register_client():
    """Automatically register OAuth client using dynamic client registration."""
    form = AutoRegisterForm()

    if not form.validate_on_submit():
        flash("Invalid request", "error")
        return redirect(url_for("routes.configure_client"))

    metadata = session.get("server_metadata")
    issuer_url = session.get("issuer_url")

    if not metadata or "registration_endpoint" not in metadata:
        flash("Dynamic client registration not supported", "error")
        return redirect(url_for("routes.configure_client"))

    registration_endpoint = metadata["registration_endpoint"]

    redirect_uris = [
        url_for("routes.login_callback", _external=True),
        url_for("routes.register_callback", _external=True),
    ]

    post_logout_redirect_uris = [
        url_for("routes.logout_callback", _external=True),
    ]

    registration_data = {
        "client_name": "Auth Playground",
        "client_uri": url_for("routes.home", _external=True),
        "redirect_uris": redirect_uris,
        "post_logout_redirect_uris": post_logout_redirect_uris,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "openid profile email phone address groups",
    }

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
        flash(f"Auto-registration failed: {str(e)}", "error")
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

    flash(
        "Client successfully registered!",
        "success",
    )
    return redirect(url_for("routes.home"))


@bp.route("/tos")
def tos():
    return render_template("tos.html")


@bp.route("/policy")
def policy():
    return render_template("policy.html")


@bp.route("/register")
def register():
    """Redirect users to the Identity Provider registration page."""
    return auth_playground.oauth.default.authorize_redirect(
        url_for("routes.register_callback", _external=True), prompt="create"
    )


@bp.route("/register_callback")
def register_callback():
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

    return redirect(url_for("routes.home"))


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

    return redirect(url_for("routes.home"))


@bp.route("/logout/local")
def logout_local():
    """Log out locally without contacting the Identity Provider."""
    clear_user_session()
    flash("You have been logged out locally from this application", "success")
    return redirect(url_for("routes.home"))


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
    clear_user_session()
    flash("You have been globally logged out", "success")
    return redirect(url_for("routes.home"))


@bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh the access token using the refresh token."""
    form = RefreshTokenForm()
    if not form.validate_on_submit():
        flash("Invalid request", "error")
        return redirect(url_for("routes.home"))

    refresh_token = session.get("token", {}).get("refresh_token")
    if not refresh_token:
        flash("No refresh token available", "error")
        return redirect(url_for("routes.home"))

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

    return redirect(url_for("routes.home"))

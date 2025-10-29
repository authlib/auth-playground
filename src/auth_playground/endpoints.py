import requests
from flask import Blueprint
from flask import current_app
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from flask_babel import gettext as _

import auth_playground
from auth_playground.forms import ClientConfigForm
from auth_playground.forms import DynamicRegistrationForm
from auth_playground.forms import RefreshTokenForm
from auth_playground.forms import ServerConfigForm
from auth_playground.forms import UnregisterClientForm
from auth_playground.oauth import clear_user_session
from auth_playground.session import ServerConfig

bp = Blueprint("routes", __name__)


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
        flash(_("Cannot connect to the server. Please check the URL."), "error")
        return on_error()
    except requests.exceptions.Timeout:
        flash(_("Connection timeout. The server is not responding."), "error")
        return on_error()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            flash(
                _(
                    "This server does not support OIDC Discovery or OAuth 2.0 Authorization Server Metadata"
                ),
                "error",
            )
        else:
            flash(
                _("Server returned an error: HTTP {status_code}").format(
                    status_code=e.response.status_code
                ),
                "error",
            )
        return on_error()
    except requests.RequestException:
        flash(_("Failed to connect to the server. Please check the URL."), "error")
        return on_error()
    except ValueError:
        flash(_("Invalid response from server"), "error")
        return on_error()


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
@bp.route("/server/<path:domain>", methods=["GET", "POST"])
def configure_server(domain=None):
    """Display form to configure and validate identity provider URL."""
    if auth_playground.is_oauth_server_from_env(current_app):
        flash(
            _(
                "OAuth configuration is set via environment variables and cannot be changed"
            ),
            "warning",
        )
        return redirect(url_for("routes.playground"))

    form = ServerConfigForm()

    if domain:
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"
        issuer_url = domain.rstrip("/")

    elif not form.validate_on_submit():
        if g.server_config and g.server_config.issuer_url:
            flash(_("You can now configure a different identity provider"), "info")
        clear_server_session()
        g.server_config = ServerConfig()
        return render_template("configure_server.html", form=form)

    else:
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

    flash(_("Server metadata successfully loaded"), "success")

    return redirect(url_for("routes.configure_client"))


@bp.route("/client", methods=["GET", "POST"])
def configure_client():
    """Display options to configure OAuth client credentials."""
    if auth_playground.is_oauth_client_from_env(current_app):
        flash(
            _("OAuth client is set via environment variables and cannot be changed"),
            "warning",
        )
        return redirect(url_for("routes.playground"))

    issuer_url = g.server_config.issuer_url
    if not issuer_url:
        flash(_("Please configure a server"), "warning")
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
    flash(_("OAuth configuration completed successfully"), "success")
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
        "playground.html",
        refresh_form=refresh_form,
        unregister_form=unregister_form,
    )


@bp.route("/specs")
def specs():
    """Display server specifications."""
    if not g.server_config or not g.server_config.specs:
        flash(_("No server configured"), "warning")
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


@bp.route("/tos")
def tos():
    """Display the Terms of Service page."""
    return render_template("tos.html")


@bp.route("/policy")
def policy():
    """Display the Privacy Policy page."""
    return render_template("policy.html")

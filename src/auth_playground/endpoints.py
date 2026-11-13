import requests
from flask import Blueprint
from flask import current_app
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask_babel import gettext as _

import auth_playground
from auth_playground.client_auth import KEY_METHOD
from auth_playground.client_auth import SECRET_METHODS
from auth_playground.client_key import key_summary
from auth_playground.decorators import server_config_needed
from auth_playground.forms import ChangeClientForm
from auth_playground.forms import ChangeServerForm
from auth_playground.forms import ClientConfigForm
from auth_playground.forms import DynamicRegistrationForm
from auth_playground.forms import ServerConfigForm
from auth_playground.forms import UnregisterClientForm
from auth_playground.grants import GRANTS_BY_NAME
from auth_playground.grants import tokens_grant
from auth_playground.oauth import forget_registered_client
from auth_playground.pages import render_grant_page
from auth_playground.pages import render_request_page
from auth_playground.pages import render_tokens_page
from auth_playground.session import ServerConfig

bp = Blueprint("routes", __name__)


def _get_metadata_document(url: str, timeout: int) -> dict:
    """Fetch a metadata document and check that it is a JSON object."""
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    metadata = response.json()
    if not isinstance(metadata, dict):
        raise requests.exceptions.InvalidJSONError(
            "The server metadata is not a JSON object", response=response
        )
    return metadata


class IssuerMismatchError(Exception):
    """The issuer of the server metadata is not the issuer URL entered.

    The issuer is ``None`` when the metadata has none.
    """

    def __init__(self, issuer):
        super().__init__(issuer)
        self.issuer = issuer


def fetch_server_metadata(issuer_url: str, timeout: int = 10) -> tuple[dict, str]:
    """Fetch server metadata from well-known OIDC or OAuth2 endpoints.

    Per OIDC Discovery §4.3 and RFC 8414 §3.3, the issuer of the metadata must
    be the issuer URL the well-known URL is built from. ``issuer_url`` has no
    trailing slash, and a trailing slash in the issuer is accepted.
    """
    metadata, server_type = _fetch_metadata_document(issuer_url, timeout)
    issuer = metadata.get("issuer")
    if not isinstance(issuer, str):
        raise IssuerMismatchError(None)
    if issuer.rstrip("/") != issuer_url:
        raise IssuerMismatchError(issuer)
    return metadata, server_type


def _fetch_metadata_document(issuer_url: str, timeout: int) -> tuple[dict, str]:
    """Fetch the OIDC metadata document, or else the OAuth2 one."""
    oidc_url = f"{issuer_url}/.well-known/openid-configuration"
    try:
        return _get_metadata_document(oidc_url, timeout), "oidc"
    except requests.exceptions.HTTPError as e:
        if e.response.status_code != 404:
            raise

    oauth2_url = f"{issuer_url}/.well-known/oauth-authorization-server"
    return _get_metadata_document(oauth2_url, timeout), "oauth2"


def metadata_error(exception: Exception) -> str:
    """Return why the server metadata could not be loaded, for the user."""
    if isinstance(exception, IssuerMismatchError) and exception.issuer is None:
        return _("The server metadata has no issuer.")
    if isinstance(exception, IssuerMismatchError):
        return _(
            "The issuer of the server metadata is {issuer}, not the URL "
            "you entered. A server must not use the issuer of another one."
        ).format(issuer=exception.issuer)
    if isinstance(exception, requests.exceptions.ConnectionError):
        return _("Cannot connect to the server. Please check the URL.")
    if isinstance(exception, requests.exceptions.Timeout):
        return _("Connection timeout. The server is not responding.")
    if isinstance(exception, requests.exceptions.HTTPError):
        if exception.response.status_code == 404:
            return _(
                "This server does not support OIDC Discovery or OAuth 2.0 Authorization Server Metadata"
            )
        return _("Server returned an error: HTTP {status_code}").format(
            status_code=exception.response.status_code
        )
    if isinstance(exception, requests.exceptions.InvalidJSONError):
        return _("Invalid response from server")
    if isinstance(exception, requests.RequestException):
        return _("Failed to connect to the server. Please check the URL.")
    current_app.logger.error("Cannot load the server metadata", exc_info=exception)
    return _("Cannot load the server metadata.")


def clear_server_session():
    """Clear all server-related data from the session."""
    auth_playground.forget_client()
    ServerConfig.clear(session)


def load_server_metadata() -> tuple[dict, str] | None:
    """Load the metadata of the provider set by the environment, if needed.

    The metadata go in g.server_config. On error, flash why and return None.
    """
    if g.server_config.metadata:
        return g.server_config.metadata, g.server_config.server_type

    issuer_url = current_app.config.get("OAUTH_AUTH_SERVER")
    if not issuer_url:
        return None

    issuer_url = issuer_url.rstrip("/")
    try:
        metadata, server_type = fetch_server_metadata(issuer_url)
    except Exception as e:
        flash(metadata_error(e), "error")
        return None

    g.server_config.metadata = metadata
    g.server_config.server_type = server_type
    g.server_config.issuer_url = issuer_url
    # The client was set up before the metadata, which can change its
    # signing algorithm.
    auth_playground.setup_oauth(current_app)

    return metadata, server_type


@bp.route("/")
def index():
    """Redirect to the appropriate configuration step or main page."""
    server_configured = auth_playground.is_server_configured()
    client_configured = auth_playground.is_client_configured()

    if not server_configured:
        return redirect(url_for("routes.configure_server"))

    elif not client_configured:
        return redirect(url_for("routes.configure_client"))

    elif not session.get("token"):
        return redirect(url_for("routes.request_tokens"))

    return redirect(url_for("routes.tokens"))


@bp.route("/server")
def configure_server():
    """Show the provider, or the ways to choose one."""
    if auth_playground.is_oauth_server_from_env(current_app):
        load_server_metadata()
        return render_template("configure_server.html", locked=True)

    if g.server_config.issuer_url:
        return render_template("configure_server.html", change_form=ChangeServerForm())

    if not current_app.debug:
        return redirect(url_for("routes.discover_server"))

    return render_template("configure_server.html")


@bp.route("/server/discover", methods=["GET", "POST"])
@bp.route("/server/<path:domain>")
def discover_server(domain=None):
    """Read the metadata of the provider at the URL the user enters.

    The /server/<domain> URL reads the metadata of that domain, only while no
    provider is set: a link on another site cannot replace the provider.
    """
    if auth_playground.is_server_configured():
        if domain or request.method == "POST":
            flash(_("A provider is already set. Change it to use another one."), "info")
        return redirect(url_for("routes.configure_server"))

    form = ServerConfigForm()

    if domain:
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"
        issuer_url = domain.rstrip("/")
        form.issuer_url.data = issuer_url

    elif not form.validate_on_submit():
        return render_template("server_discover.html", form=form)

    else:
        issuer_url = form.issuer_url.data.rstrip("/")

    try:
        metadata, server_type = fetch_server_metadata(issuer_url)
    except Exception as exc:
        form.issuer_url.errors = [metadata_error(exc)]
        return render_template("server_discover.html", form=form)

    g.server_config = ServerConfig(
        metadata=metadata,
        issuer_url=issuer_url,
        server_type=server_type,
    )

    return redirect(url_for("routes.configure_client"))


@bp.route("/server/static")
def static_server_configuration():
    """Explain how to set the provider and the client with environment variables."""
    if not current_app.debug or auth_playground.is_server_configured():
        return redirect(url_for("routes.configure_server"))
    return render_template("server_static.html")


@bp.route("/server/change", methods=["POST"])
def change_server():
    """Forget the provider, its client and the tokens."""
    if auth_playground.is_oauth_server_from_env(current_app):
        return redirect(url_for("routes.configure_server"))

    form = ChangeServerForm()
    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.configure_server"))

    if g.server_config.issuer_url:
        clear_server_session()
        # Otherwise save_server_config would store the old provider again.
        g.server_config = ServerConfig()
    return redirect(url_for("routes.configure_server"))


def current_client_key():
    """Return what the provider needs to know about the key of the client, if any."""
    config = auth_playground.get_oauth_config(current_app)
    if config.get("token_endpoint_auth_method") != KEY_METHOD:
        return None
    return key_summary(config["client_key"], config["token_endpoint_auth_signing_alg"])


@bp.route("/client")
@server_config_needed(client_needed=False)
def configure_client():
    """Show the client, or the ways to set one up."""
    if auth_playground.is_oauth_client_from_env(current_app):
        oauth_config = auth_playground.get_oauth_config(current_app)
        return render_template(
            "configure_client.html",
            locked=True,
            oauth_config=oauth_config,
            client_key=current_client_key(),
        )

    if auth_playground.is_client_configured():
        return render_template(
            "configure_client.html",
            configured=True,
            oauth_config=auth_playground.get_oauth_config(current_app),
            change_form=ChangeClientForm(),
            unregister_form=UnregisterClientForm(),
            client_key=current_client_key(),
        )

    if not g.server_config.dynamic_registration:
        return redirect(url_for("routes.manual_client"))

    return render_template("configure_client.html")


@bp.route("/client/dynamic")
@server_config_needed(client_needed=False)
def dynamic_client():
    """Show the dynamic registration form."""
    if auth_playground.is_client_configured():
        return redirect(url_for("routes.configure_client"))

    if not g.server_config.dynamic_registration:
        return redirect(url_for("routes.manual_client"))

    return render_template(
        "client_dynamic.html", dynamic_registration_form=DynamicRegistrationForm()
    )


@bp.route("/client/manual", methods=["GET", "POST"])
@server_config_needed(client_needed=False)
def manual_client():
    """Show the form to enter a client created at the provider, and save it."""
    if auth_playground.is_client_configured():
        if request.method == "POST":
            flash(_("A client is already set. Change it to use another one."), "info")
        return redirect(url_for("routes.configure_client"))

    client_form = ClientConfigForm()
    if not client_form.validate_on_submit():
        return render_template("client_manual.html", client_form=client_form)

    method = client_form.token_endpoint_auth_method.data
    uses_key = client_form.uses_key()
    auth_playground.setup_oauth_runtime(
        current_app,
        client_form.client_id.data,
        client_form.client_secret.data if method in SECRET_METHODS else None,
        g.server_config.issuer_url,
        method,
        client_key=client_form.client_key() if uses_key else None,
        signing_alg=client_form.signing_alg.data if uses_key else None,
        userinfo_alg=client_form.userinfo_signed_response_alg.data,
    )
    return redirect(url_for("routes.request_tokens"))


@bp.route("/client/change", methods=["POST"])
@server_config_needed(client_needed=False)
def change_client():
    """Forget the client and its tokens. A registered client stays at the provider."""
    if auth_playground.is_oauth_client_from_env(current_app):
        return redirect(url_for("routes.configure_client"))

    form = ChangeClientForm()
    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.configure_client"))

    forget_registered_client()
    return redirect(url_for("routes.configure_client"))


@bp.route("/request")
@server_config_needed
def request_tokens():
    """Show the grant types the client can use to obtain tokens."""
    return render_request_page()


@bp.route("/request/<grant>")
@server_config_needed
def grant_page(grant):
    """Show the form of a grant type."""
    if grant not in GRANTS_BY_NAME:
        return redirect(url_for("routes.request_tokens"))
    return render_grant_page(GRANTS_BY_NAME[grant])


TOKENS_TABS = ("current", "logout")


@bp.route("/tokens", endpoint="tokens")
@bp.route("/tokens/<tab>", endpoint="tokens")
@server_config_needed
def tokens_page(tab="current"):
    """Show the current tokens, or how to log out.

    Client tokens have no user to log out.
    """
    if not session.get("token"):
        return redirect(url_for("routes.request_tokens"))
    if tab not in TOKENS_TABS:
        return redirect(url_for("routes.tokens"))
    if tab == "logout" and not tokens_grant().provider_session:
        return redirect(url_for("routes.tokens"))

    return render_tokens_page(tab)


@bp.route("/specs")
@server_config_needed(client_needed=False)
def specs():
    """Display server specifications."""
    if not g.server_config.specs:
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

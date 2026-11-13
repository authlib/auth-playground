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
from auth_playground.grants import tokens_grant
from auth_playground.oauth import forget_registered_client
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


def _flash_metadata_error(exception: Exception) -> None:
    """Flash user-friendly error messages for metadata loading errors."""
    if isinstance(exception, IssuerMismatchError) and exception.issuer is None:
        flash(_("The server metadata has no issuer."), "error")
    elif isinstance(exception, IssuerMismatchError):
        flash(
            _(
                "The issuer of the server metadata is {issuer}, not the URL "
                "you entered. A server must not use the issuer of another one."
            ).format(issuer=exception.issuer),
            "error",
        )
    elif isinstance(exception, requests.exceptions.ConnectionError):
        flash(_("Cannot connect to the server. Please check the URL."), "error")
    elif isinstance(exception, requests.exceptions.Timeout):
        flash(_("Connection timeout. The server is not responding."), "error")
    elif isinstance(exception, requests.exceptions.HTTPError):
        if exception.response.status_code == 404:
            flash(
                _(
                    "This server does not support OIDC Discovery or OAuth 2.0 Authorization Server Metadata"
                ),
                "error",
            )
        else:
            flash(
                _("Server returned an error: HTTP {status_code}").format(
                    status_code=exception.response.status_code
                ),
                "error",
            )
    elif isinstance(exception, requests.exceptions.InvalidJSONError):
        flash(_("Invalid response from server"), "error")
    elif isinstance(exception, requests.RequestException):
        flash(_("Failed to connect to the server. Please check the URL."), "error")
    else:
        current_app.logger.error("Cannot load the server metadata", exc_info=exception)
        flash(_("Cannot load the server metadata."), "error")


def clear_server_session():
    """Clear all server-related data from the session."""
    auth_playground.forget_client()
    ServerConfig.clear(session)


def load_server_metadata(
    issuer_url: str | None = None,
    *,
    update_config: bool = True,
) -> tuple[dict, str] | None:
    """Load server metadata.

    If issuer_url is None, tries to get it from environment.
    If update_config is True, updates g.server_config with metadata.
    On error, displays a user-friendly message and returns None.
    """
    if update_config and g.server_config and g.server_config.metadata:
        return g.server_config.metadata, g.server_config.server_type

    if not issuer_url:
        issuer_url = current_app.config.get("OAUTH_AUTH_SERVER")

    if not issuer_url:
        return None

    issuer_url = issuer_url.rstrip("/")
    try:
        metadata, server_type = fetch_server_metadata(issuer_url)
    except Exception as e:
        _flash_metadata_error(e)
        return None

    if update_config and g.server_config:
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

    return redirect(url_for("routes.tokens"))


@bp.route("/server", methods=["GET", "POST"])
@bp.route("/server/<path:domain>", methods=["GET", "POST"])
def configure_server(domain=None):
    """Display form to configure and validate identity provider URL."""
    if auth_playground.is_oauth_server_from_env(current_app):
        load_server_metadata()
        return render_template("configure_server.html", locked=True)

    form = ServerConfigForm()

    if domain:
        if not domain.startswith(("http://", "https://")):
            domain = f"https://{domain}"
        issuer_url = domain.rstrip("/")

    elif not form.validate_on_submit():
        return render_server_page(form)

    else:
        issuer_url = form.issuer_url.data.rstrip("/")

    result = load_server_metadata(issuer_url, update_config=False)
    if not result:
        return render_server_page(form)
    metadata, server_type = result

    # The client and the tokens belong to the previous provider.
    if g.server_config.issuer_url and g.server_config.issuer_url != issuer_url:
        clear_server_session()

    g.server_config = ServerConfig(
        metadata=metadata,
        issuer_url=issuer_url,
        server_type=server_type,
    )

    flash(_("Server metadata successfully loaded"), "success")

    return redirect(url_for("routes.configure_client"))


def render_server_page(form):
    """Render the provider page, with the form to change the provider."""
    return render_template(
        "configure_server.html", form=form, change_form=ChangeServerForm()
    )


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
        flash(_("You can now configure a different identity provider"), "info")
    return redirect(url_for("routes.configure_server"))


def current_client_key():
    """Return what the provider needs to know about the key of the client, if any."""
    config = auth_playground.get_oauth_config(current_app)
    if config.get("token_endpoint_auth_method") != KEY_METHOD:
        return None
    return key_summary(config["client_key"], config["token_endpoint_auth_signing_alg"])


@bp.route("/client", methods=["GET", "POST"])
@server_config_needed(client_needed=False)
def configure_client():
    """Display options to configure OAuth client credentials."""
    if auth_playground.is_oauth_client_from_env(current_app):
        oauth_config = auth_playground.get_oauth_config(current_app)
        return render_template(
            "configure_client.html",
            locked=True,
            oauth_config=oauth_config,
            client_key=current_client_key(),
        )

    if auth_playground.is_client_configured() and request.method == "GET":
        return render_template(
            "configure_client.html",
            configured=True,
            oauth_config=auth_playground.get_oauth_config(current_app),
            change_form=ChangeClientForm(),
            unregister_form=UnregisterClientForm(),
            client_key=current_client_key(),
        )

    client_form = ClientConfigForm()
    if not client_form.validate_on_submit():
        return render_template(
            "configure_client.html",
            client_form=client_form,
            # It posts elsewhere: it must not read the data of the client form.
            dynamic_registration_form=DynamicRegistrationForm(formdata=None),
            client_key=current_client_key(),
        )

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
    flash(_("OAuth configuration completed successfully"), "success")
    return redirect(url_for("routes.tokens"))


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
    flash(_("You can now configure another client"), "info")
    return redirect(url_for("routes.configure_client"))


TOKENS_TABS = ("request", "current", "logout")


@bp.route("/tokens", endpoint="tokens")
@bp.route("/tokens/<tab>", endpoint="tokens")
@server_config_needed
def tokens_page(tab=None):
    """Display the tokens area: request, current tokens and logout sub-pages.

    Client tokens have no user to log out.
    """
    logged_in = bool(session.get("token"))
    args = request.args.to_dict()

    if tab is None:
        tab = "current" if logged_in and "grant" not in args else "request"
        return redirect(url_for("routes.tokens", tab=tab, **args))
    if tab not in TOKENS_TABS:
        return redirect(url_for("routes.tokens", **args))
    if not logged_in and tab != "request":
        return redirect(url_for("routes.tokens", tab="request", **args))
    if tab == "logout" and not tokens_grant().provider_session:
        return redirect(url_for("routes.tokens", tab="current"))

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

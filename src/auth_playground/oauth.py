import importlib.metadata
import time
import uuid
from urllib.parse import urlencode

import requests
from authlib.common.errors import AuthlibBaseError
from authlib.common.security import generate_token
from authlib.integrations.base_client import OAuthError
from flask import Blueprint
from flask import Response
from flask import abort
from flask import current_app
from flask import flash
from flask import g
from flask import jsonify
from flask import redirect
from flask import request
from flask import session
from flask import url_for
from flask_babel import gettext as _
from joserfc.errors import JoseError

import auth_playground
from auth_playground.authorization import authorization_params
from auth_playground.authorization import new_code_verifier
from auth_playground.authorization import pkce_params
from auth_playground.authorization import requested_scope
from auth_playground.client_auth import KEY_METHOD
from auth_playground.client_auth import METHODS
from auth_playground.client_auth import PUBLIC_METHOD
from auth_playground.client_auth import SECRET_METHODS
from auth_playground.client_key import jwks_uri
from auth_playground.client_key import key_algorithms
from auth_playground.client_key import key_id as client_key_id
from auth_playground.client_key import private_pem
from auth_playground.client_key import public_jwks
from auth_playground.client_key import publish_key
from auth_playground.client_key import published_jwks
from auth_playground.decorators import server_config_needed
from auth_playground.forms import AuthorizationParamsForm
from auth_playground.forms import ClientCredentialsForm
from auth_playground.forms import DynamicRegistrationForm
from auth_playground.forms import LogoutLocalForm
from auth_playground.forms import LogoutParamsForm
from auth_playground.forms import PasswordForm
from auth_playground.forms import RefreshTokenForm
from auth_playground.forms import UnregisterClientForm
from auth_playground.grants import tokens_grant
from auth_playground.pages import render_tokens_page
from auth_playground.session import server_metadata
from auth_playground.token_request import extra_token_params

bp = Blueprint("oauth", __name__)

# Authorization requests kept while waiting for their callback.
MAX_PENDING_AUTHORIZATIONS = 5


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


def forget_tokens():
    """Forget the user and the tokens."""
    for key in ("user", "token", "token_info"):
        session.pop(key, None)


def clear_user_session():
    """Forget the user, the tokens and the pending authorization requests."""
    forget_tokens()
    session.pop("authorization_requests", None)


@bp.route("/client/dynamic-registration", methods=["POST"])
@server_config_needed(client_needed=False)
def client_dynamic_registration():
    """Automatically register OAuth client using dynamic client registration."""
    form = DynamicRegistrationForm()

    if not form.validate_on_submit():
        errors = (
            []
            if "csrf_token" in form.errors
            else [
                *form.grant_types.errors,
                *form.private_key.errors,
                *form.signing_alg.errors,
            ]
        )
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
    client_key = form.client_key() if form.uses_key() else None
    signing_alg = form.signing_alg.data if client_key else None
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

    if client_key:
        registration_data["token_endpoint_auth_signing_alg"] = signing_alg
        if form.jwks_delivery.data == "jwks_uri":
            registration_data["jwks_uri"] = jwks_uri(client_key)
            # The provider may download the key during the registration.
            publish_key(client_key)
        else:
            registration_data["jwks"] = public_jwks(client_key)

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
    if auth_method in SECRET_METHODS and not client_secret:
        flash(
            _(
                "The server registered the client without a client secret, "
                "but its authentication method {auth_method} needs one. "
                "The client is still registered on the server."
            ).format(auth_method=auth_method),
            "error",
        )
        return redirect(url_for("routes.configure_client"))

    if auth_method == KEY_METHOD and not client_key:
        flash(
            _(
                "The server registered the client with the private_key_jwt "
                "authentication method, but the playground has no key for it. "
                "The client is still registered on the server."
            ),
            "error",
        )
        return redirect(url_for("routes.configure_client"))

    uses_key = auth_method == KEY_METHOD
    if uses_key:
        # Per RFC 7591 §3.2.1, the server may choose another algorithm.
        signing_alg = client_data.get("token_endpoint_auth_signing_alg") or signing_alg
        if signing_alg not in key_algorithms(client_key):
            flash(
                _(
                    "The server registered the client with the {alg} signing "
                    "algorithm, which its key cannot use. "
                    "The client is still registered on the server."
                ).format(alg=signing_alg),
                "error",
            )
            return redirect(url_for("routes.configure_client"))

    auth_playground.setup_oauth_runtime(
        current_app,
        client_data["client_id"],
        client_secret if auth_method in SECRET_METHODS else None,
        g.server_config.issuer_url,
        auth_method,
        client_key=client_key if uses_key else None,
        signing_alg=signing_alg if uses_key else None,
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
    return redirect(url_for("routes.tokens"))


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

    auth_playground.forget_client()

    g.server_config.registration_access_token = None
    g.server_config.registration_client_uri = None

    flash(_("Client successfully unregistered"), "success")
    return redirect(url_for("routes.configure_client"))


@bp.route("/jwks/<key_id>.json")
def client_jwks(key_id):
    """Serve the public key of a private_key_jwt client, for its provider."""
    if (env_key := current_app.config.get("OAUTH_CLIENT_KEY")) and key_id == (
        client_key_id(env_key)
    ):
        return jsonify(public_jwks(env_key))

    if not (jwks := published_jwks(key_id)):
        abort(404)
    return jsonify(jwks)


@bp.route("/client/key.pem")
def client_private_key():
    """Download the private key of the client of the session."""
    oauth_config = session.get("oauth_config") or {}
    if not (client_key := oauth_config.get("client_key")):
        abort(404)

    return Response(
        private_pem(client_key),
        mimetype="application/x-pem-file",
        headers={
            "Content-Disposition": "attachment; filename=client-key.pem",
            "Cache-Control": "no-store",
        },
    )


@bp.route("/authorize", methods=["GET", "POST"])
@server_config_needed
def authorize():
    """Redirect users to the Identity Provider authorization page."""
    form = AuthorizationParamsForm()
    if request.method == "POST" and not form.validate_on_submit():
        if "csrf_token" in form.errors:
            flash(_("Invalid request"), "error")
        return render_tokens_page(
            "request", grant="authorization_code", grant_form=form
        )

    params = authorization_params(form)
    if request.method == "GET" and "user" in session:
        params["prompt"] = "login"

    pending = {"scope": params["scope"]}
    if method := form.pkce.data:
        code_verifier = new_code_verifier()
        params.update(pkce_params(method, code_verifier))
        pending.update(code_verifier=code_verifier, pkce=method)

    state = generate_token(30)
    save_authorization_request(state, pending)
    return auth_playground.oauth.default.authorize_redirect(
        url_for("oauth.authorize_callback", _external=True), state=state, **params
    )


def save_authorization_request(state, pending):
    """Keep what the callback needs, by state, for the recent requests only."""
    requests = dict(session.get("authorization_requests", {}))
    requests[state] = pending
    session["authorization_requests"] = dict(
        list(requests.items())[-MAX_PENDING_AUTHORIZATIONS:]
    )


def pop_authorization_request(state):
    """Return and forget what the authorization request of ``state`` needs."""
    requests = dict(session.get("authorization_requests", {}))
    pending = requests.pop(state, {})
    session["authorization_requests"] = requests
    return pending


def store_token(token, grant_type, requested_scope=None, pkce=None):
    """Store the token and how it was obtained in the session.

    ``grant`` is the grant type that first obtained the tokens. A refresh keeps it.
    """
    old_token = session.get("token", {})
    old_info = session.get("token_info", {})
    session["token"] = {
        "access_token": token.get("access_token"),
        "refresh_token": token.get("refresh_token") or old_token.get("refresh_token"),
        "id_token": token.get("id_token") or old_token.get("id_token"),
        "token_type": token.get("token_type"),
        "expires_in": token.get("expires_in"),
        "expires_at": token.get("expires_at"),
        "scope": token.get("scope"),
    }
    oauth_config = auth_playground.get_oauth_config(current_app)
    session["token_info"] = {
        "grant_type": grant_type,
        "grant": old_info.get("grant") if grant_type == "refresh_token" else grant_type,
        "client_auth": oauth_config.get("token_endpoint_auth_method"),
        "pkce": pkce,
        "requested_scope": requested_scope,
        "token_endpoint": server_metadata().get("token_endpoint"),
        "obtained_at": int(time.time()),
        "response": {key: value for key, value in token.items() if key != "userinfo"},
    }


def fetch_tokens(grant_type, form, **params):
    """Request tokens at the token endpoint, or flash why it failed."""
    if not server_metadata().get("token_endpoint"):
        flash(_("The provider has no token endpoint."), "error")
        return None

    try:
        return auth_playground.oauth.default.fetch_access_token(
            grant_type=grant_type,
            body=urlencode(extra_token_params(form)),
            timeout=10,
            **params,
        )
    except AuthlibBaseError as exc:
        error = exc.description or exc.error
    except requests.HTTPError as exc:
        error = get_response_error(exc) or str(exc)
    except (requests.RequestException, ValueError) as exc:
        error = str(exc)

    flash(_("The token request failed: {error}").format(error=error), "error")
    return None


def render_grant_form(grant_type, form):
    """Render the request tab again, with the form of ``grant_type``."""
    if "csrf_token" in form.errors:
        flash(_("Invalid request"), "error")
    return render_tokens_page("request", grant=grant_type, grant_form=form)


@bp.route("/token/client-credentials", methods=["POST"])
@server_config_needed
def client_credentials():
    """Request tokens for the client itself, without any user."""
    form = ClientCredentialsForm()
    if not form.validate_on_submit():
        return render_grant_form("client_credentials", form)

    scope = requested_scope(form)
    # An empty scope keeps Authlib from sending the default scope.
    token = fetch_tokens("client_credentials", form, scope=scope)
    if token is None:
        return render_grant_form("client_credentials", form)

    forget_tokens()
    store_token(token, "client_credentials", requested_scope=scope or None)
    flash(_("The client obtained tokens."), "success")
    return redirect(url_for("routes.tokens", tab="current"))


@bp.route("/token/password", methods=["POST"])
@server_config_needed
def password():
    """Request tokens with the username and password of the user."""
    form = PasswordForm()
    if not form.validate_on_submit():
        return render_grant_form("password", form)

    scope = requested_scope(form)
    token = fetch_tokens(
        "password",
        form,
        username=form.username.data,
        password=form.password.data,
        scope=scope,
    )
    if token is None:
        return render_grant_form("password", form)

    forget_tokens()
    store_token(token, "password", requested_scope=scope or None)
    session["user"] = read_id_token(token)
    if session["user"]:
        flash(_("You have been successfully logged in."), "success")
    else:
        flash(
            _("Tokens obtained for {username}.").format(username=form.username.data),
            "success",
        )
    return redirect(url_for("routes.tokens", tab="current"))


def read_id_token(token):
    """Return the claims of the ID token, or flash why it cannot be read.

    The password grant sends no nonce, so the ID token has none to check.
    """
    try:
        return auth_playground.oauth.default.parse_id_token(token, nonce=None)
    except requests.RequestException as exc:
        flash(
            _("The signing keys of the provider could not be fetched: {error}").format(
                error=exc
            ),
            "warning",
        )
    except (JoseError, RuntimeError, ValueError, KeyError) as exc:
        flash(_("The ID token is not valid: {error}").format(error=exc), "warning")
    return None


@bp.route("/authorize_callback")
def authorize_callback():
    """Handle OAuth callback after user authorization."""
    pending = pop_authorization_request(request.args.get("state"))
    kwargs = {}
    if code_verifier := pending.get("code_verifier"):
        kwargs["code_verifier"] = code_verifier

    try:
        token = auth_playground.oauth.default.authorize_access_token(**kwargs)
    except AuthlibBaseError as exc:
        flash(
            _("An error happened during login: {error}").format(
                error=exc.description or exc.error
            ),
            "error",
        )
        return redirect(url_for("routes.tokens"))
    except JoseError as exc:
        flash(_("The ID token is not valid: {error}").format(error=exc), "error")
        return redirect(url_for("routes.tokens"))
    except requests.RequestException as exc:
        flash(
            _("An error happened during login: {error}").format(
                error=get_response_error(exc) or exc
            ),
            "error",
        )
        return redirect(url_for("routes.tokens"))

    session.pop("token", None)
    session["user"] = token.get("userinfo")
    store_token(
        token,
        "authorization_code",
        requested_scope=pending.get("scope"),
        pkce=pending.get("pkce"),
    )
    flash(_("You have been successfully logged in."), "success")
    return redirect(url_for("routes.tokens"))


@bp.route("/logout/local", methods=["POST"])
def logout_local():
    """Log out locally without contacting the Identity Provider."""
    form = LogoutLocalForm()
    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.tokens"))

    message = (
        _("The tokens were forgotten")
        if not tokens_grant().provider_session
        else _("You have been logged out")
    )
    clear_user_session()
    flash(message, "success")
    return redirect(url_for("routes.tokens"))


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
    return redirect(url_for("routes.tokens"))


@bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh the access token using the refresh token."""
    form = RefreshTokenForm()
    if not form.validate_on_submit():
        flash(_("Invalid request"), "error")
        return redirect(url_for("routes.tokens"))

    refresh_token = session.get("token", {}).get("refresh_token")
    if not refresh_token:
        flash(_("No refresh token available"), "error")
        return redirect(url_for("routes.tokens"))

    try:
        original_scope = session.get("token", {}).get("scope", "")
        new_token = auth_playground.oauth.default.fetch_access_token(
            grant_type="refresh_token",
            refresh_token=refresh_token,
            scope=original_scope,
        )

        store_token(new_token, "refresh_token", requested_scope=original_scope)
        flash(_("Token successfully refreshed"), "success")
    except AuthlibBaseError as exc:
        flash(
            _("An error happened during token refresh: {error}").format(
                error=exc.description or exc.error
            ),
            "error",
        )

    return redirect(url_for("routes.tokens"))

import importlib.metadata
import os
import tempfile
import time

from authlib.oauth2.rfc7523 import ClientSecretJWT
from authlib.oauth2.rfc7523 import PrivateKeyJWT
from authlib.oidc.discovery import get_well_known_url
from cachelib.file import FileSystemCache
from cachelib.simple import SimpleCache
from flask import Flask
from flask import abort
from flask import current_app
from flask import g
from flask import has_request_context
from flask import redirect
from flask import request
from flask import session as flask_session
from flask import url_for
from flask_babel import gettext as _
from flask_session import Session
from werkzeug.local import LocalProxy
from werkzeug.middleware.proxy_fix import ProxyFix

from auth_playground.authorization import DEFAULT_SCOPE
from auth_playground.client_auth import KEY_METHOD
from auth_playground.client_auth import advertised_signing_algs
from auth_playground.client_auth import default_method
from auth_playground.client_key import PENDING_KEY
from auth_playground.client_key import check_private_key
from auth_playground.client_key import key_algorithms
from auth_playground.client_key import load_key
from auth_playground.client_key import preferred_algorithm
from auth_playground.client_key import publish_key
from auth_playground.client_key import unpublish_key
from auth_playground.endpoints import bp
from auth_playground.i18n import babel
from auth_playground.i18n import setup_i18n
from auth_playground.oauth import bp as oauth_bp
from auth_playground.oauth import clear_user_session
from auth_playground.oauth_client import PlaygroundOAuth
from auth_playground.session import ServerConfig
from auth_playground.session import server_metadata
from auth_playground.steps import setup_steps

sess = Session()


def get_oauth_registry():
    """Return the OAuth registry of the current request."""
    if "oauth" not in g:
        g.oauth = PlaygroundOAuth(current_app)
    return g.oauth


oauth = LocalProxy(get_oauth_registry)


def is_client_configured():
    """Check if OAuth client is configured by checking the registry."""
    return "default" in oauth._registry


def is_oauth_server_from_env(app):
    """Check if OAuth server is set via environment variables."""
    return bool(app.config.get("OAUTH_AUTH_SERVER"))


def is_server_configured():
    """Check if OAuth server is configured (from env or session)."""
    return is_oauth_server_from_env(current_app) or (
        g.server_config and g.server_config.issuer_url
    )


def is_oauth_client_from_env(app):
    """Check if OAuth client credentials are set via environment variables."""
    return bool(app.config.get("OAUTH_CLIENT_ID"))


def get_oauth_config(app):
    """Get OAuth config from environment or session, with env taking priority."""
    env_config = {
        "client_id": app.config.get("OAUTH_CLIENT_ID"),
        "client_secret": app.config.get("OAUTH_CLIENT_SECRET"),
        "auth_server": app.config.get("OAUTH_AUTH_SERVER"),
    }

    session_config = {}
    if has_request_context():
        session_config = flask_session.get("oauth_config", {})
    config = {
        **session_config,
        **{k: v for k, v in env_config.items() if v is not None},
    }
    if is_oauth_client_from_env(app):
        config["token_endpoint_auth_method"] = default_method(
            config.get("client_secret"), app.config.get("OAUTH_CLIENT_KEY")
        )
        if client_key := app.config.get("OAUTH_CLIENT_KEY"):
            config["client_key"] = client_key
            config["token_endpoint_auth_signing_alg"] = env_signing_alg(client_key)
    elif config.get("client_id"):
        config.setdefault(
            "token_endpoint_auth_method", default_method(config.get("client_secret"))
        )

    return config


def env_signing_alg(client_key):
    """Return the algorithm of the key set by the environment.

    It is the first one the key can use that the server advertises, else the
    first one the key can use.
    """
    return preferred_algorithm(
        key_algorithms(client_key), advertised_signing_algs(server_metadata())
    )


def setup_oauth(app):
    """Initialize OAuth client with configuration from environment or session.

    Each request gets its own registry, so it uses the client of its own session.
    """
    registry = PlaygroundOAuth(app)
    g.oauth = registry

    config = get_oauth_config(app)
    if not config.get("client_id"):
        return False

    client_secret = config.get("client_secret")
    client_auth_methods = [ClientSecretJWT()]
    if config["token_endpoint_auth_method"] == KEY_METHOD:
        client_secret = load_key(config["client_key"])
        client_auth_methods.append(
            PrivateKeyJWT(alg=config["token_endpoint_auth_signing_alg"])
        )

    registry.register(
        name="default",
        client_id=config["client_id"],
        client_secret=client_secret,
        server_metadata_url=get_well_known_url(config["auth_server"], external=True),
        client_kwargs={
            # Every request of the Authlib client: metadata, token, JWKS, UserInfo.
            "default_timeout": 10,
            "scope": DEFAULT_SCOPE,
            "token_endpoint_auth_method": config["token_endpoint_auth_method"],
        },
        client_auth_methods=client_auth_methods,
    )
    if metadata := server_metadata():
        # Reuse the metadata already loaded, instead of fetching it again.
        client = registry.create_client("default")
        client.server_metadata.update(metadata, _loaded_at=time.time())
    return True


def setup_oauth_runtime(
    app,
    client_id,
    client_secret,
    auth_server,
    token_endpoint_auth_method,
    client_key=None,
    signing_alg=None,
):
    """Set up OAuth with runtime configuration stored in session.

    The tokens and the key of the previous client are forgotten. The public
    key of the new client is served at its jwks_uri.
    """
    forget_client()
    flask_session["oauth_config"] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "auth_server": auth_server,
        "token_endpoint_auth_method": token_endpoint_auth_method,
    }
    if client_key:
        flask_session["oauth_config"].update(
            client_key=client_key, token_endpoint_auth_signing_alg=signing_alg
        )
        publish_key(client_key)

    return setup_oauth(app)


def forget_client():
    """Forget the client of the session, its tokens and its key."""
    clear_user_session()
    for pending in (flask_session.pop(PENDING_KEY, None) or {}).values():
        unpublish_key(pending)
    oauth_config = flask_session.pop("oauth_config", None) or {}
    if client_key := oauth_config.get("client_key"):
        unpublish_key(client_key)


def is_proxy_fix_enabled():
    """Read from the environment whether the application runs behind a proxy."""
    value = os.environ.get("PROXY_FIX", "").strip().lower()
    if value in ("", "0", "false"):
        return False
    if value in ("1", "true"):
        return True
    raise ValueError(f"PROXY_FIX must be true or false, got {value!r}")


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY", "dev-secret-key-change-in-production"
    )
    app.config["NAME"] = os.environ.get("APP_NAME", "Auth Playground")

    app.config["SESSION_TYPE"] = "cachelib"
    app.config["SESSION_CACHELIB"] = (
        SimpleCache()
        if app.debug
        else FileSystemCache(os.path.join(tempfile.gettempdir(), "flask_sessions"))
    )
    app.config["SESSION_PERMANENT"] = False
    # Only store the session when a request changes it. Otherwise concurrent
    # requests, such as htmx ones, overwrite each other's changes.
    app.config["SESSION_REFRESH_EACH_REQUEST"] = False

    app.config["BABEL_DEFAULT_LOCALE"] = "en"
    app.config["BABEL_DEFAULT_TIMEZONE"] = "UTC"

    oauth_auth_server_env = os.environ.get("OAUTH_AUTH_SERVER")
    app.config["OAUTH_CLIENT_ID"] = os.environ.get("OAUTH_CLIENT_ID")
    app.config["OAUTH_CLIENT_SECRET"] = os.environ.get("OAUTH_CLIENT_SECRET")
    app.config["OAUTH_CLIENT_KEY"] = None
    app.config["OAUTH_AUTH_SERVER"] = (
        oauth_auth_server_env.rstrip("/") if oauth_auth_server_env else None
    )
    app.config["SERVER_NAME"] = os.environ.get("SERVER_NAME")
    if is_proxy_fix_enabled():
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_prefix=1)

    sess.init_app(app)
    setup_i18n(app)
    if private_key := os.environ.get("OAUTH_CLIENT_PRIVATE_KEY"):
        with app.app_context():
            app.config["OAUTH_CLIENT_KEY"] = check_private_key(private_key)

    app.register_blueprint(oauth_bp)
    app.register_blueprint(bp, url_prefix="/<lang:lang_code>")

    @app.route("/")
    def root():
        """Redirect to the appropriate language prefix based on browser preference."""
        available_langs = [locale.language for locale in babel.list_translations()]
        default_lang = app.config.get("BABEL_DEFAULT_LOCALE", "en")
        lang = request.accept_languages.best_match(available_langs) or default_lang
        return redirect(url_for("routes.index", lang_code=lang))

    @app.before_request
    def redirect_to_server_name():
        """Redirect requests to SERVER_NAME if host doesn't match."""
        server_name = app.config.get("SERVER_NAME")
        if not server_name or request.host == server_name:
            return None

        if request.method != "GET":
            abort(
                400,
                _("This request should be sent to %(server_name)s")
                % {"server_name": server_name},
            )

        url = f"{request.scheme}://{server_name}{request.path}"
        if request.query_string:
            url += "?" + request.query_string.decode()

        return redirect(url)

    @app.before_request
    def load_server_config():
        """Load server configuration into flask.g."""
        if not g.get("server_config"):
            g.server_config = ServerConfig.deserialize(flask_session)
            if not g.server_config:
                g.server_config = ServerConfig()
            if issuer_url := app.config.get("OAUTH_AUTH_SERVER"):
                g.server_config.issuer_url = issuer_url

        setup_oauth(app)

    @app.after_request
    def keep_client_key_published(response):
        """Serve the public key of the client as long as its session lasts.

        Flask runs the after_request functions in reverse order: this one
        runs after save_server_config, which can change the session.
        """
        oauth_config = flask_session.get("oauth_config") or {}
        if flask_session.modified and (client_key := oauth_config.get("client_key")):
            publish_key(client_key)
        return response

    @app.after_request
    def save_server_config(response):
        """Automatically save server configuration to session after each request."""
        if (
            g.get("server_config")
            and not app.config.get("OAUTH_AUTH_SERVER")
            and (g.server_config.metadata or g.server_config.issuer_url)
        ):
            g.server_config.save(flask_session)
        return response

    @app.context_processor
    def inject_server_info():
        """Inject server information into all templates."""
        pkg_metadata = importlib.metadata.metadata("auth-playground")
        project_urls = dict(
            [url.split(", ", 1) for url in pkg_metadata.get_all("Project-URL") or []]
        )
        return {
            "app_version": importlib.metadata.version("auth-playground"),
            "repository_url": project_urls.get("repository"),
            "server_configured": is_server_configured(),
            "setup_steps": setup_steps,
        }

    return app

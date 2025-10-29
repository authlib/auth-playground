import importlib.metadata
import os

from authlib.integrations.flask_client import OAuth
from authlib.oidc.discovery import get_well_known_url
from cachelib.simple import SimpleCache
from flask import Flask
from flask import g
from flask import has_request_context
from flask import redirect
from flask import request
from flask import session as flask_session
from flask import url_for
from flask_session import Session

from auth_playground.endpoints import bp
from auth_playground.i18n import babel
from auth_playground.i18n import setup_i18n
from auth_playground.oauth import bp as oauth_bp
from auth_playground.session import ServerConfig

oauth = OAuth()
sess = Session()


def is_oauth_configured():
    """Check if OAuth client is configured by checking the registry."""
    return "default" in oauth._registry


def is_oauth_server_from_env(app):
    """Check if OAuth server is set via environment variables."""
    return bool(app.config.get("OAUTH_AUTH_SERVER"))


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

    return config


def setup_oauth(app):
    """Initialize OAuth client with configuration from environment or session."""
    if "default" in oauth._registry:
        del oauth._registry["default"]

    config = get_oauth_config(app)
    if not config:
        return False

    oauth.init_app(app)

    oauth.register(
        name="default",
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        server_metadata_url=get_well_known_url(config["auth_server"], external=True),
        client_kwargs={"scope": "openid profile email phone address groups"},
    )
    return True


def setup_oauth_runtime(app, client_id, client_secret, auth_server):
    """Set up OAuth with runtime configuration stored in session."""
    flask_session["oauth_config"] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "auth_server": auth_server,
    }

    return setup_oauth(app)


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY", "dev-secret-key-change-in-production"
    )
    app.config["NAME"] = os.environ.get("APP_NAME", "Auth Playground")

    app.config["SESSION_TYPE"] = "cachelib"
    app.config["SESSION_CACHELIB"] = SimpleCache()
    app.config["SESSION_PERMANENT"] = False

    app.config["BABEL_DEFAULT_LOCALE"] = "en"
    app.config["BABEL_DEFAULT_TIMEZONE"] = "UTC"

    oauth_auth_server_env = os.environ.get("OAUTH_AUTH_SERVER")
    app.config["OAUTH_CLIENT_ID"] = os.environ.get("OAUTH_CLIENT_ID")
    app.config["OAUTH_CLIENT_SECRET"] = os.environ.get("OAUTH_CLIENT_SECRET")
    app.config["OAUTH_AUTH_SERVER"] = (
        oauth_auth_server_env.rstrip("/") if oauth_auth_server_env else None
    )

    sess.init_app(app)
    setup_i18n(app)

    # Register OAuth blueprint without language prefix (technical endpoints)
    app.register_blueprint(oauth_bp)

    # Register main blueprint with mandatory language prefix (/<lang:lang_code>/...)
    # The 'lang' converter validates that lang_code is an available language
    app.register_blueprint(bp, url_prefix="/<lang:lang_code>")

    @app.route("/")
    def root():
        """Redirect to the appropriate language prefix based on browser preference."""
        available_langs = [locale.language for locale in babel.list_translations()]
        default_lang = app.config.get("BABEL_DEFAULT_LOCALE", "en")
        lang = request.accept_languages.best_match(available_langs) or default_lang
        return redirect(url_for("routes.index", lang_code=lang))

    @app.before_request
    def load_server_config():
        """Load server configuration into flask.g."""
        setup_oauth(app)

        if not g.get("server_config"):
            g.server_config = ServerConfig.deserialize(flask_session)
            if not g.server_config:
                g.server_config = ServerConfig()
            if issuer_url := app.config.get("OAUTH_AUTH_SERVER"):
                g.server_config.issuer_url = issuer_url

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
        }

    return app

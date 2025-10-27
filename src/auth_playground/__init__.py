import os

from authlib.integrations.flask_client import OAuth
from authlib.oidc.discovery import get_well_known_url
from cachelib.simple import SimpleCache
from dotenv import load_dotenv
from flask import Flask
from flask_babel import Babel
from flask_session import Session

from auth_playground.endpoints import bp

oauth = OAuth()
oauth_configured = False
sess = Session()
babel = Babel()


def get_oauth_config_from_session():
    """Get OAuth configuration from Flask session if available."""
    from flask import has_request_context
    from flask import session

    if not has_request_context():
        return None

    oauth_config = session.get("oauth_config")
    if not oauth_config:
        return None

    return oauth_config


def get_oauth_config_from_env(app):
    """Get OAuth configuration from app config (environment variables)."""
    client_id = app.config.get("OAUTH_CLIENT_ID")
    client_secret = app.config.get("OAUTH_CLIENT_SECRET")
    auth_server = app.config.get("OAUTH_AUTH_SERVER")

    if not all([client_id, client_secret, auth_server]):
        return None

    return {
        "client_id": client_id,
        "client_secret": client_secret,
        "auth_server": auth_server.rstrip("/"),
    }


def is_oauth_config_from_env(app):
    """Check if OAuth server is set via environment variables."""
    return bool(app.config.get("OAUTH_AUTH_SERVER"))


def is_oauth_client_from_env(app):
    """Check if OAuth client credentials are set via environment variables."""
    return bool(
        app.config.get("OAUTH_CLIENT_ID") and app.config.get("OAUTH_CLIENT_SECRET")
    )


def get_oauth_config(app):
    """Get OAuth config from environment or session, with env taking priority."""
    env_config = get_oauth_config_from_env(app)
    if env_config:
        return env_config

    session_config = get_oauth_config_from_session()
    if session_config:
        return session_config

    return None


def unregister_oauth_client():
    """Remove existing OAuth client registration if present."""
    if "default" in oauth._registry:
        del oauth._registry["default"]


def register_oauth_client(config):
    """Register OAuth client with Authlib using provided configuration."""
    oauth.register(
        name="default",
        client_id=config["client_id"],
        client_secret=config["client_secret"],
        server_metadata_url=get_well_known_url(config["auth_server"], external=True),
        client_kwargs={"scope": "openid profile email phone address groups"},
    )


def setup_oauth(app):
    """Initialize OAuth client with configuration from environment or session."""
    global oauth_configured

    config = get_oauth_config(app)
    if not config:
        app.logger.warning("OAuth not configured")
        oauth_configured = False
        return False

    unregister_oauth_client()
    oauth.init_app(app)
    register_oauth_client(config)
    oauth_configured = True
    return True


def setup_oauth_runtime(app, client_id, client_secret, auth_server):
    """Set up OAuth with runtime configuration stored in session."""
    from flask import session

    session["oauth_config"] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "auth_server": auth_server,
    }

    return setup_oauth(app)


def create_app():
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
    babel.init_app(app)

    app.register_blueprint(bp)
    setup_oauth(app)
    return app


def main():
    """Run the Auth Playground application."""
    load_dotenv()
    app = create_app()
    host = os.environ.get("FLASK_RUN_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_RUN_PORT", "4000"))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() == "true"
    app.run(host=host, port=port, debug=debug)

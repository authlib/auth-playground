import os

from authlib.integrations.flask_client import OAuth
from authlib.oidc.discovery import get_well_known_url
from dotenv import load_dotenv
from flask import Flask

from auth_playground.endpoints import bp

oauth = OAuth()
oauth_configured = False


def setup_oauth(app):
    global oauth_configured

    required_config = ["OAUTH_CLIENT_ID", "OAUTH_CLIENT_SECRET", "OAUTH_AUTH_SERVER"]
    missing_config = [key for key in required_config if not app.config.get(key)]

    if missing_config:
        app.logger.warning(
            f"OAuth not configured. Missing: {', '.join(missing_config)}"
        )
        oauth_configured = False
        return

    oauth.init_app(app)
    oauth.register(
        name="canaille",
        client_id=app.config["OAUTH_CLIENT_ID"],
        client_secret=app.config["OAUTH_CLIENT_SECRET"],
        server_metadata_url=get_well_known_url(
            app.config["OAUTH_AUTH_SERVER"], external=True
        ),
        client_kwargs={"scope": "openid profile email phone address groups"},
    )
    oauth_configured = True


def create_app():
    app = Flask(__name__)

    app.config["SECRET_KEY"] = os.environ.get(
        "SECRET_KEY", "dev-secret-key-change-in-production"
    )
    app.config["NAME"] = os.environ.get("APP_NAME", "Auth Playground")

    app.config["OAUTH_CLIENT_ID"] = os.environ.get("OAUTH_CLIENT_ID")
    app.config["OAUTH_CLIENT_SECRET"] = os.environ.get("OAUTH_CLIENT_SECRET")
    app.config["OAUTH_AUTH_SERVER"] = os.environ.get("OAUTH_AUTH_SERVER")

    app.jinja_env.add_extension("jinja2_highlight.HighlightExtension")

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

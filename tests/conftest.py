import os
from unittest.mock import patch

import pytest
from babel.messages.frontend import CompileCatalog
from flask import session
from flask_webtest import TestApp
from flask_wtf.csrf import generate_csrf

from auth_playground import create_app
from tests.fake_provider import METADATA


@pytest.fixture(autouse=True, scope="session")
def babel_catalogs():
    cmd = CompileCatalog()
    cmd.directory = os.path.dirname(__file__) + "/../src/auth_playground/translations"
    cmd.statistics = True
    cmd.finalize_options()
    cmd.run()


@pytest.fixture
def iam_client(iam_server):
    """Create an OAuth client for testing."""
    client = iam_server.models.Client(
        client_id="auth-playground-test",
        client_secret="test-secret",
        client_name="Auth Playground Test",
        client_uri="http://client.test",
        redirect_uris=[
            "http://client.test/authorize_callback",
            "http://client.test/logout_callback",
        ],
        grant_types=["authorization_code", "refresh_token", "client_credentials"],
        response_types=["code"],
        token_endpoint_auth_method="client_secret_basic",
        scope=["openid", "profile", "email", "groups"],
    )
    iam_server.backend.save(client)
    yield client
    iam_server.backend.delete(client)


@pytest.fixture
def user(iam_server):
    """Create a test user."""
    user = iam_server.random_user()
    yield user


@pytest.fixture
def proxy_fix():
    """Return whether the application runs behind a reverse proxy."""
    return False


@pytest.fixture
def unconfigured_app(monkeypatch, proxy_fix):
    """Create an unconfigured Flask application for testing config errors."""
    monkeypatch.setenv("PROXY_FIX", str(proxy_fix).lower())
    app = create_app()
    app.config["TESTING"] = True
    app.config["SERVER_NAME"] = "client.test"
    app.config["SECRET_KEY"] = "test-secret-key"
    app.config["OAUTH_CLIENT_ID"] = None
    app.config["OAUTH_CLIENT_SECRET"] = None
    app.config["OAUTH_AUTH_SERVER"] = None

    return app


@pytest.fixture
def app(iam_server, iam_client, unconfigured_app):
    """Create a configured Flask application for testing."""
    unconfigured_app.config["OAUTH_CLIENT_ID"] = iam_client.client_id
    unconfigured_app.config["OAUTH_CLIENT_SECRET"] = iam_client.client_secret
    unconfigured_app.config["OAUTH_AUTH_SERVER"] = iam_server.url
    return unconfigured_app


@pytest.fixture
def test_client(app):
    """Create a test client for the Flask application."""
    return app.test_client()


@pytest.fixture
def unconfigured_test_client(unconfigured_app):
    """Create a test client for the unconfigured Flask application."""
    return unconfigured_app.test_client()


@pytest.fixture
def testapp(app):
    """Create a WebTest client for the configured Flask application."""
    return TestApp(app)


@pytest.fixture
def unconfigured_testapp(unconfigured_app):
    """Create a WebTest client for the unconfigured Flask application."""
    return TestApp(unconfigured_app)


@pytest.fixture
def csrf_token():
    """Return a function that gives a valid CSRF token for a test client."""

    def get_token(client):
        app = client.application
        with app.app_context(), app.test_request_context():
            token = generate_csrf()
            raw_token = session["csrf_token"]
        with client.session_transaction() as sess:
            sess["csrf_token"] = raw_token
        return token

    return get_token


@pytest.fixture
def provider_metadata():
    """Serve the metadata of the fake provider without network."""
    with patch(
        "authlib.integrations.base_client.sync_app.OAuth2Mixin.load_server_metadata",
        return_value=METADATA,
    ):
        yield

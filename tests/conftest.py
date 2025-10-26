import pytest

from auth_playground import create_app
from auth_playground import setup_oauth


@pytest.fixture
def iam_client(iam_server):
    """Create an OAuth client for testing."""
    client = iam_server.models.Client(
        client_id="auth-playground-test",
        client_secret="test-secret",
        client_name="Auth Playground Test",
        client_uri="http://client.test",
        redirect_uris=[
            "http://client.test/login_callback",
            "http://client.test/logout_callback",
        ],
        grant_types=["authorization_code"],
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
def unconfigured_app():
    """Create an unconfigured Flask application for testing config errors."""
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

    setup_oauth(unconfigured_app)

    return unconfigured_app


@pytest.fixture
def test_client(app):
    """Create a test client for the Flask application."""
    return app.test_client()


@pytest.fixture
def unconfigured_test_client(unconfigured_app):
    """Create a test client for the unconfigured Flask application."""
    return unconfigured_app.test_client()

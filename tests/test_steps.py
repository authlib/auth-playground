import pytest

METADATA = {
    "issuer": "https://idp.example.com",
    "authorization_endpoint": "https://idp.example.com/oauth/authorize",
    "token_endpoint": "https://idp.example.com/oauth/token",
}


def configure(client, oauth_config=None, token=None, user=None):
    """Store a server, and optionally a client, tokens and a user."""
    with client.session_transaction() as sess:
        sess["issuer_url"] = "https://idp.example.com"
        sess["server_metadata"] = METADATA
        sess["server_type"] = "oidc"
        if oauth_config:
            sess["oauth_config"] = {
                "auth_server": "https://idp.example.com",
                **oauth_config,
            }
        if token:
            sess["token"] = token
        if user:
            sess["user"] = user


def test_steps_without_server(unconfigured_test_client):
    """Test only the provider step is reachable without a server."""
    res = unconfigured_test_client.get("/en/server")

    assert "Choose a provider" in res.text
    assert '<a href="/en/server" aria-current="step">' in res.text
    assert "Step 1:" in res.text
    assert "Available once the provider is set" in res.text
    assert "Available once the client is set" in res.text


def test_steps_without_client(unconfigured_test_client):
    """Test the client step is current once the provider is set."""
    configure(unconfigured_test_client)
    res = unconfigured_test_client.get("/en/client")

    assert "<small>idp.example.com</small>" in res.text
    assert "Register or enter a client" in res.text
    assert '<a href="/en/client" aria-current="step">' in res.text
    assert "Step 1, done:" in res.text


@pytest.mark.parametrize(
    "oauth_config,summary",
    [
        (
            {"client_id": "c", "token_endpoint_auth_method": "none"},
            "Public · none",
        ),
        (
            {"client_id": "c", "client_secret": "s"},
            "Confidential · client_secret_basic",
        ),
    ],
)
def test_steps_show_the_client(unconfigured_test_client, oauth_config, summary):
    """Test the client step shows the client type and authentication."""
    configure(unconfigured_test_client, oauth_config)
    res = unconfigured_test_client.get("/en/tokens/request")

    assert summary in res.text
    assert "No tokens yet" in res.text
    assert '<a href="/en/tokens" aria-current="step">' in res.text


@pytest.mark.parametrize(
    "user,summary",
    [
        ({"sub": "jdoe", "preferred_username": "jane"}, "Signed in as jane"),
        ({"sub": "jdoe"}, "Signed in as jdoe"),
        (None, "Tokens obtained"),
    ],
)
def test_steps_show_the_session(unconfigured_test_client, user, summary):
    """Test the session step shows who is signed in."""
    configure(
        unconfigured_test_client,
        {"client_id": "c", "client_secret": "s"},
        token={"access_token": "a", "token_type": "Bearer"},
        user=user,
    )
    res = unconfigured_test_client.get("/en/tokens/current")

    assert summary in res.text


def test_steps_mark_what_the_environment_sets(app, test_client):
    """Test the steps set by the environment are marked as such."""
    res = test_client.get("/en/tos")

    assert res.text.count('class="done locked"') == 2
    assert "Step 1, done:" in res.text
    assert res.text.count("set by the environment") == 2
    assert 'aria-current="step"' not in res.text


def test_provider_step_shows_the_issuer_path(unconfigured_test_client):
    """Test the provider step keeps the issuer path, as realms need it."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://kc.example.com/realms/demo"
        sess["server_metadata"] = METADATA
        sess["server_type"] = "oauth2"
    res = unconfigured_test_client.get("/en/specs")

    assert "<small>kc.example.com/realms/demo</small>" in res.text

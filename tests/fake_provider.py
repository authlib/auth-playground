"""A provider served without network, configured through the session."""

METADATA = {
    "issuer": "https://test.example.com",
    "authorization_endpoint": "https://test.example.com/oauth/authorize",
    "token_endpoint": "https://test.example.com/oauth/token",
    "registration_endpoint": "https://test.example.com/oauth/register",
    "scopes_supported": ["openid", "profile"],
    "code_challenge_methods_supported": ["S256", "plain"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic", "none"],
}


def server_session(client, oauth_config=None):
    """Store a configured server, and optionally a client, in the session."""
    with client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = METADATA
        if oauth_config:
            sess["oauth_config"] = {
                "auth_server": "https://test.example.com",
                **oauth_config,
            }

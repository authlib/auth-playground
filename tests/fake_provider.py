"""A provider served without network, configured through the session."""

import json as jsonlib
from http import HTTPStatus

import requests

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


def http_response(
    status=200,
    json=None,
    text="",
    headers=None,
    method="POST",
    url="https://test.example.com/oauth/token",
    data=None,
):
    """Return a response of the provider, with the request the playground sent."""
    response = requests.Response()
    response.status_code = status
    response.reason = HTTPStatus(status).phrase
    response.headers.update(headers or {})
    if json is not None:
        text = jsonlib.dumps(json)
        response.headers.setdefault("Content-Type", "application/json")
    response._content = text.encode()
    response.encoding = "utf-8"
    response.url = url
    response.request = requests.Request(method, url, data=data).prepare()
    return response

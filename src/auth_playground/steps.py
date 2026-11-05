"""The setup steps shown at the top of every page."""

from dataclasses import dataclass

from flask import current_app
from flask import g
from flask import session
from flask import url_for
from flask_babel import gettext as _

import auth_playground
from auth_playground.client_auth import PUBLIC_METHOD
from auth_playground.grants import client_tokens


@dataclass
class Step:
    """A step of the setup, and what it holds."""

    number: int
    label: str
    summary: str
    url: str | None
    done: bool = False
    locked: bool = False

    @property
    def status(self):
        """Describe the step for screen readers, before its label."""
        if self.done:
            return _("Step {number}, done:").format(number=self.number)
        return _("Step {number}:").format(number=self.number)


def provider_step():
    """Return the provider step."""
    server_config = g.get("server_config")
    issuer_url = server_config.issuer_url if server_config else None
    locked = auth_playground.is_oauth_server_from_env(current_app)
    if not issuer_url:
        return Step(
            1, _("Provider"), _("Choose a provider"), url_for("routes.configure_server")
        )

    summary = issuer_url.split("://", 1)[-1]
    if locked:
        summary = _("{provider}, set by the environment").format(provider=summary)

    return Step(
        1,
        _("Provider"),
        summary,
        url_for("routes.configure_server"),
        done=True,
        locked=locked,
    )


def client_step(provider):
    """Return the client step."""
    if not provider.done:
        return Step(2, _("Client"), _("Available once the provider is set"), None)

    url = url_for("routes.configure_client")
    if not auth_playground.is_client_configured():
        return Step(2, _("Client"), _("Register or enter a client"), url)

    oauth_config = auth_playground.get_oauth_config(current_app)
    method = oauth_config.get("token_endpoint_auth_method")
    client_type = _("Public") if method == PUBLIC_METHOD else _("Confidential")
    locked = auth_playground.is_oauth_client_from_env(current_app)
    summary = f"{client_type} · {method}"
    if locked:
        summary = _("{client}, set by the environment").format(client=summary)

    return Step(2, _("Client"), summary, url, done=True, locked=locked)


def tokens_step(client):
    """Return the tokens step."""
    if not client.done:
        return Step(3, _("Tokens"), _("Available once the client is set"), None)

    url = url_for("routes.tokens")
    if not session.get("token"):
        return Step(3, _("Tokens"), _("No tokens yet"), url)

    if client_tokens():
        return Step(3, _("Tokens"), _("Client tokens"), url, done=True)

    user = session.get("user") or {}
    if name := user.get("preferred_username") or user.get("sub"):
        return Step(
            3, _("Tokens"), _("Signed in as {name}").format(name=name), url, done=True
        )

    return Step(3, _("Tokens"), _("Tokens obtained"), url, done=True)


def setup_steps():
    """Return the provider, client and tokens steps."""
    provider = provider_step()
    client = client_step(provider)
    return [provider, client, tokens_step(client)]

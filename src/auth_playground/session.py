from __future__ import annotations

from dataclasses import dataclass

from flask import g

from auth_playground.specs import ServerSpecs


def server_metadata() -> dict:
    """Return the metadata of the configured server, or an empty dict."""
    server_config = g.get("server_config")
    return (server_config.metadata if server_config else None) or {}


@dataclass
class ServerConfig:
    """Encapsulates server configuration data from session."""

    metadata: dict | None = None
    issuer_url: str | None = None
    server_type: str | None = None
    registration_access_token: str | None = None
    registration_client_uri: str | None = None

    @property
    def specs(self) -> ServerSpecs | None:
        """Get ServerSpecs for the configured server."""
        if not self.metadata:
            return None
        return ServerSpecs(self.metadata)

    @property
    def display_name(self) -> str:
        """Get display name for the server type."""
        if self.server_type == "oidc":
            return "OpenID Provider"
        else:
            return "OAuth 2.0 Authorization Server"

    def serialize(self) -> dict:
        """Serialize to dict for session storage."""
        return {
            "server_metadata": self.metadata,
            "issuer_url": self.issuer_url,
            "server_type": self.server_type,
            "registration_access_token": self.registration_access_token,
            "registration_client_uri": self.registration_client_uri,
        }

    @classmethod
    def deserialize(cls, session_data: dict) -> ServerConfig | None:
        """Deserialize from session storage."""
        metadata = session_data.get("server_metadata")
        issuer_url = session_data.get("issuer_url")
        server_type = session_data.get("server_type")
        registration_access_token = session_data.get("registration_access_token")
        registration_client_uri = session_data.get("registration_client_uri")

        if not metadata and not issuer_url:
            return None

        return cls(
            metadata=metadata,
            issuer_url=issuer_url,
            server_type=server_type,
            registration_access_token=registration_access_token,
            registration_client_uri=registration_client_uri,
        )

    def save(self, session_data: dict):
        """Save to session storage, without touching the values that did not change."""
        for key, value in self.serialize().items():
            if value is None and key in session_data:
                del session_data[key]
            elif value is not None and session_data.get(key) != value:
                session_data[key] = value

    @classmethod
    def clear(cls, session_data: dict):
        """Clear from session storage."""
        session_data.pop("server_metadata", None)
        session_data.pop("issuer_url", None)
        session_data.pop("server_type", None)
        session_data.pop("registration_access_token", None)
        session_data.pop("registration_client_uri", None)

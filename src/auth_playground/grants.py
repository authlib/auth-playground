"""The grant types the playground can use to obtain tokens."""

from dataclasses import dataclass

from flask import session
from flask_babel import lazy_gettext as _

from auth_playground.session import server_metadata

# Per RFC 8414 §2, when the server does not publish grant_types_supported.
DEFAULT_GRANT_TYPES = ["authorization_code", "implicit"]


def advertised_grant_types():
    """Return the grant types the server advertises."""
    return server_metadata().get("grant_types_supported", DEFAULT_GRANT_TYPES)


@dataclass(frozen=True)
class Grant:
    """A grant type, and how it is presented."""

    value: str
    label: str
    group: str
    description: str
    references: tuple[tuple[str, str], ...]
    confidential_client: bool = False

    @property
    def advertised(self):
        """Tell whether the server advertises this grant type."""
        return self.value in advertised_grant_types()


GRANTS = (
    Grant(
        "authorization_code",
        _("Authorization code"),
        _("Redirect"),
        _(
            "The user signs in at the provider, which redirects back with a code. "
            "The playground then exchanges the code for tokens at the token "
            "endpoint. Signing in again updates auth_time, acr and amr."
        ),
        (
            ("RFC 6749 §4.1", "https://www.rfc-editor.org/rfc/rfc6749#section-4.1"),
            (
                "OpenID Connect Core §3.1",
                "https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth",
            ),
        ),
    ),
    Grant(
        "client_credentials",
        _("Client credentials"),
        _("Direct"),
        _(
            "The client gets tokens for itself, without any user. The playground "
            "sends its credentials to the token endpoint."
        ),
        (("RFC 6749 §4.4", "https://www.rfc-editor.org/rfc/rfc6749#section-4.4"),),
        confidential_client=True,
    ),
)

GRANTS_BY_VALUE = {grant.value: grant for grant in GRANTS}


def client_tokens():
    """Tell whether the client obtained the tokens for itself."""
    return session.get("token_info", {}).get("grant") == "client_credentials"


def get_grant(value):
    """Return the grant type ``value``, or else the one that obtained the tokens."""
    if value in GRANTS_BY_VALUE:
        return GRANTS_BY_VALUE[value]

    last = session.get("token_info", {}).get("grant")
    return GRANTS_BY_VALUE.get(last, GRANTS[0])

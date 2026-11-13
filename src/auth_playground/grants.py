"""The grant types the playground can use to obtain tokens."""

from dataclasses import dataclass

from authlib.oauth2.rfc7523 import JWTBearerGrant
from flask import current_app
from flask import session
from flask_babel import lazy_gettext as _

import auth_playground
from auth_playground.session import server_metadata

# Per RFC 8414 §2, when the server does not publish grant_types_supported.
DEFAULT_GRANT_TYPES = ["authorization_code", "implicit"]

JWT_BEARER = JWTBearerGrant.GRANT_TYPE


def advertised_grant_types():
    """Return the grant types the server advertises."""
    return server_metadata().get("grant_types_supported", DEFAULT_GRANT_TYPES)


def registered_grant_types():
    """Return the grant types the provider registered for the client.

    They are only known for a client of the dynamic registration, and are
    ``None`` otherwise.
    """
    return auth_playground.get_oauth_config(current_app).get("grant_types")


@dataclass(frozen=True)
class Grant:
    """A grant type, and how it is presented."""

    value: str
    label: str
    group: str
    description: str
    references: tuple[tuple[str, str], ...]
    confidential_client: bool = False
    deprecated: bool = False
    # The tokens are for a user, and not for the client itself.
    user: bool = True
    # The user signs in at the provider, which keeps a session for them.
    provider_session: bool = False
    # The name in the playground URLs, for a grant type that is a URN.
    short_name: str | None = None

    @property
    def name(self):
        """Return the name of the grant type in the playground URLs."""
        return self.short_name or self.value

    @property
    def advertised(self):
        """Tell whether the server advertises this grant type."""
        return self.value in advertised_grant_types()

    @property
    def registered(self):
        """Tell whether the client may use this grant type, as far as the playground knows."""
        grant_types = registered_grant_types()
        return grant_types is None or self.value in grant_types


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
        provider_session=True,
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
        user=False,
    ),
    Grant(
        "password",
        _("Password (ROPC)"),
        _("Direct"),
        _(
            "The client asks the user for their username and password, and sends "
            "them to the token endpoint. The provider never sees the user sign in."
        ),
        (
            ("RFC 6749 §4.3", "https://www.rfc-editor.org/rfc/rfc6749#section-4.3"),
            ("RFC 9700 §2.4", "https://www.rfc-editor.org/rfc/rfc9700#section-2.4"),
        ),
        deprecated=True,
    ),
    Grant(
        JWT_BEARER,
        _("JWT bearer"),
        _("Direct"),
        _(
            "The client sends a signed JWT that says who the tokens are for. "
            "The provider checks the signature and the claims, then issues tokens "
            "for the subject."
        ),
        (("RFC 7523 §2.1", "https://www.rfc-editor.org/rfc/rfc7523#section-2.1"),),
        short_name="jwt_bearer",
    ),
)

GRANTS_BY_VALUE = {grant.value: grant for grant in GRANTS}
GRANTS_BY_NAME = {grant.name: grant for grant in GRANTS}


def tokens_grant():
    """Return the grant type that obtained the tokens, or else the default one."""
    grant = session.get("token_info", {}).get("grant")
    return GRANTS_BY_VALUE.get(grant, GRANTS[0])


def get_grant(name):
    """Return the grant type called ``name``, or else the one that obtained the tokens."""
    return GRANTS_BY_NAME.get(name) or tokens_grant()

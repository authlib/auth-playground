"""Assertions of the JWT bearer grant (RFC 7523 §2.1)."""

import json
import math
import time
from dataclasses import dataclass
from dataclasses import field

from authlib.oauth2.rfc7523 import JWTBearerGrant
from flask import current_app
from flask_babel import format_datetime
from flask_babel import gettext as _
from joserfc import jws
from joserfc.errors import JoseError
from joserfc.jwk import OctKey

import auth_playground
from auth_playground.client_key import load_key
from auth_playground.grants import JWT_BEARER
from auth_playground.preview import GENERATED
from auth_playground.preview import NOW
from auth_playground.session import server_metadata
from auth_playground.token_request import signed_header
from auth_playground.token_request import token_preview

KEY_SOURCE = "key"
SECRET_SOURCE = "secret"
PASTED_SOURCE = "paste"

# A MAC with the client secret, like client_secret_jwt.
SECRET_ALG = "HS256"

DEFAULT_LIFETIME = 300

# The server metadata the audience can be.
AUDIENCES = ("issuer", "token_endpoint")

# The claims shown as dates under a decoded assertion.
TIME_CLAIMS = ("iat", "nbf", "exp")

# The claims the form sets. The extra claims cannot replace them.
FORM_CLAIMS = ("iss", "sub", "aud", "iat", "exp")


@dataclass
class AssertionPreview:
    """The assertion of the grant, as shown to the user."""

    note: str
    header: str | None = None
    claims: str | None = None
    dates: list[tuple[str, str]] = field(default_factory=list)
    notices: list[tuple[str, str]] = field(default_factory=list)


def json_object(text, **kwargs):
    """Return the JSON object in ``text``, or ``None`` when it is not one."""
    try:
        data = json.loads(text, **kwargs)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def reject_constant(name):
    """Refuse NaN and Infinity, which are not JSON (RFC 8259 §6)."""
    raise ValueError(name)


def claims_object(text):
    """Return the JSON object of claims to sign, or ``None`` when it is not one."""
    return json_object(text, parse_constant=reject_constant)


def extra_claims(form):
    """Return the extra claims of the form, or an empty dict."""
    return claims_object(form.extra_claims.data or "{}") or {}


def audience(form):
    """Return the audience the form chose: the issuer or the token endpoint."""
    if form.audience.data not in AUDIENCES:
        return ""
    return server_metadata().get(form.audience.data, "")


def assertion_alg(source, oauth_config):
    """Return the algorithm that signs the assertion."""
    if source == SECRET_SOURCE:
        return SECRET_ALG
    return oauth_config["token_endpoint_auth_signing_alg"]


def assertion_header(source, oauth_config):
    """Return the header of the assertion the playground signs.

    Like Authlib, it takes the kid of the signing key.
    """
    kid = signing_key(source, oauth_config).kid
    return signed_header(assertion_alg(source, oauth_config), kid)


def signing_key(source, oauth_config):
    """Return the key that signs the assertion."""
    if source == SECRET_SOURCE:
        return OctKey.import_key(oauth_config["client_secret"])
    return load_key(oauth_config["client_key"])


def sign_assertion(form):
    """Sign the assertion the form describes."""
    oauth_config = auth_playground.get_oauth_config(current_app)
    source = form.source.data
    # Authlib adds the kid of the key.
    header = signed_header(assertion_alg(source, oauth_config))
    issued_at = int(time.time())
    return JWTBearerGrant.sign(
        signing_key(source, oauth_config),
        issuer=form.issuer.data,
        audience=audience(form),
        subject=form.subject.data,
        issued_at=issued_at,
        expires_at=issued_at + form.lifetime.data,
        claims=extra_claims(form),
        header=header,
    )


def pasted_assertion(form):
    """Return the pasted assertion, without the spaces a copy may add."""
    return "".join((form.assertion.data or "").split())


def decode_assertion(text):
    """Return the header and the claims of a JWT, or ``None``.

    The signature is not checked.
    """
    try:
        token = jws.extract_compact(text.encode())
    except JoseError:
        return None

    claims = json_object(token.payload)
    if claims is None:
        return None
    return token.protected, claims


def assertion_subject(form):
    """Return who the assertion is for, or ``None`` when it does not say."""
    if form.signing():
        return form.subject.data
    decoded = decode_assertion(pasted_assertion(form))
    return decoded[1].get("sub") if decoded else None


def jwt_bearer_preview(form):
    """Return the JWT bearer token request built from the form.

    Like Authlib, it leaves out an empty assertion.
    """
    assertion = GENERATED if form.signing() else pasted_assertion(form)
    params = [("assertion", assertion)] if assertion else []
    return token_preview(form, JWT_BEARER, params)


def build_assertion_preview(form):
    """Return the assertion built from the form, or the pasted one, decoded."""
    if not form.signing():
        return pasted_assertion_preview(pasted_assertion(form))

    oauth_config = auth_playground.get_oauth_config(current_app)
    if form.source.data not in available_sources(oauth_config):
        return AssertionPreview(_("This client cannot sign the assertion."))

    header = assertion_header(form.source.data, oauth_config)
    claims = {"iss": form.issuer.data or "", "aud": audience(form)}
    if form.subject.data:
        claims["sub"] = form.subject.data
    claims["iat"] = NOW
    claims["exp"] = f"[now + {form.lifetime.data or 0} s]"
    # In the order Authlib writes them: the extra claims come last.
    claims["jti"] = GENERATED
    claims.update(extra_claims(form))
    return AssertionPreview(
        _("Signed with {alg} when the request is sent").format(alg=header["alg"]),
        header=json.dumps(header),
        claims=json.dumps(claims, indent=2),
    )


def pasted_assertion_preview(text):
    """Return the pasted assertion decoded, with what the provider may refuse."""
    note = _("Decoded, the signature is not checked")
    if not text:
        return AssertionPreview(note)

    decoded = decode_assertion(text)
    if decoded is None:
        return AssertionPreview(
            note,
            notices=[
                (
                    "warning",
                    _("This is not a JWT the playground can decode. It is sent as is."),
                )
            ],
        )

    header, claims = decoded
    dates = {name: format_date(claims.get(name)) for name in TIME_CLAIMS}
    return AssertionPreview(
        note,
        header=json.dumps(header),
        claims=json.dumps(claims, indent=2),
        dates=[(name, date) for name, date in dates.items() if date],
        notices=assertion_notices(claims, dates["exp"]),
    )


def format_date(value):
    """Return a NumericDate claim as a date, or ``None`` when it is not one."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if not math.isfinite(value):
        return None
    try:
        return format_datetime(value)
    except (ValueError, OverflowError, OSError):
        return None


def assertion_notices(claims, exp_date):
    """Return why the provider may refuse the claims of a pasted assertion."""
    notices = []
    if exp_date and claims["exp"] < time.time():
        notices.append(
            (
                "warning",
                _(
                    "The assertion expired on {date}. The provider will refuse it."
                ).format(date=exp_date),
            )
        )

    metadata = server_metadata()
    aud = claims.get("aud")
    audiences = {
        value
        for value in (aud if isinstance(aud, list) else [aud])
        if isinstance(value, str)
    }
    if audiences & {metadata.get("issuer"), metadata.get("token_endpoint")}:
        return notices

    notices.append(
        (
            "warning",
            _(
                "The audience is neither the issuer nor the token endpoint. "
                "The provider will likely refuse the assertion."
            ),
        )
    )
    return notices


def available_sources(oauth_config):
    """Return the sources of the assertion the client can use."""
    sources = []
    if oauth_config.get("client_key"):
        sources.append(KEY_SOURCE)
    if oauth_config.get("client_secret"):
        sources.append(SECRET_SOURCE)
    return [*sources, PASTED_SOURCE]

"""Keys that sign the client assertions of private_key_jwt (RFC 7523 §2.2)."""

import json
from functools import lru_cache

from flask import current_app
from flask import session
from flask import url_for
from flask_babel import gettext as _
from joserfc import jwk
from joserfc.errors import JoseError

KEY_TYPES = ("RSA", "EC", "OKP")

# The key generated for the client being configured, before it is saved.
PENDING_KEY = "pending_client_key"

# The key each algorithm needs, as the arguments of joserfc's generate_key.
ALGORITHMS = {
    "RS256": ("RSA", 2048),
    "RS384": ("RSA", 2048),
    "RS512": ("RSA", 2048),
    "PS256": ("RSA", 2048),
    "PS384": ("RSA", 2048),
    "PS512": ("RSA", 2048),
    "ES256": ("EC", "P-256"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
    "EdDSA": ("OKP", "Ed25519"),
}

# Offered when the server does not advertise its algorithms.
DEFAULT_ALGORITHMS = ("RS256", "ES256", "EdDSA")


class InvalidKeyError(ValueError):
    """The text is not a private key the playground can use."""


def key_algorithms(data):
    """Return the algorithms that can sign with the key.

    A JWK with an ``alg`` (RFC 7517 §4.4) only signs with that algorithm.
    """
    if data["kty"] == "RSA":
        algs = [alg for alg, (kty, _size) in ALGORITHMS.items() if kty == "RSA"]
    else:
        algs = [
            alg
            for alg, needed in ALGORITHMS.items()
            if needed == (data["kty"], data["crv"])
        ]
    if "alg" not in data:
        return algs
    return [data["alg"]] if data["alg"] in algs else []


def generate_key(alg):
    """Generate a private key for ``alg``, as a JWK dict whose kid is its thumbprint."""
    key_type, size = ALGORITHMS[alg]
    key = jwk.generate_key(key_type, size, private=True, auto_kid=True)
    return key.as_dict(private=True)


def import_private_key(text, kid=None):
    """Import a private key, PEM or JWK, as a JWK dict.

    The kid is ``kid``, else the one of the JWK, else the key thumbprint
    (RFC 7638).
    """
    key = parse_key(text.strip())
    if not key.is_private:
        raise InvalidKeyError(_("This is a public key. Paste the private key."))

    data = key.as_dict(private=True)
    data["kid"] = kid or key.kid or key.thumbprint()
    return data


def check_private_key(text, kid=None):
    """Import a private key the playground can sign with, as a JWK dict."""
    data = import_private_key(text, kid)
    if data.get("use", "sig") != "sig" or "sign" not in data.get("key_ops", ["sign"]):
        raise InvalidKeyError(_("This key is not meant for signing."))
    if key_algorithms(data):
        return data
    if "alg" in data:
        raise InvalidKeyError(
            _("The playground cannot sign with this key for {alg}.").format(
                alg=data["alg"]
            )
        )
    raise InvalidKeyError(_("The playground cannot sign with this key."))


def parse_key(text):
    """Read a PEM or JWK key, trying each key type the playground supports."""
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise InvalidKeyError(_("This JWK is not valid JSON.")) from exc

        if not isinstance(data, dict) or data.get("kty") not in KEY_TYPES:
            raise InvalidKeyError(_("The JWK must be an RSA, EC or OKP key."))

        try:
            return jwk.import_key(data, data["kty"])
        except (JoseError, ValueError, TypeError) as exc:
            raise InvalidKeyError(
                _("This JWK is not valid: {error}").format(error=exc)
            ) from exc

    for key_type in KEY_TYPES:
        try:
            return jwk.import_key(text, key_type)
        except (JoseError, ValueError, TypeError):
            continue

    raise InvalidKeyError(_("This is not an RSA, EC or Ed25519 key in PEM format."))


def load_key(data):
    """Return the joserfc key of a JWK dict."""
    return load_jwk(json.dumps(data, sort_keys=True))


# Importing a private RSA key takes tens of milliseconds, and the client key
# is needed at each request.
@lru_cache(maxsize=64)
def load_jwk(text):
    """Return the joserfc key of a JWK in JSON."""
    data = json.loads(text)
    return jwk.import_key(data, data["kty"])


def public_jwks(data):
    """Return the JWK set that publishes the public part of the key.

    It has an ``alg`` only when the private key has one: the provider may
    choose another algorithm at registration (RFC 7591 §3.2.1).
    """
    key = load_key(data)
    public = key.as_dict(private=False)
    # The key_ops of a private key, like "sign", do not fit its public key.
    public.pop("key_ops", None)
    public.update(kid=data["kid"], use="sig")
    return {"keys": [public]}


def key_id(data):
    """Return the identifier of the key in the jwks_uri: its thumbprint."""
    return load_key(data).thumbprint()


def private_pem(data):
    """Return the private key in PEM format."""
    return load_key(data).as_pem(private=True)


def pending_key(form_name, alg, regenerate=False):
    """Return the key generated for the client that ``form_name`` configures.

    It stays in the session, so that the public key the user copies does
    not change. Each form has its own. A new key replaces it when it cannot
    sign with ``alg``. It is published at once, so that its jwks_uri works
    before the client is saved.
    """
    keys = dict(session.get(PENDING_KEY) or {})
    data = keys.get(form_name)
    if not regenerate and data and alg in key_algorithms(data):
        return data

    if data:
        unpublish_key(data)
    data = keys[form_name] = generate_key(alg)
    session[PENDING_KEY] = keys
    publish_key(data)
    return data


def preferred_algorithm(algs, advertised):
    """Return the first of ``algs`` the server advertises, or else the first one.

    The order is the one of ``algs``: the metadata does not tell which
    algorithm the server prefers.
    """
    return next((alg for alg in algs if alg in (advertised or ())), algs[0])


def jwks_uri(data):
    """Return the address where the provider can download the public key."""
    return url_for("oauth.client_jwks", key_id=key_id(data), _external=True)


def jwks_cache():
    """Return the cache shared by the requests, where the public keys are published."""
    return current_app.config["SESSION_CACHELIB"]


def publish_key(data):
    """Serve the public key at its jwks_uri, as long as the session lasts.

    The session is saved again each time it changes: so is the key.
    """
    lifetime = current_app.permanent_session_lifetime.total_seconds()
    jwks_cache().set(f"jwks:{key_id(data)}", public_jwks(data), timeout=int(lifetime))


def unpublish_key(data):
    """Stop serving the public key at its jwks_uri."""
    jwks_cache().delete(f"jwks:{key_id(data)}")


def published_jwks(key_id):
    """Return the public keys served at the jwks_uri of ``key_id``, or ``None``."""
    return jwks_cache().get(f"jwks:{key_id}")


def key_summary(data, alg):
    """Return what the provider needs to know about the key."""
    return {
        "description": describe_key(data),
        "kid": data["kid"],
        "alg": alg,
        "jwks": json.dumps(public_jwks(data), indent=2),
        "jwks_uri": jwks_uri(data),
    }


def describe_key(data):
    """Return a short description of the key, like "RSA 2048" or "EC P-256"."""
    key = load_key(data)
    if key.key_type == "RSA":
        return f"RSA {key.raw_value.key_size}"
    return f"{key.key_type} {data['crv']}"

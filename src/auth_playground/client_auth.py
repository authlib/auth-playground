"""Client authentication methods at the token endpoint (RFC 7591 §2)."""

SECRET_METHODS = ("client_secret_basic", "client_secret_post", "client_secret_jwt")
KEY_METHOD = "private_key_jwt"
PUBLIC_METHOD = "none"
CONFIDENTIAL_METHODS = (*SECRET_METHODS, KEY_METHOD)
METHODS = (*CONFIDENTIAL_METHODS, PUBLIC_METHOD)


def default_method(client_secret, client_key=None):
    """Return the method of a client that did not choose one."""
    if client_key:
        return KEY_METHOD
    return SECRET_METHODS[0] if client_secret else PUBLIC_METHOD


def advertised_methods(metadata):
    """Return the methods the server advertises.

    Per RFC 8414 §2, the default is ``client_secret_basic``.
    """
    return (metadata or {}).get(
        "token_endpoint_auth_methods_supported", ["client_secret_basic"]
    )


def advertised_signing_algs(metadata):
    """Return the algorithms the server advertises for the client assertions.

    ``None`` when the server advertises none.
    """
    return (metadata or {}).get("token_endpoint_auth_signing_alg_values_supported")

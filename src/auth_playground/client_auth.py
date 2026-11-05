"""Client authentication methods at the token endpoint (RFC 7591 §2)."""

SECRET_METHODS = ("client_secret_basic", "client_secret_post", "client_secret_jwt")
PUBLIC_METHOD = "none"
METHODS = (*SECRET_METHODS, PUBLIC_METHOD)


def default_method(client_secret):
    """Return the method of a client that did not choose one."""
    return SECRET_METHODS[0] if client_secret else PUBLIC_METHOD


def advertised_methods(metadata):
    """Return the methods the server advertises.

    Per RFC 8414 §2, the default is ``client_secret_basic``.
    """
    return (metadata or {}).get(
        "token_endpoint_auth_methods_supported", ["client_secret_basic"]
    )

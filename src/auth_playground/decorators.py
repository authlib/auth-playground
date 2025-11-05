from functools import wraps

from flask import redirect
from flask import url_for

import auth_playground


def server_config_needed(f=None, *, client_needed=True):
    """Ensure server is configured and metadata is loaded.

    If client_needed is True, also ensures OAuth client is configured.
    """

    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            from auth_playground.endpoints import load_server_metadata

            if not auth_playground.is_server_configured():
                return redirect(url_for("routes.configure_server"))

            load_server_metadata(flash_errors=True)

            if client_needed and not auth_playground.is_client_configured():
                return redirect(url_for("routes.configure_client"))

            return func(*args, **kwargs)

        return decorated_function

    if f is None:
        return decorator
    else:
        return decorator(f)

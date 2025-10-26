from authlib.common.errors import AuthlibBaseError
from authlib.common.urls import add_params_to_uri
from flask import Blueprint
from flask import current_app
from flask import flash
from flask import redirect
from flask import render_template
from flask import session
from flask import url_for
from pygments.formatters import HtmlFormatter

import auth_playground

bp = Blueprint("routes", __name__)


@bp.route("/pygments.css")
def pygments_css():
    """Serve Pygments CSS for syntax highlighting with light/dark mode support."""
    light_formatter = HtmlFormatter(style="default")
    dark_formatter = HtmlFormatter(style="monokai")

    light_css = light_formatter.get_style_defs(".highlight")
    dark_css = dark_formatter.get_style_defs(".highlight")

    return (
        render_template("pygments.css", light_css=light_css, dark_css=dark_css),
        200,
        {"Content-Type": "text/css"},
    )


@bp.route("/config-error")
def config_error():
    """Display configuration error page."""
    return render_template("config_error.html")


@bp.route("/")
def index():
    if not auth_playground.oauth_configured:
        return redirect(url_for("routes.config_error"))
    return render_template(
        "index.html",
        user=session.get("user"),
        token=session.get("token"),
    )


@bp.route("/tos")
def tos():
    return render_template("tos.html")


@bp.route("/policy")
def policy():
    return render_template("policy.html")


@bp.route("/register")
def register():
    """Redirect users to the Identity Provider registration page."""
    return auth_playground.oauth.canaille.authorize_redirect(
        url_for("routes.register_callback", _external=True), prompt="create"
    )


@bp.route("/register_callback")
def register_callback():
    try:
        token = auth_playground.oauth.canaille.authorize_access_token()
        session["user"] = token.get("userinfo")
        session["token"] = {
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "id_token": token.get("id_token"),
            "token_type": token.get("token_type"),
            "expires_in": token.get("expires_in"),
            "expires_at": token.get("expires_at"),
            "scope": token.get("scope"),
        }
        flash("You account has been successfully created.", "success")
    except AuthlibBaseError as exc:
        flash(f"An error happened during registration: {exc.description}", "error")

    return redirect(url_for("routes.index"))


@bp.route("/login")
def login():
    """Redirect users to the Identity Provider login page."""
    if "user" in session:
        return auth_playground.oauth.canaille.authorize_redirect(
            url_for("routes.login_callback", _external=True), prompt="login"
        )
    else:
        return auth_playground.oauth.canaille.authorize_redirect(
            url_for("routes.login_callback", _external=True)
        )


@bp.route("/consent")
def consent():
    """Redirect users to the Identity Provider consent page."""
    return auth_playground.oauth.canaille.authorize_redirect(
        url_for("routes.login_callback", _external=True), prompt="consent"
    )


@bp.route("/login_callback")
def login_callback():
    try:
        token = auth_playground.oauth.canaille.authorize_access_token()
        session["user"] = token.get("userinfo")
        session["token"] = {
            "access_token": token.get("access_token"),
            "refresh_token": token.get("refresh_token"),
            "id_token": token.get("id_token"),
            "token_type": token.get("token_type"),
            "expires_in": token.get("expires_in"),
            "expires_at": token.get("expires_at"),
            "scope": token.get("scope"),
        }
        flash("You have been successfully logged in.", "success")
    except AuthlibBaseError as exc:
        flash(f"An error happened during login: {exc.description}", "error")

    return redirect(url_for("routes.index"))


@bp.route("/logout")
def logout():
    """Redirect users to the Identity Provider logout page."""
    auth_playground.oauth.canaille.load_server_metadata()
    end_session_endpoint = auth_playground.oauth.canaille.server_metadata.get(
        "end_session_endpoint"
    )
    id_token = session.get("token", {}).get("id_token")
    end_session_url = add_params_to_uri(
        end_session_endpoint,
        dict(
            client_id=current_app.config["OAUTH_CLIENT_ID"],
            id_token_hint=id_token,
            post_logout_redirect_uri=url_for("routes.logout_callback", _external=True),
        ),
    )
    return redirect(end_session_url)


@bp.route("/logout_callback")
def logout_callback():
    try:
        del session["user"]
    except KeyError:
        pass

    try:
        del session["token"]
    except KeyError:
        pass

    flash("You have been successfully logged out", "success")
    return redirect(url_for("routes.index"))

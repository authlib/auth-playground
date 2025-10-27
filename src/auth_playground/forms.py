from flask import current_app
from flask_wtf import FlaskForm
from wtforms import PasswordField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import ValidationError
from wtforms.validators import DataRequired
from wtforms.validators import Length


class RefreshTokenForm(FlaskForm):
    """Form to refresh access token using refresh token."""

    submit = SubmitField("Renew tokens")


def validate_issuer_url(form, field):
    """Validate issuer URL with relaxed rules in debug/testing mode."""
    url = field.data

    if not url:
        raise ValidationError("Identity Provider URL is required")

    if not url.startswith(("http://", "https://")):
        raise ValidationError("URL must start with http:// or https://")

    is_debug = current_app.debug
    is_testing = current_app.testing

    if url.startswith("http://") and not (is_debug or is_testing):
        raise ValidationError(
            "HTTP is only allowed in debug or testing mode. Use HTTPS in production."
        )


class ServerConfigForm(FlaskForm):
    """Form to configure the Identity Provider server URL."""

    issuer_url = StringField(
        "Identity Provider URL:",
        validators=[
            DataRequired(message="Identity Provider URL is required"),
            validate_issuer_url,
        ],
        description="Enter the base URL of your OIDC/OAuth2 provider (e.g., https://auth.example.com)",
        render_kw={"placeholder": "https://auth.example.com", "type": "url"},
    )
    submit = SubmitField("Validate server")


class ClientConfigForm(FlaskForm):
    """Form to configure OAuth client credentials manually."""

    client_id = StringField(
        "Client ID:",
        validators=[
            DataRequired(message="Client ID is required"),
            Length(
                min=1,
                max=255,
                message="Client ID must be between 1 and 255 characters",
            ),
        ],
        render_kw={"placeholder": "auth-playground-client"},
    )
    client_secret = PasswordField(
        "Client secret:",
        validators=[
            DataRequired(message="Client Secret is required"),
            Length(min=1, message="Client Secret is required"),
        ],
        render_kw={"placeholder": "******************"},
    )
    submit = SubmitField("Complete Configuration")


class AutoRegisterForm(FlaskForm):
    """Form to trigger automatic client registration with CSRF protection."""

    initial_access_token = StringField(
        "Initial access token:",
        validators=[],
        render_kw={"placeholder": "Leave empty if not required"},
    )
    submit = SubmitField("Register client")

from flask import current_app
from flask_babel import lazy_gettext as _
from flask_wtf import FlaskForm
from wtforms import PasswordField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import ValidationError
from wtforms.validators import DataRequired
from wtforms.validators import Length


class RefreshTokenForm(FlaskForm):
    """Form to refresh access token using refresh token."""

    submit = SubmitField(_("Renew tokens"))


def validate_issuer_url(form, field):
    """Validate issuer URL with relaxed rules in debug/testing mode."""
    url = field.data

    if not url.startswith(("http://", "https://")):
        raise ValidationError(_("URL must start with http:// or https://"))

    is_debug = current_app.debug
    is_testing = current_app.testing

    if url.startswith("http://") and not (is_debug or is_testing):  # pragma: no cover
        raise ValidationError(
            _("HTTP is only allowed in debug or testing mode. Use HTTPS in production.")
        )


class ServerConfigForm(FlaskForm):
    """Form to configure the provider server URL."""

    issuer_url = StringField(
        _("Provider URL:"),
        validators=[
            DataRequired(message=_("Provider URL is required")),
            validate_issuer_url,
        ],
        description=_(
            "Enter the base URL of your OIDC/OAuth2 provider (e.g., https://auth.example.com)"
        ),
        render_kw={"placeholder": "https://auth.example.com", "type": "url"},
    )
    submit = SubmitField(_("Continue"))


class ClientConfigForm(FlaskForm):
    """Form to configure OAuth client credentials manually."""

    client_id = StringField(
        _("Client ID:"),
        validators=[
            DataRequired(message=_("Client ID is required")),
            Length(
                min=1,
                max=255,
                message=_("Client ID must be between 1 and 255 characters"),
            ),
        ],
        render_kw={"placeholder": "auth-playground-client"},
    )
    client_secret = PasswordField(
        _("Client secret:"),
        validators=[
            DataRequired(message=_("Client Secret is required")),
            Length(min=1, message=_("Client Secret is required")),
        ],
        render_kw={"placeholder": "******************"},
    )
    submit = SubmitField(_("Complete configuration"))


class DynamicRegistrationForm(FlaskForm):
    """Form to trigger dynamic client registration with CSRF protection."""

    initial_access_token = StringField(
        _("Initial access token:"),
        validators=[],
        render_kw={"placeholder": _("Leave empty if not required")},
    )
    submit = SubmitField(_("Register client"))


class UnregisterClientForm(FlaskForm):
    """Form to trigger client unregistration with CSRF protection."""

    submit = SubmitField(_("Unregister client"))

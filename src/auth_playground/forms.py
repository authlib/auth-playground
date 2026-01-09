from urllib.parse import urlparse

from babel import Locale
from babel import UnknownLocaleError
from flask import current_app
from flask import g
from flask_babel import lazy_gettext as _
from flask_wtf import FlaskForm
from wtforms import PasswordField
from wtforms import SelectField
from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import ValidationError
from wtforms.validators import DataRequired
from wtforms.validators import Length
from wtforms.widgets import CheckboxInput
from wtforms.widgets import ListWidget


def get_scopes_choices():
    """Get scopes choices from server metadata."""
    if g.server_config and g.server_config.metadata:
        scopes_supported = g.server_config.metadata.get("scopes_supported", [])
        return [(scope, scope) for scope in scopes_supported]
    return []


def get_scopes_default():
    """Get default scopes (all supported scopes)."""
    if g.server_config and g.server_config.metadata:
        return g.server_config.metadata.get("scopes_supported", [])
    return []


def get_prompt_choices():
    """Get prompt choices for OAuth authorization."""
    return [
        ("", _("Default")),
        ("none", _("None - No UI")),
        ("login", _("Login - Authentication page")),
        ("consent", _("Consent - Consent page")),
        ("select_account", _("Select account - Account selection page")),
        ("create", _("Create - Registration page")),
    ]


def get_ui_locales_choices():
    """Get UI locales choices from server metadata."""
    choices = [("", _("Default"))]
    if (
        g.server_config
        and g.server_config.metadata
        and (
            ui_locales_supported := g.server_config.metadata.get(
                "ui_locales_supported", []
            )
        )
    ):
        for locale_code in ui_locales_supported:
            try:
                # Parse the locale and get its display name in its own language
                locale_obj = Locale.parse(locale_code.replace("-", "_"))
                display_name = locale_obj.get_display_name(
                    locale_code.replace("-", "_")
                )
                choices.append((locale_code, display_name))

            except (UnknownLocaleError, ValueError):
                # Fallback to the locale code if parsing fails
                choices.append((locale_code, locale_code))
    return choices


class RefreshTokenForm(FlaskForm):
    """Form to refresh access token using refresh token."""

    submit = SubmitField(_("Renew tokens"))


def validate_issuer_url(form, field):
    """Validate issuer URL with relaxed rules in debug/testing mode or for localhost."""
    url = field.data

    if not url.startswith(("http://", "https://")):
        raise ValidationError(_("URL must start with http:// or https://"))

    is_debug = current_app.debug
    is_testing = current_app.testing
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    # RFC 8252 Section 8.3: HTTP is allowed for loopback interface redirect URIs
    # https://datatracker.ietf.org/doc/html/rfc8252#section-8.3
    is_localhost = hostname in ("localhost", "127.0.0.1", "::1")

    if url.startswith("http://") and not (
        is_debug or is_testing or is_localhost
    ):  # pragma: no cover
        raise ValidationError(
            _(
                "HTTP is only allowed for localhost or in debug/testing mode. Use HTTPS in production."
            )
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


class AuthorizationParamsForm(FlaskForm):
    """Form to customize OAuth authorization parameters."""

    scopes = SelectMultipleField(
        _("Scopes:"),
        choices=get_scopes_choices,
        default=get_scopes_default,
        description=_("Select the scopes to request from the authorization server"),
        widget=ListWidget(prefix_label=False),
        option_widget=CheckboxInput(),
    )
    prompt = SelectField(
        _("Prompt:"),
        choices=get_prompt_choices,
        description=_("Control the authentication UI behavior"),
    )
    ui_locales = SelectField(
        _("UI Locale:"),
        choices=get_ui_locales_choices,
        description=_("Preferred language for the authentication UI"),
    )

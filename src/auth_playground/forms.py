from urllib.parse import urlparse

from babel import Locale
from babel import UnknownLocaleError
from flask import current_app
from flask import g
from flask_babel import lazy_gettext as _
from flask_wtf import FlaskForm
from markupsafe import Markup
from wtforms import ButtonField
from wtforms import HiddenField
from wtforms import IntegerField
from wtforms import PasswordField
from wtforms import SelectField
from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms import ValidationError
from wtforms.csrf.core import CSRFTokenField
from wtforms.fields.choices import SelectFieldBase
from wtforms.meta import clean_key
from wtforms.validators import DataRequired
from wtforms.validators import Length
from wtforms.validators import NumberRange
from wtforms.validators import Optional
from wtforms.widgets import CheckboxInput
from wtforms.widgets import ListWidget

BARE_FIELDS = (
    HiddenField,
    CSRFTokenField,
    SubmitField,
    ButtonField,
    SelectFieldBase._Option,
)


class BaseForm(FlaskForm):
    """Form whose fields are rendered through the _field.html template.

    Hidden fields, buttons and choice options are rendered bare. A field can declare
    ``render_kw={"group_with": "<button name>"}`` to render that button
    next to its input.
    """

    class Meta:
        def render_field(self, field, render_kw):
            render_kw = {**(field.render_kw or {}), **render_kw}
            group_with = render_kw.pop("group_with", None)
            render_kw = {clean_key(key): value for key, value in render_kw.items()}
            if isinstance(field, BARE_FIELDS):
                return field.widget(field, **render_kw)

            template = current_app.jinja_env.get_template("_field.html")
            return Markup(
                template.render(
                    field=field,
                    render_kw=render_kw,
                    field_id=render_kw.get("id", field.id),
                    fieldset=isinstance(field.widget, ListWidget),
                    button=field._form[group_with] if group_with else None,
                )
            )


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


class RefreshTokenForm(BaseForm):
    """Form to refresh access token using refresh token."""

    refresh = SubmitField(_("Renew tokens"))


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

    if url.startswith("http://") and not (is_debug or is_testing or is_localhost):
        raise ValidationError(
            _(
                "HTTP is only allowed for localhost or in debug/testing mode. Use HTTPS in production."
            )
        )


class ServerConfigForm(BaseForm):
    """Form to configure the provider server URL."""

    issuer_url = StringField(
        _("Provider URL:"),
        validators=[
            DataRequired(message=_("Provider URL is required")),
            validate_issuer_url,
        ],
        render_kw={
            "placeholder": "https://auth.example.com",
            "type": "url",
            "group_with": "discover",
        },
    )
    discover = SubmitField(_("Continue"), render_kw={"class": "primary"})


class ClientConfigForm(BaseForm):
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
    save = SubmitField(_("Complete configuration"))


class DynamicRegistrationForm(BaseForm):
    """Form to trigger dynamic client registration with CSRF protection."""

    initial_access_token = StringField(
        _("Initial access token:"),
        validators=[],
        render_kw={
            "placeholder": _("Leave empty if not required"),
            "group_with": "register",
        },
    )
    register = SubmitField(_("Register client"), render_kw={"class": "primary"})


class UnregisterClientForm(BaseForm):
    """Form to trigger client unregistration with CSRF protection."""

    unregister = SubmitField(_("Unregister client"), render_kw={"class": "secondary"})


class LogoutLocalForm(BaseForm):
    """Form to trigger local logout with CSRF protection."""

    logout = SubmitField(_("Log out"), render_kw={"class": "secondary"})


class AuthorizationParamsForm(BaseForm):
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
    max_age = IntegerField(
        _("Max age (seconds):"),
        validators=[Optional(), NumberRange(min=0)],
        description=_(
            "Maximum authentication age. 0 forces re-authentication and refreshes auth_time."
        ),
        render_kw={"placeholder": "0"},
    )
    acr_values = StringField(
        _("ACR values:"),
        description=_(
            "Requested authentication context classes, space-separated (step-up authentication)."
        ),
    )
    login_hint = StringField(
        _("Login hint:"),
        description=_("Identifier to pre-fill on the provider's login screen."),
    )
    claims = TextAreaField(
        _("Claims (JSON):"),
        description=_(
            "Specific claims to request, as an OIDC claims JSON object (advanced)."
        ),
    )
    sign_in = ButtonField(_("Sign in"), render_kw={"class": "primary"})


class LogoutParamsForm(BaseForm):
    """Form to customize RP-Initiated Logout parameters."""

    id_token_hint = StringField(
        _("ID Token Hint:"),
        description=_("ID Token previously issued, used to identify the user session"),
    )
    client_id = StringField(
        _("Client ID:"),
        description=_("OAuth client identifier"),
    )
    post_logout_redirect_uri = StringField(
        _("Post-Logout Redirect URI:"),
        description=_("URI to redirect to after logout"),
    )
    logout_hint = StringField(
        _("Logout Hint:"),
        description=_("Hint about the user to log out"),
    )
    ui_locales = SelectField(
        _("UI Locale:"),
        choices=get_ui_locales_choices,
        description=_("Preferred language for the logout UI"),
    )
    server_logout = ButtonField(_("Server log out"), render_kw={"class": "contrast"})

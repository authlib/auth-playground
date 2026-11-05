import ipaddress
import json
from urllib.parse import urlparse

from babel import Locale
from babel import UnknownLocaleError
from flask import current_app
from flask import g
from flask import render_template
from flask import url_for
from flask_babel import lazy_gettext as _
from flask_wtforms_htmx import HtmxFlaskForm
from markupsafe import Markup
from wtforms import ButtonField
from wtforms import Field
from wtforms import HiddenField
from wtforms import IntegerField
from wtforms import PasswordField
from wtforms import RadioField
from wtforms import SelectField
from wtforms import SelectMultipleField
from wtforms import StringField
from wtforms import SubmitField
from wtforms import TextAreaField
from wtforms import ValidationError
from wtforms.csrf.core import CSRFTokenField
from wtforms.fields import SelectChoice
from wtforms.meta import clean_key
from wtforms.validators import DataRequired
from wtforms.validators import InputRequired
from wtforms.validators import Length
from wtforms.validators import NumberRange
from wtforms.validators import Optional
from wtforms.widgets import CheckboxInput
from wtforms.widgets import ListWidget
from wtforms.widgets import html_params

import auth_playground
from auth_playground.authorization import PKCE_METHODS
from auth_playground.authorization import authorization_endpoint
from auth_playground.authorization import parse_extra_params
from auth_playground.authorization import preview_lines
from auth_playground.authorization import preview_params
from auth_playground.client_auth import METHODS
from auth_playground.client_auth import PUBLIC_METHOD
from auth_playground.client_auth import SECRET_METHODS
from auth_playground.client_auth import advertised_methods
from auth_playground.session import server_metadata

REGISTRABLE_GRANT_TYPES = ("authorization_code", "refresh_token")

BARE_FIELDS = (
    HiddenField,
    CSRFTokenField,
    SubmitField,
    ButtonField,
)


class BaseForm(HtmxFlaskForm):
    """Form whose fields are rendered through the _field.html template.

    Hidden fields and buttons are rendered bare. A field can declare
    ``render_kw={"group_with": "<button name>"}`` to render that button
    next to its input.
    """

    class Meta:
        htmx_inline_validation = False

        def field_wrapper(self, field, render_kw):
            group_with = render_kw.pop("group_with", None)
            render_kw = {clean_key(key): value for key, value in render_kw.items()}
            if isinstance(field, BARE_FIELDS):
                return field.widget(field, **render_kw)

            field_id = render_kw.get("id", field.id)
            fieldset = isinstance(field.widget, ListWidget)
            error_id = f"{field_id}-error" if field.errors else None
            if error_id and not fieldset:
                render_kw = {
                    **render_kw,
                    "aria-invalid": "true",
                    "aria-describedby": error_id,
                }

            template = current_app.jinja_env.get_template("_field.html")
            return Markup(
                template.render(
                    field=field,
                    render_kw=render_kw,
                    field_id=field_id,
                    fieldset=fieldset,
                    error_id=error_id,
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


def is_loopback_address(hostname):
    """Tell whether the hostname is a loopback IP address."""
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


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
    is_localhost = hostname == "localhost" or is_loopback_address(hostname)

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


def advertised_choices(values, advertised):
    """Build the choices of values, labelling the ones the server does not advertise."""
    return [
        SelectChoice(
            value,
            value
            if value in advertised
            else _("{value} (not advertised)").format(value=value),
        )
        for value in values
    ]


def auth_method_choices(methods):
    """Label the authentication methods the server does not advertise."""
    return advertised_choices(methods, advertised_methods(server_metadata()))


def auth_method_default(methods):
    """Return the first advertised method, or the first method."""
    advertised = advertised_methods(server_metadata())
    return next((method for method in methods if method in advertised), methods[0])


def get_grant_type_choices():
    """Label the grant types the server does not advertise.

    Per RFC 8414 §2, the default is ``authorization_code`` and ``implicit``.
    """
    advertised = server_metadata().get(
        "grant_types_supported", ["authorization_code", "implicit"]
    )
    return advertised_choices(REGISTRABLE_GRANT_TYPES, advertised)


def disable_for_public_client(form, source, target):
    """Disable the authentication method when the client is public."""
    target.render_kw = {**(target.render_kw or {}), "disabled": source.data == "public"}


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
        description=_("Leave empty for a public client."),
        render_kw={"placeholder": "******************"},
    )
    token_endpoint_auth_method = SelectField(
        _("Token endpoint authentication:"),
        choices=lambda: auth_method_choices(METHODS),
        default=lambda: auth_method_default(METHODS),
        description=_("How the client proves its identity to the token endpoint."),
    )
    save = SubmitField(_("Complete configuration"))

    def validate_client_secret(self, field):
        if self.token_endpoint_auth_method.data != PUBLIC_METHOD:
            if not field.data:
                raise ValidationError(
                    _("This authentication method needs a client secret.")
                )
            return

        if field.data:
            raise ValidationError(
                _("A public client has no secret. Leave the secret empty.")
            )


class DynamicRegistrationForm(BaseForm):
    """Form to trigger dynamic client registration with CSRF protection."""

    client_type = RadioField(
        _("Client type:"),
        choices=[
            SelectChoice("confidential", _("Confidential, with a client secret")),
            SelectChoice("public", _("Public, without a secret, with PKCE")),
        ],
        default="confidential",
    )
    auth_method = SelectField(
        _("Token endpoint authentication:"),
        choices=lambda: auth_method_choices(SECRET_METHODS),
        default=lambda: auth_method_default(SECRET_METHODS),
        description=_("A public client uses none."),
    ).triggered_by("client_type", disable_for_public_client, on="change")
    grant_types = SelectMultipleField(
        _("Grant types to register:"),
        choices=get_grant_type_choices,
        default=list(REGISTRABLE_GRANT_TYPES),
        validators=[InputRequired(message=_("Choose at least one grant type."))],
        widget=ListWidget(prefix_label=False),
        option_widget=CheckboxInput(),
    )
    initial_access_token = StringField(
        _("Initial access token:"),
        validators=[],
        render_kw={
            "placeholder": _("Leave empty if not required"),
            "group_with": "register",
        },
    )
    register = SubmitField(_("Register client"), render_kw={"class": "primary"})

    def __init__(self, *args, **kwargs):
        meta = {"htmx_endpoint": url_for("oauth.client_dynamic_registration")}
        super().__init__(*args, meta={**meta, **kwargs.pop("meta", {})}, **kwargs)


class ChangeServerForm(BaseForm):
    """Form to forget the provider, and configure another one."""

    change = SubmitField(_("Change provider"), render_kw={"class": "secondary"})


class UnregisterClientForm(BaseForm):
    """Form to trigger client unregistration with CSRF protection."""

    unregister = SubmitField(_("Unregister client"), render_kw={"class": "secondary"})


class LogoutLocalForm(BaseForm):
    """Form to trigger local logout with CSRF protection."""

    logout = SubmitField(_("Log out"), render_kw={"class": "secondary"})


def get_pkce_choices():
    """Label the PKCE methods the server does not advertise."""
    advertised = server_metadata().get("code_challenge_methods_supported", [])
    return advertised_choices(PKCE_METHODS, advertised) + [
        SelectChoice("", _("Disabled"))
    ]


def get_pkce_default():
    """Return the first advertised PKCE method.

    A public client uses S256 even when the server advertises nothing, per
    RFC 9700 §2.1.1. A confidential client uses no PKCE then.
    """
    advertised = server_metadata().get("code_challenge_methods_supported", [])
    if method := next((m for m in PKCE_METHODS if m in advertised), None):
        return method

    oauth_config = auth_playground.get_oauth_config(current_app)
    if oauth_config.get("token_endpoint_auth_method") == PUBLIC_METHOD:
        return "S256"
    return ""


class AuthorizationPreviewWidget:
    """Render the authorization request built from the form."""

    def __call__(self, field, **kwargs):
        kwargs.setdefault("id", field.id)
        return Markup(
            render_template(
                "_auth_preview.html",
                attributes=Markup(html_params(**kwargs)),
                label=field.label.text,
                endpoint=authorization_endpoint(),
                params=list(preview_lines(preview_params(field._form))),
            )
        )


class AuthorizationPreviewField(Field):
    """A read-only preview of the authorization request."""

    widget = AuthorizationPreviewWidget()

    def process_formdata(self, valuelist):
        pass


class AuthorizationParamsForm(BaseForm):
    """Form to customize OAuth authorization parameters."""

    class Meta:
        htmx_inline_validation = True

    pkce = SelectField(
        _("PKCE:"),
        choices=get_pkce_choices,
        default=get_pkce_default,
        description=_(
            "Sends a code_challenge here, and the code_verifier with the token request."
        ),
    )
    scopes = SelectMultipleField(
        _("Scopes:"),
        choices=get_scopes_choices,
        default=get_scopes_default,
        description=_("Select the scopes to request from the authorization server"),
        widget=ListWidget(prefix_label=False),
        option_widget=CheckboxInput(),
    )
    other_scopes = StringField(
        _("Other scopes:"),
        description=_("Space-separated, sent as they are."),
    )
    prompt = SelectField(
        _("Prompt:"),
        choices=get_prompt_choices,
        description=_("Control the authentication UI behavior"),
    )
    ui_locales = SelectField(
        _("UI Locale:"),
        choices=get_ui_locales_choices,
        default="",
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
    extra_params = TextAreaField(
        _("Extra parameters:"),
        description=_("One name=value per line, added to the request as they are."),
        render_kw={"placeholder": "resource=https://api.example.com"},
    )
    preview = AuthorizationPreviewField(
        _("Authorization request"), wrapper=False
    ).triggered_by("*")
    sign_in = ButtonField(_("Sign in"), render_kw={"class": "primary"})

    def __init__(self, *args, **kwargs):
        meta = {"htmx_endpoint": url_for("oauth.authorize")}
        super().__init__(*args, meta={**meta, **kwargs.pop("meta", {})}, **kwargs)

    def validate_claims(self, field):
        if not field.data:
            return

        try:
            claims = json.loads(field.data)
        except ValueError:
            claims = None

        if not isinstance(claims, dict):
            raise ValidationError(_("Claims must be a JSON object."))

    def validate_extra_params(self, field):
        _pairs, errors = parse_extra_params(field.data)
        if errors:
            raise ValidationError(
                _(
                    "Each line must be name=value, with a parameter the playground "
                    "does not set itself: {errors}"
                ).format(errors=", ".join(errors))
            )


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

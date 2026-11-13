import ipaddress
import json
from functools import cached_property
from urllib.parse import urlparse

from babel import Locale
from babel import UnknownLocaleError
from flask import current_app
from flask import g
from flask import render_template
from flask import session
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
from wtforms.fields import SelectFieldBase
from wtforms.meta import clean_key
from wtforms.validators import DataRequired
from wtforms.validators import InputRequired
from wtforms.validators import Length
from wtforms.validators import NumberRange
from wtforms.validators import Optional
from wtforms.widgets import CheckboxInput
from wtforms.widgets import ListWidget
from wtforms.widgets import RadioInput
from wtforms.widgets import html_params

import auth_playground
from auth_playground.authorization import PKCE_METHODS
from auth_playground.authorization import RESERVED_PARAMS
from auth_playground.authorization import authorization_preview
from auth_playground.authorization import parse_extra_params
from auth_playground.client_auth import CONFIDENTIAL_METHODS
from auth_playground.client_auth import KEY_METHOD
from auth_playground.client_auth import METHODS
from auth_playground.client_auth import PUBLIC_METHOD
from auth_playground.client_auth import SECRET_METHODS
from auth_playground.client_auth import advertised_methods
from auth_playground.client_auth import advertised_signing_algs
from auth_playground.client_key import ALGORITHMS
from auth_playground.client_key import DEFAULT_ALGORITHMS
from auth_playground.client_key import InvalidKeyError
from auth_playground.client_key import check_private_key
from auth_playground.client_key import key_algorithms
from auth_playground.client_key import key_summary
from auth_playground.client_key import pending_key
from auth_playground.client_key import preferred_algorithm
from auth_playground.client_key import publish_key
from auth_playground.grants import GRANTS
from auth_playground.grants import JWT_BEARER
from auth_playground.grants import advertised_grant_types
from auth_playground.grants import grant_type_label
from auth_playground.jwt_bearer import DEFAULT_LIFETIME
from auth_playground.jwt_bearer import FORM_CLAIMS
from auth_playground.jwt_bearer import KEY_SOURCE
from auth_playground.jwt_bearer import PASTED_SOURCE
from auth_playground.jwt_bearer import SECRET_SOURCE
from auth_playground.jwt_bearer import assertion_alg
from auth_playground.jwt_bearer import available_sources
from auth_playground.jwt_bearer import build_assertion_preview
from auth_playground.jwt_bearer import claims_object
from auth_playground.jwt_bearer import jwt_bearer_preview
from auth_playground.jwt_bearer import pasted_assertion
from auth_playground.logout import logout_preview
from auth_playground.session import server_metadata
from auth_playground.token_request import TOKEN_RESERVED_PARAMS
from auth_playground.token_request import client_credentials_preview
from auth_playground.token_request import password_preview

REGISTRABLE_GRANT_TYPES = (
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "password",
    JWT_BEARER,
)

DEFAULT_REGISTERED_GRANT_TYPES = ["authorization_code", "refresh_token"]

# The render_kw keys that field_wrapper reads, and that are not HTML attributes.
WRAPPER_DEFAULTS = {"group_with": None, "hidden": False, "param": None}

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
    next to its input, and ``render_kw={"param": "<name>"}`` to show the
    protocol parameter it sets after its label.
    """

    class Meta:
        htmx_inline_validation = False

        def render_field(self, field, render_kw):
            # WTForms gives the render_kw of a choices field to each of its
            # options, which are rendered without field_wrapper.
            if isinstance(field, SelectFieldBase._Option) and field.render_kw:
                field.render_kw = {
                    key: value
                    for key, value in field.render_kw.items()
                    if key not in WRAPPER_DEFAULTS
                }
            return super().render_field(field, render_kw)

        def field_wrapper(self, field, render_kw):
            wrapper_kw = {
                key: render_kw.pop(key, default)
                for key, default in WRAPPER_DEFAULTS.items()
            }
            group_with = wrapper_kw["group_with"]
            render_kw = {clean_key(key): value for key, value in render_kw.items()}
            if isinstance(field, BARE_FIELDS):
                return field.widget(field, hidden=wrapper_kw["hidden"], **render_kw)

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
                    hidden=wrapper_kw["hidden"],
                    param=wrapper_kw["param"],
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

    refresh = SubmitField(_("Renew tokens"), render_kw={"class": "secondary"})


class UserInfoForm(BaseForm):
    """Form to call the UserInfo endpoint with the access token."""

    userinfo = SubmitField(_("Get user info"), render_kw={"class": "secondary"})


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


def advertised_label(label, advertised):
    """Mark the label of a value the server does not advertise."""
    if advertised:
        return label
    return _("{value} (not advertised)").format(value=label)


def advertised_choices(values, advertised):
    """Build the choices of values, labelling the ones the server does not advertise."""
    return [
        SelectChoice(value, advertised_label(value, value in advertised))
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
    """Label the grant types with their name and value, and mark the ones not advertised."""
    advertised = advertised_grant_types()
    return [
        SelectChoice(
            value,
            Markup('{} <code class="param-name">{}</code>').format(
                advertised_label(grant_type_label(value), value in advertised), value
            ),
        )
        for value in REGISTRABLE_GRANT_TYPES
    ]


def disable_for_public_client(form, source, target):
    """Disable the authentication method when the client is public."""
    target.render_kw = {**(target.render_kw or {}), "disabled": source.data == "public"}


def show_field(field, shown):
    """Show or hide the field, with its label."""
    field.render_kw = {**(field.render_kw or {}), "hidden": not shown}


def signing_alg_choices(algs):
    """Label the signing algorithms the server does not advertise."""
    advertised = advertised_signing_algs(server_metadata())
    if advertised is None:
        return [SelectChoice(alg, alg) for alg in algs]
    return advertised_choices(algs, advertised)


def advertised_userinfo_algs():
    """Return the algorithms the server can sign the UserInfo response with."""
    algs = server_metadata().get("userinfo_signing_alg_values_supported") or []
    if isinstance(algs, str):
        algs = [algs]
    return [alg for alg in algs if isinstance(alg, str) and alg != "none"]


def userinfo_alg_choices():
    """Offer an unsigned UserInfo response, or one signed with an advertised algorithm."""
    return [
        SelectChoice("", _("JSON, not signed")),
        *(
            SelectChoice(alg, _("Signed with {alg}").format(alg=alg))
            for alg in advertised_userinfo_algs()
        ),
    ]


def userinfo_alg_field(**kwargs):
    """Return the field of the userinfo_signed_response_alg client setting."""
    return SelectField(
        _("UserInfo response:"),
        choices=userinfo_alg_choices,
        default="",
        description=_("A signed response is a JWT, and Authlib checks its signature."),
        render_kw={"param": "userinfo_signed_response_alg"},
        **kwargs,
    )


def default_signing_alg(algs):
    """Return the first advertised algorithm, or the first algorithm."""
    return preferred_algorithm(algs, advertised_signing_algs(server_metadata()))


def generated_key_algorithms():
    """Return the algorithms a generated key can use."""
    if advertised_signing_algs(server_metadata()) is None:
        return list(DEFAULT_ALGORITHMS)
    return list(ALGORITHMS)


def regenerate_key(form, source, target):
    """Replace the generated key with a new one."""
    pending_key(form.key_form_name, form.signing_alg.data, regenerate=True)


class ClientKeyPreviewWidget:
    """Render the public key of the client, as the provider needs it."""

    def __call__(self, field, **kwargs):
        kwargs.setdefault("id", field.id)
        form = field._form
        return Markup(
            render_template(
                "_client_key_preview.html",
                attributes=Markup(html_params(**kwargs)),
                key=form.key_details(),
                registration=field.registration,
                jwks_delivery=form.jwks_delivery.data if field.registration else None,
            )
        )


class ClientKeyPreviewField(Field):
    """A read-only preview of the key of a private_key_jwt client."""

    widget = ClientKeyPreviewWidget()

    def __init__(self, label=None, registration=False, **kwargs):
        super().__init__(label, **kwargs)
        self.registration = registration

    def process_formdata(self, valuelist):
        pass


def client_key_fields(method_sources, id_prefix="", registration=False):
    """Return the fields that choose the key of a private_key_jwt client."""
    source_sources = [*method_sources, "key_source"]
    preview_sources = [*source_sources, "private_key", "key_id", "signing_alg"]
    if registration:
        preview_sources.append("jwks_delivery")
    return (
        RadioField(
            _("Client key:"),
            choices=[
                SelectChoice("generate", _("Generate a key")),
                SelectChoice("import", _("Import a key")),
            ],
            default="generate",
            id=f"{id_prefix}key_source",
            description=_("The client signs its token requests with this key."),
        ).triggered_by(method_sources, on="change"),
        TextAreaField(
            _("Private key:"),
            id=f"{id_prefix}private_key",
            description=_(
                "PEM or JWK: RSA, EC or Ed25519. Kept in your session, never shown again."
            ),
            render_kw={
                "rows": 6,
                "placeholder": "-----BEGIN PRIVATE KEY-----",
                "autocomplete": "off",
                "spellcheck": "false",
            },
        ).triggered_by(source_sources, on="change"),
        StringField(
            _("Key ID (kid):"),
            id=f"{id_prefix}key_id",
            description=_(
                "Sent in the assertion header. Leave empty to use the key "
                "thumbprint (RFC 7638)."
            ),
        ).triggered_by(source_sources, on="change"),
        SelectField(
            _("Signing algorithm:"),
            choices=[],
            id=f"{id_prefix}signing_alg",
            description=_("From token_endpoint_auth_signing_alg_values_supported."),
            render_kw={"param": "token_endpoint_auth_signing_alg"},
        ).triggered_by([*source_sources, "private_key"], on="change"),
        ButtonField(
            _("Generate another key"),
            id=f"{id_prefix}regenerate_key",
            render_kw={"class": "secondary outline"},
        )
        .triggered_by(source_sources, on="change")
        .triggers("key_preview", regenerate_key),
        ClientKeyPreviewField(
            id=f"{id_prefix}key_preview", registration=registration, wrapper=False
        ).triggered_by(preview_sources, on="change"),
    )


class ClientKeyMixin:
    """Choose the key of a private_key_jwt client.

    The form declares the fields of ``client_key_fields``, and the
    ``key_form_name`` its generated key is kept under.
    """

    key_form_name = None

    def uses_key(self):
        """Tell whether the client authenticates with a private key."""
        raise NotImplementedError

    def setup_client_key(self):
        """Show the fields the chosen key needs, and offer the algorithms of the key."""
        uses_key = self.uses_key()
        importing = self.key_source.data == "import"
        show_field(self.key_source, uses_key)
        show_field(self.private_key, uses_key and importing)
        show_field(self.key_id, uses_key and importing)
        show_field(self.signing_alg, uses_key)
        show_field(self.regenerate_key, uses_key and not importing)

        algs = self.key_algorithms()
        self.signing_alg.choices = signing_alg_choices(algs)
        if self.signing_alg.data not in algs:
            self.signing_alg.data = default_signing_alg(algs)

        # The provider may download the key as soon as the user enters its
        # jwks_uri, before the client is saved.
        if uses_key and (data := self.client_key()):
            publish_key(data)

    @cached_property
    def imported_key(self):
        """The imported key as a JWK dict, or ``None`` when it is not valid."""
        if not self.private_key.data:
            return None
        try:
            return check_private_key(self.private_key.data, self.key_id.data or None)
        except InvalidKeyError:
            return None

    def key_algorithms(self):
        """Return the algorithms the chosen key can use."""
        if self.key_source.data != "import":
            return generated_key_algorithms()
        if data := self.imported_key:
            return key_algorithms(data)
        return list(ALGORITHMS)

    def client_key(self):
        """Return the chosen key as a JWK dict, or ``None`` when there is none yet."""
        if self.key_source.data == "import":
            return self.imported_key
        return pending_key(self.key_form_name, self.signing_alg.data)

    def key_details(self):
        """Return what the provider needs to know about the key, or ``None``."""
        if not self.uses_key():
            return None

        data = self.client_key()
        if data is None:
            return {}

        return {
            **key_summary(data, self.signing_alg.data),
            "generated": self.key_source.data != "import",
        }

    def validate_private_key(self, field):
        if not self.uses_key() or self.key_source.data != "import":
            return
        if not field.data:
            raise ValidationError(_("Paste the private key of the client."))
        try:
            check_private_key(field.data)
        except InvalidKeyError as exc:
            raise ValidationError(str(exc)) from exc


class ClientConfigForm(ClientKeyMixin, BaseForm):
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
        render_kw={"placeholder": "auth-playground-client", "param": "client_id"},
    )
    token_endpoint_auth_method = SelectField(
        _("Token endpoint authentication:"),
        choices=lambda: auth_method_choices(METHODS),
        default=lambda: auth_method_default(METHODS),
        description=_("How the client proves its identity to the token endpoint."),
        render_kw={"param": "token_endpoint_auth_method"},
    )
    client_secret = PasswordField(
        _("Client secret:"),
        description=_("Leave empty for a public client."),
        render_kw={"param": "client_secret"},
    ).triggered_by("token_endpoint_auth_method", on="change")
    (
        key_source,
        private_key,
        key_id,
        signing_alg,
        regenerate_key,
        key_preview,
    ) = client_key_fields(["token_endpoint_auth_method"])
    userinfo_signed_response_alg = userinfo_alg_field()
    save = SubmitField(_("Complete configuration"))

    key_form_name = "manual"

    def __init__(self, *args, **kwargs):
        meta = {"htmx_endpoint": url_for("routes.configure_client")}
        super().__init__(*args, meta={**meta, **kwargs.pop("meta", {})}, **kwargs)
        show_field(self.client_secret, not self.uses_key())
        show_field(self.userinfo_signed_response_alg, bool(advertised_userinfo_algs()))
        self.setup_client_key()

    def uses_key(self):
        return self.token_endpoint_auth_method.data == KEY_METHOD

    def validate_client_secret(self, field):
        method = self.token_endpoint_auth_method.data
        if method in SECRET_METHODS:
            if not field.data:
                raise ValidationError(
                    _("This authentication method needs a client secret.")
                )
            return

        if method == PUBLIC_METHOD and field.data:
            raise ValidationError(
                _("A public client has no secret. Leave the secret empty.")
            )


class DynamicRegistrationForm(ClientKeyMixin, BaseForm):
    """Form to trigger dynamic client registration with CSRF protection."""

    client_type = RadioField(
        _("Client type:"),
        choices=[
            SelectChoice("confidential", _("Confidential, with a secret or a key")),
            SelectChoice("public", _("Public, without a secret, with PKCE")),
        ],
        default="confidential",
    )
    auth_method = SelectField(
        _("Token endpoint authentication:"),
        choices=lambda: auth_method_choices(CONFIDENTIAL_METHODS),
        default=lambda: auth_method_default(CONFIDENTIAL_METHODS),
        description=_("A public client uses none."),
        render_kw={"param": "token_endpoint_auth_method"},
    ).triggered_by("client_type", disable_for_public_client, on="change")
    (
        key_source,
        private_key,
        key_id,
        signing_alg,
        regenerate_key,
        key_preview,
    ) = client_key_fields(
        ["client_type", "auth_method"], id_prefix="registration-", registration=True
    )
    jwks_delivery = RadioField(
        _("Public key sent to the provider:"),
        choices=[
            SelectChoice("jwks", _("jwks: the key goes in the registration request")),
            SelectChoice(
                "jwks_uri",
                _(
                    "jwks_uri: the provider downloads the key from the playground, "
                    "which must be reachable from the provider"
                ),
            ),
        ],
        default="jwks",
        id="registration-jwks_delivery",
    ).triggered_by(["client_type", "auth_method"], on="change")
    userinfo_signed_response_alg = userinfo_alg_field(
        id="registration-userinfo_signed_response_alg"
    )
    grant_types = SelectMultipleField(
        _("Grant types to register:"),
        choices=get_grant_type_choices,
        default=DEFAULT_REGISTERED_GRANT_TYPES,
        widget=ListWidget(prefix_label=False),
        option_widget=CheckboxInput(),
        render_kw={"param": "grant_types"},
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

    key_form_name = "registration"

    def __init__(self, *args, **kwargs):
        meta = {"htmx_endpoint": url_for("oauth.client_dynamic_registration")}
        super().__init__(*args, meta={**meta, **kwargs.pop("meta", {})}, **kwargs)
        show_field(self.jwks_delivery, self.uses_key())
        show_field(self.userinfo_signed_response_alg, bool(advertised_userinfo_algs()))
        self.setup_client_key()

    def uses_key(self):
        return self.client_type.data != "public" and self.auth_method.data == KEY_METHOD

    def validate_grant_types(self, field):
        # InputRequired would put "required" on every checkbox,
        # so the browser would refuse any unchecked one.
        if not field.data:
            raise ValidationError(_("Choose at least one grant type."))


class ChangeServerForm(BaseForm):
    """Form to forget the provider, and configure another one."""

    change = SubmitField(_("Change provider"), render_kw={"class": "secondary"})


class UnregisterClientForm(BaseForm):
    """Form to trigger client unregistration with CSRF protection."""

    unregister = SubmitField(_("Unregister client"), render_kw={"class": "secondary"})


class LogoutLocalForm(BaseForm):
    """Form to trigger local logout with CSRF protection."""

    logout = SubmitField(_("Log out here"), render_kw={"class": "secondary"})


class ChangeClientForm(BaseForm):
    """Form to forget the client, and configure another one."""

    change = SubmitField(_("Change client"), render_kw={"class": "secondary"})


def get_pkce_choices():
    """Label the PKCE methods the server does not advertise."""
    advertised = server_metadata().get("code_challenge_methods_supported", [])
    return advertised_choices(PKCE_METHODS, advertised) + [
        SelectChoice("", _("Disabled"))
    ]


def get_response_mode_choices():
    """Offer the default response mode, and label form_post when not advertised.

    Per OIDC Discovery §3, a server without response_modes_supported supports
    query and fragment.
    """
    advertised = server_metadata().get("response_modes_supported") or [
        "query",
        "fragment",
    ]
    return [
        SelectChoice("", _("Default (query)")),
        *advertised_choices(["form_post"], advertised),
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


class PreviewWidget:
    """Render what the form builds, with ``template``."""

    def __init__(self, template):
        self.template = template

    def __call__(self, field, **kwargs):
        kwargs.setdefault("id", field.id)
        return Markup(
            render_template(
                self.template,
                attributes=Markup(html_params(**kwargs)),
                label=field.label.text,
                preview=field.build(field._form),
            )
        )


class RequestPreviewField(Field):
    """A read-only preview of the request that ``build(form)`` returns."""

    widget = PreviewWidget("_request_preview.html")

    def __init__(self, label=None, build=None, **kwargs):
        super().__init__(label, **kwargs)
        self.build = build

    def process_formdata(self, valuelist):
        pass


def scopes_field(default=None):
    """Return a field to check the scopes the server supports."""
    return SelectMultipleField(
        _("Scopes:"),
        choices=get_scopes_choices,
        default=default,
        description=_("Select the scopes to request from the authorization server."),
        widget=ListWidget(prefix_label=False),
        option_widget=CheckboxInput(),
        render_kw={"param": "scope"},
    )


class AssertionPreviewField(RequestPreviewField):
    """A read-only preview of the assertion that ``build(form)`` returns."""

    widget = PreviewWidget("_assertion_preview.html")


class RequestParamsForm(BaseForm):
    """Parameters common to the requests that obtain tokens.

    The form validates its fields inline at ``endpoint``, where it is posted.
    """

    endpoint = None
    reserved_params = RESERVED_PARAMS
    # Not kept when the form is shown again after a failed request.
    secret_fields = ()

    class Meta:
        htmx_inline_validation = True

    other_scopes = StringField(
        _("Other scopes:"),
        description=_("Space-separated, sent as they are."),
        render_kw={"param": "scope"},
    )
    extra_params = TextAreaField(
        _("Extra parameters:"),
        description=_("One name=value per line, added to the request as they are."),
        render_kw={"placeholder": "resource=https://api.example.com"},
    )

    def __init__(self, *args, **kwargs):
        meta = {"htmx_endpoint": url_for(self.endpoint)}
        super().__init__(*args, meta={**meta, **kwargs.pop("meta", {})}, **kwargs)

    def validate_extra_params(self, field):
        _pairs, errors = parse_extra_params(field.data, self.reserved_params)
        if errors:
            raise ValidationError(
                _(
                    "Each line must be name=value, with a parameter the playground "
                    "does not set itself: {errors}"
                ).format(errors=", ".join(errors))
            )


class AuthorizationParamsForm(RequestParamsForm):
    """Form to customize OAuth authorization parameters."""

    endpoint = "oauth.authorize"

    pkce = SelectField(
        _("PKCE:"),
        choices=get_pkce_choices,
        default=get_pkce_default,
        description=_(
            "Sends a code_challenge here, and the code_verifier with the token request."
        ),
        render_kw={"param": "code_challenge_method"},
    )
    scopes = scopes_field(default=get_scopes_default)
    response_mode = SelectField(
        _("Response mode:"),
        choices=get_response_mode_choices,
        default="",
        description=_(
            "form_post: the provider posts the response to the playground, "
            "instead of putting it in the URL."
        ),
        render_kw={"param": "response_mode"},
    )
    prompt = SelectField(
        _("Prompt:"),
        choices=get_prompt_choices,
        description=_("What the provider shows to the user."),
        render_kw={"param": "prompt"},
    )
    ui_locales = SelectField(
        _("UI locales:"),
        choices=get_ui_locales_choices,
        default="",
        description=_("Preferred language for the authentication UI."),
        render_kw={"param": "ui_locales"},
    )
    max_age = IntegerField(
        _("Max age (seconds):"),
        validators=[Optional(), NumberRange(min=0)],
        description=_(
            "Maximum authentication age. 0 forces re-authentication and refreshes auth_time."
        ),
        render_kw={"param": "max_age"},
    )
    acr_values = StringField(
        _("ACR values:"),
        description=_(
            "Requested authentication context classes, space-separated (step-up authentication)."
        ),
        render_kw={"param": "acr_values"},
    )
    login_hint = StringField(
        _("Login hint:"),
        description=_("Identifier to pre-fill on the provider's login screen."),
        render_kw={"param": "login_hint"},
    )
    claims = TextAreaField(
        _("Claims (JSON):"),
        description=_(
            "Specific claims to request, as an OIDC claims JSON object (advanced)."
        ),
        render_kw={"param": "claims"},
    )
    preview = RequestPreviewField(
        _("Authorization request"), build=authorization_preview, wrapper=False
    ).triggered_by("*")
    sign_in = ButtonField(_("Sign in"), render_kw={"class": "primary"})

    def validate_claims(self, field):
        if not field.data:
            return

        try:
            claims = json.loads(field.data)
        except ValueError:
            claims = None

        if not isinstance(claims, dict):
            raise ValidationError(_("Claims must be a JSON object."))


class ClientCredentialsForm(RequestParamsForm):
    """Form to request tokens for the client itself (RFC 6749 §4.4)."""

    endpoint = "oauth.client_credentials"
    reserved_params = TOKEN_RESERVED_PARAMS

    scopes = scopes_field()
    preview = RequestPreviewField(
        _("Token request"), build=client_credentials_preview, wrapper=False
    ).triggered_by("*")
    request_tokens = ButtonField(_("Request tokens"), render_kw={"class": "primary"})


class PasswordForm(RequestParamsForm):
    """Form to request tokens with the user's password (RFC 6749 §4.3)."""

    endpoint = "oauth.password"
    reserved_params = TOKEN_RESERVED_PARAMS | {"username", "password"}
    secret_fields = ("password",)

    username = StringField(
        _("Username:"),
        validators=[InputRequired()],
        render_kw={"autocomplete": "off", "param": "username"},
    )
    password = PasswordField(
        _("Password:"),
        validators=[InputRequired()],
        # Browsers ignore "off" on password fields.
        render_kw={"autocomplete": "new-password", "param": "password"},
    )
    scopes = scopes_field(default=get_scopes_default)
    preview = RequestPreviewField(
        _("Token request"), build=password_preview, wrapper=False
    ).triggered_by("*")
    request_tokens = ButtonField(_("Request tokens"), render_kw={"class": "primary"})


class ChoiceRadioInput(RadioInput):
    """A radio button that applies the render_kw of its choice."""

    # WTForms 3.3.2 applies the render_kw of the choices to the options of a
    # select, but not to radio buttons.
    def __call__(self, field, **kwargs):
        return super().__call__(field, **{**field.choice.render_kw, **kwargs})


def assertion_source_choices():
    """Offer the sources of the assertion, and disable those the client lacks."""
    oauth_config = auth_playground.get_oauth_config(current_app)
    available = available_sources(oauth_config)
    if KEY_SOURCE in available:
        key_label = _("Sign with the client key: {alg}").format(
            alg=assertion_alg(KEY_SOURCE, oauth_config)
        )
    else:
        key_label = _("Sign with the client key: this client has none.")
    if SECRET_SOURCE in available:
        secret_label = _("Sign with the client secret: {alg}").format(
            alg=assertion_alg(SECRET_SOURCE, oauth_config)
        )
    else:
        secret_label = _("Sign with the client secret: this client has none.")
    return [
        SelectChoice(
            KEY_SOURCE, key_label, render_kw={"disabled": KEY_SOURCE not in available}
        ),
        SelectChoice(
            SECRET_SOURCE,
            secret_label,
            render_kw={"disabled": SECRET_SOURCE not in available},
        ),
        SelectChoice(
            PASTED_SOURCE,
            _("Paste an assertion issued elsewhere"),
        ),
    ]


def assertion_source_default():
    """Return the first source of the assertion the client can use."""
    return available_sources(auth_playground.get_oauth_config(current_app))[0]


def signed_in_subject():
    """Return the sub of the signed-in user, or an empty string."""
    return (session.get("user") or {}).get("sub", "")


def configured_client_id():
    """Return the ID of the configured client, or an empty string."""
    return auth_playground.get_oauth_config(current_app).get("client_id", "")


def audience_choices():
    """Offer the issuer and the token endpoint as the audience."""
    metadata = server_metadata()
    return [
        SelectChoice(
            "issuer", _("{url} (issuer)").format(url=metadata.get("issuer", ""))
        ),
        SelectChoice(
            "token_endpoint",
            _("{url} (token endpoint)").format(url=metadata.get("token_endpoint", "")),
        ),
    ]


class JwtBearerForm(RequestParamsForm):
    """Form to request tokens with a JWT that says who they are for (RFC 7523 §2.1)."""

    endpoint = "oauth.jwt_bearer"
    reserved_params = TOKEN_RESERVED_PARAMS | {"assertion"}

    source = RadioField(
        _("Assertion:"),
        choices=assertion_source_choices,
        default=assertion_source_default,
        option_widget=ChoiceRadioInput(),
        description=_(
            "A client gets a key with private_key_jwt, and a secret with the "
            "other confidential methods."
        ),
    )
    assertion = TextAreaField(
        _("Assertion (JWT):"),
        description=_(
            "Sent as is. The playground only decodes it, it does not check "
            "the signature."
        ),
        render_kw={
            "rows": 5,
            "autocomplete": "off",
            "spellcheck": "false",
            "param": "assertion",
        },
    ).triggered_by("source", on="change")
    subject = StringField(
        _("Subject (sub):"),
        default=signed_in_subject,
        description=_(
            "Who the tokens are for. Filled with the sub of the signed-in user."
        ),
        render_kw={"autocomplete": "off"},
    ).triggered_by("source", on="change")
    issuer = StringField(
        _("Issuer (iss):"),
        default=configured_client_id,
        description=_("The client ID, unless another party issues the assertion."),
    ).triggered_by("source", on="change")
    audience = SelectField(
        _("Audience (aud):"),
        choices=audience_choices,
        default="issuer",
        description=_("Per RFC 10070 §4, both are allowed for a grant."),
    ).triggered_by("source", on="change")
    lifetime = IntegerField(
        _("Lifetime (seconds):"),
        default=DEFAULT_LIFETIME,
        description=_("From now to exp."),
        render_kw={"min": 1},
    ).triggered_by("source", on="change")
    extra_claims = TextAreaField(
        _("Extra claims:"),
        description=_("A JSON object, added to the claims above."),
        render_kw={"placeholder": '{"act": {"sub": "admin"}}'},
    ).triggered_by("source", on="change")
    scopes = scopes_field(default=get_scopes_default)
    preview = RequestPreviewField(
        _("Token request"), build=jwt_bearer_preview, wrapper=False
    ).triggered_by("*")
    assertion_preview = AssertionPreviewField(
        _("Assertion"), build=build_assertion_preview, wrapper=False
    ).triggered_by("*")
    request_tokens = ButtonField(_("Request tokens"), render_kw={"class": "primary"})

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        signing = self.signing()
        show_field(self.assertion, not signing)
        for field in (
            self.subject,
            self.issuer,
            self.audience,
            self.lifetime,
            self.extra_claims,
        ):
            show_field(field, signing)

    def signing(self):
        """Tell whether the playground signs the assertion."""
        return self.source.data != PASTED_SOURCE

    def validate_source(self, field):
        oauth_config = auth_playground.get_oauth_config(current_app)
        if field.data not in available_sources(oauth_config):
            raise ValidationError(_("This client cannot sign the assertion this way."))

    def validate_assertion(self, field):
        if not self.signing() and not pasted_assertion(self):
            raise ValidationError(_("Paste the assertion."))

    def validate_subject(self, field):
        if self.signing() and not field.data:
            raise ValidationError(_("Enter who the tokens are for."))

    def validate_issuer(self, field):
        if self.signing() and not field.data:
            raise ValidationError(_("Enter who issues the assertion."))

    def validate_lifetime(self, field):
        if not self.signing():
            # Like Optional, forget that the hidden value is not a number.
            field.errors[:] = []
            return
        if field.data is not None and field.data < 1:
            raise ValidationError(_("Enter a number of seconds, 1 or more."))

    def validate_extra_claims(self, field):
        if not self.signing() or not field.data:
            return

        claims = claims_object(field.data)
        if claims is None:
            raise ValidationError(_("The extra claims must be a JSON object."))
        if form_claims := [name for name in FORM_CLAIMS if name in claims]:
            raise ValidationError(
                _("The form already sets these claims: {claims}.").format(
                    claims=", ".join(form_claims)
                )
            )


def grant_label(grant):
    """Mark the label of a grant type that is deprecated, not advertised or not registered."""
    marks = [grant.label]
    if grant.deprecated:
        marks.append(_("deprecated"))
    if not grant.advertised:
        marks.append(_("not advertised"))
    if not grant.registered:
        marks.append(_("not registered"))
    return " · ".join(str(mark) for mark in marks)


def get_grant_choices():
    """Group the grant types, and label the ones the server does not advertise."""
    return [
        SelectChoice(grant.name, grant_label(grant), optgroup=grant.group)
        for grant in GRANTS
    ]


class GrantForm(BaseForm):
    """Choose the grant type used to obtain tokens."""

    class Meta:
        csrf = False

    grant = SelectField(_("Grant type:"), choices=get_grant_choices)
    choose = SubmitField(_("Choose"), render_kw={"class": "secondary"})


class LogoutParamsForm(BaseForm):
    """Form to customize RP-Initiated Logout parameters."""

    class Meta:
        htmx_inline_validation = True

    id_token_hint = StringField(
        _("ID token hint:"),
        description=_(
            "The ID token from the sign-in. It tells the provider which session to end."
        ),
        render_kw={"param": "id_token_hint"},
    )
    client_id = StringField(
        _("Client ID:"),
        description=_("The ID of the client."),
        render_kw={"param": "client_id"},
    )
    post_logout_redirect_uri = StringField(
        _("Post-logout redirect URI:"),
        description=_("Where the provider sends the browser after the logout."),
        render_kw={"param": "post_logout_redirect_uri"},
    )
    logout_hint = StringField(
        _("Logout hint:"),
        description=_("Which user to log out, when the ID token hint is empty."),
        render_kw={"param": "logout_hint"},
    )
    ui_locales = SelectField(
        _("UI locales:"),
        choices=get_ui_locales_choices,
        description=_("Preferred language for the logout UI."),
        render_kw={"param": "ui_locales"},
    )
    preview = RequestPreviewField(
        _("Logout request"), build=logout_preview, wrapper=False
    ).triggered_by("*")
    server_logout = ButtonField(
        _("Log out at the provider"), render_kw={"class": "primary"}
    )

    def __init__(self, *args, **kwargs):
        meta = {"htmx_endpoint": url_for("oauth.logout")}
        super().__init__(*args, meta={**meta, **kwargs.pop("meta", {})}, **kwargs)

from flask import g
from flask_babel import Babel
from flask_babel import get_locale
from werkzeug.exceptions import NotFound
from werkzeug.routing import BaseConverter

babel = Babel()


class LangConverter(BaseConverter):
    """URL converter that validates language codes against available translations."""

    def __init__(self, map, *args, **kwargs):
        super().__init__(map, *args, **kwargs)
        self.regex = r"[a-z]{2,3}"

    def to_python(self, value):
        """Convert URL value to Python, validating against available translations.

        Raises 404 if language code is not available.
        """
        available_langs = [locale.language for locale in babel.list_translations()]

        if value not in available_langs:
            raise NotFound(
                f"Language '{value}' is not available. "
                f"Available languages: {', '.join(available_langs)}"
            )

        return value

    def to_url(self, value):
        """Convert Python value to URL."""
        return value


def setup_i18n(app):
    @app.url_defaults
    def add_language_code(endpoint, values):
        """Automatically inject language code into url_for() calls when using i18n routes."""
        if endpoint and endpoint.startswith("oauth."):
            return

        if not g.get("lang_code"):
            g.lang_code = app.config.get("BABEL_DEFAULT_LOCALE", "en")

        if "lang_code" not in values:
            values.setdefault("lang_code", g.lang_code)

    @app.url_value_preprocessor
    def pull_lang_code(endpoint, values):
        """Extract language code from URL and store in g.lang_code for i18n routes."""
        if values is not None and "lang_code" in values:
            g.lang_code = values.pop("lang_code")

    @app.before_request
    def before_request():
        g.available_languages = babel.list_translations()
        g.available_language_codes = [
            locale.language for locale in g.available_languages
        ]

    @app.context_processor
    def global_processor():
        return {
            "locale": get_locale(),
            "available_languages": getattr(g, "available_languages", []),
        }

    def locale_selector():
        # Language is always specified in URL prefix (mandatory)
        return g.get("lang_code", app.config["BABEL_DEFAULT_LOCALE"])

    babel.init_app(app, locale_selector=locale_selector)
    app.url_map.converters["lang"] = LangConverter
    app.jinja_env.policies["ext.i18n.trimmed"] = True

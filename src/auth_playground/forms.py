from flask_wtf import FlaskForm
from wtforms import SubmitField


class RefreshTokenForm(FlaskForm):
    """Form to refresh access token using refresh token."""

    submit = SubmitField("Renew tokens")

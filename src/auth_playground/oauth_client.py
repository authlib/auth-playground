"""Authlib client classes used by the playground."""

from authlib.common.urls import url_decode
from authlib.integrations.flask_client import FlaskOAuth2App
from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session


class TokenSession(OAuth2Session):
    """Send every value of a repeated token request parameter.

    Authlib 1.9.4 keeps only the last one (authlib issue #524).
    """

    def _fetch_token(
        self, url, body="", headers=None, auth=None, method="POST", **kwargs
    ):
        if method.upper() != "POST":
            return super()._fetch_token(
                url, body=body, headers=headers, auth=auth, method=method, **kwargs
            )

        resp = self.session.post(
            url, data=url_decode(body), headers=headers, auth=auth, **kwargs
        )
        for hook in self.compliance_hook["access_token_response"]:
            resp = hook(resp)
        return self.parse_response_token(resp)


class PlaygroundOAuth2App(FlaskOAuth2App):
    client_cls = TokenSession


class PlaygroundOAuth(OAuth):
    oauth2_client_cls = PlaygroundOAuth2App

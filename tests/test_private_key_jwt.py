import json
from unittest.mock import patch

import pytest
import requests
from authlib.common.urls import url_decode
from flask import g
from flask_webtest import TestApp
from joserfc import jwk
from joserfc import jwt

from auth_playground import client_key
from auth_playground import create_app
from auth_playground import env_signing_alg
from auth_playground.client_key import InvalidKeyError
from auth_playground.endpoints import load_server_metadata
from auth_playground.session import ServerConfig
from tests.fake_provider import METADATA
from tests.fake_provider import server_session

HTMX_HEADERS = {"HX-Request": "true"}


@pytest.fixture
def ec_key():
    """Return a P-256 private key in PEM format."""
    return jwk.generate_key("EC", "P-256", private=True).as_pem(private=True).decode()


def key_session(client, alg="RS256", method="private_key_jwt", **extra):
    """Store a client that authenticates with a generated key."""
    data = client_key.generate_key(alg)
    server_session(
        client,
        {
            "client_id": "c",
            "client_secret": None,
            "token_endpoint_auth_method": method,
            "client_key": data,
            "token_endpoint_auth_signing_alg": alg,
            **extra,
        },
    )
    return data


@pytest.mark.parametrize("alg", list(client_key.ALGORITHMS))
def test_generated_key_signs_with_its_algorithm(alg):
    """Test a generated key can use the algorithm it was made for."""
    data = client_key.generate_key(alg)

    assert alg in client_key.key_algorithms(data)
    assert data["kid"] == client_key.load_key(data).thumbprint()


def test_import_a_pem_key(ec_key):
    """Test a PEM key gets its thumbprint as kid."""
    data = client_key.import_private_key(ec_key)

    assert data["kty"] == "EC"
    assert data["kid"] == client_key.load_key(data).thumbprint()
    assert client_key.key_algorithms(data) == ["ES256"]
    assert client_key.describe_key(data) == "EC P-256"


def test_import_a_jwk_keeps_its_kid():
    """Test a JWK keeps its kid, unless another one is given."""
    key = jwk.generate_key("OKP", "Ed25519", private=True)
    text = json.dumps({**key.as_dict(private=True), "kid": "mine"})

    assert client_key.import_private_key(text)["kid"] == "mine"
    assert client_key.import_private_key(text, "other")["kid"] == "other"
    assert client_key.key_algorithms(client_key.import_private_key(text)) == [
        "Ed25519",
        "EdDSA",
    ]


def rsa_jwk(**extra):
    """Return an RSA private key as JWK text."""
    key = jwk.generate_key("RSA", 2048, private=True)
    return json.dumps({**key.as_dict(private=True), **extra})


@pytest.mark.parametrize(
    ("alg", "expected"),
    [(None, ["RS256", "RS384"]), ("PS384", ["PS384"]), ("ES256", [])],
)
def test_a_jwk_signs_only_with_its_algorithm(alg, expected):
    """Test a JWK with an alg can only sign with it."""
    extra = {"alg": alg} if alg else {}
    data = client_key.import_private_key(rsa_jwk(**extra))

    assert client_key.key_algorithms(data)[:2] == expected


def test_the_public_key_can_verify():
    """Test the key_ops of the private key are not published."""
    data = client_key.import_private_key(rsa_jwk(key_ops=["sign"]))
    public = client_key.public_jwks(data)["keys"][0]

    assert "key_ops" not in public
    assert "d" not in public
    assert "alg" not in public


def test_the_public_key_keeps_the_algorithm_of_the_jwk():
    """Test the alg of the private JWK is published."""
    data = client_key.import_private_key(rsa_jwk(alg="PS256"))

    assert client_key.public_jwks(data)["keys"][0]["alg"] == "PS256"


@pytest.mark.parametrize("extra", [{"use": "enc"}, {"key_ops": ["decrypt"]}])
def test_check_refuses_a_key_not_meant_for_signing(unconfigured_app, extra):
    """Test a JWK for encryption cannot sign the assertions."""
    with unconfigured_app.test_request_context(), pytest.raises(InvalidKeyError) as exc:
        client_key.check_private_key(rsa_jwk(**extra))

    assert "not meant for signing" in str(exc.value)


def test_check_refuses_a_jwk_with_a_wrong_algorithm(unconfigured_app):
    """Test a JWK cannot declare an algorithm its key cannot sign with."""
    with unconfigured_app.test_request_context(), pytest.raises(InvalidKeyError) as exc:
        client_key.check_private_key(rsa_jwk(alg="ES256"))

    assert "cannot sign with this key for ES256" in str(exc.value)


@pytest.mark.parametrize(
    ("alg", "expected"),
    [(None, "RS256"), ("PS512", "PS512")],
)
def test_env_key_signs_with_the_algorithm_of_the_jwk(unconfigured_app, alg, expected):
    """Test the alg of the JWK wins over the algorithms the server advertises."""
    extra = {"alg": alg} if alg else {}
    data = client_key.check_private_key(rsa_jwk(**extra))

    with unconfigured_app.test_request_context():
        assert env_signing_alg(data) == expected


def test_describe_an_rsa_key():
    """Test an RSA key is described with its size."""
    assert client_key.describe_key(client_key.generate_key("PS256")) == "RSA 2048"


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("not a key", "not an RSA, EC or Ed25519 key"),
        ("{not json", "not valid JSON"),
        ('{"kty": "oct", "k": "abc"}', "must be an RSA, EC or OKP key"),
        ('{"kty": "EC", "crv": "P-256"}', "This JWK is not valid"),
    ],
)
def test_import_refuses_what_is_not_a_private_key(unconfigured_app, text, message):
    """Test the import explains why the text is not a usable key."""
    with unconfigured_app.test_request_context(), pytest.raises(InvalidKeyError) as exc:
        client_key.import_private_key(text)

    assert message in str(exc.value)


def test_import_refuses_a_public_key(unconfigured_app):
    """Test a public key cannot sign the assertions."""
    public = jwk.generate_key("RSA", 2048).as_pem(private=False).decode()

    with unconfigured_app.test_request_context(), pytest.raises(InvalidKeyError) as exc:
        client_key.import_private_key(public)

    assert "public key" in str(exc.value)


def test_private_pem_is_the_same_key():
    """Test the downloaded PEM imports back to the same key."""
    data = client_key.generate_key("ES384")
    pem = client_key.private_pem(data)

    assert client_key.import_private_key(pem.decode())["d"] == data["d"]


def test_manual_form_hides_the_key_fields(unconfigured_testapp):
    """Test the key fields are hidden until private_key_jwt is chosen."""
    server_session(unconfigured_testapp)
    res = unconfigured_testapp.get("/en/client/manual")

    assert '<div id="wrap-key_source" hidden>' in res.text
    assert '<div id="wrap-client_secret">' in res.text
    assert "private_key_jwt (not advertised)" in res.text


def test_choosing_private_key_jwt_shows_a_generated_key(
    unconfigured_test_client, csrf_token
):
    """Test the key fields and the public key appear with private_key_jwt."""
    server_session(unconfigured_test_client)
    res = unconfigured_test_client.post(
        "/en/client/manual",
        data={
            "csrf_token": csrf_token(unconfigured_test_client),
            "token_endpoint_auth_method": "private_key_jwt",
            "key_source": "generate",
        },
        headers={
            **HTMX_HEADERS,
            "HX-Source": "select#token_endpoint_auth_method",
            "HX-Target": "div#wrap-client_secret",
        },
    )

    assert res.status_code == 200
    assert '<div id="wrap-client_secret" hidden>' in res.text
    assert '<div id="wrap-key_source">' in res.text
    assert "Settings to enter at the provider" in res.text
    assert "RSA 2048 key" in res.text
    with unconfigured_test_client.session_transaction() as sess:
        pending = sess[client_key.PENDING_KEY]["manual"]
    assert pending["kid"] in res.text
    assert f"/jwks/{client_key.key_id(pending)}.json" in res.text


def test_the_generated_key_stays_until_regenerated(
    unconfigured_test_client, csrf_token
):
    """Test the public key does not change between requests, unless asked."""
    server_session(unconfigured_test_client)
    data = {
        "csrf_token": csrf_token(unconfigured_test_client),
        "token_endpoint_auth_method": "private_key_jwt",
        "key_source": "generate",
        "signing_alg": "RS256",
    }
    unconfigured_test_client.get("/en/client")
    unconfigured_test_client.post("/en/client/manual", data=data)
    with unconfigured_test_client.session_transaction() as sess:
        first = sess[client_key.PENDING_KEY]["manual"]

    unconfigured_test_client.post("/en/client/manual", data=data)
    with unconfigured_test_client.session_transaction() as sess:
        assert sess[client_key.PENDING_KEY]["manual"] == first

    unconfigured_test_client.post(
        "/en/client/manual",
        data={**data, "regenerate_key": ""},
        headers={**HTMX_HEADERS, "HX-Source": "button#regenerate_key"},
    )
    with unconfigured_test_client.session_transaction() as sess:
        assert sess[client_key.PENDING_KEY]["manual"]["kid"] != first["kid"]
    first_url = f"/jwks/{client_key.key_id(first)}.json"
    assert unconfigured_test_client.get(first_url).status_code == 404


def test_the_generated_key_is_served_before_saving(unconfigured_testapp):
    """Test the jwks_uri of a generated key works before the client is saved."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["token_endpoint_auth_method"] = "private_key_jwt"
    form.submit()
    with unconfigured_testapp.session_transaction() as sess:
        pending = sess[client_key.PENDING_KEY]["manual"]
    url = f"/jwks/{client_key.key_id(pending)}.json"

    assert unconfigured_testapp.get(url).json["keys"][0]["kid"] == pending["kid"]

    unconfigured_testapp.get("/en/server").forms["change-server-form"].submit()
    unconfigured_testapp.get(url, status=404)


def test_changing_the_algorithm_generates_a_key_that_fits(
    unconfigured_test_client, csrf_token
):
    """Test an RSA key is replaced by an EC key for ES256."""
    server_session(unconfigured_test_client)
    data = {
        "csrf_token": csrf_token(unconfigured_test_client),
        "token_endpoint_auth_method": "private_key_jwt",
        "key_source": "generate",
    }
    unconfigured_test_client.post(
        "/en/client/manual", data={**data, "signing_alg": "RS256"}
    )
    unconfigured_test_client.post(
        "/en/client/manual", data={**data, "signing_alg": "ES256"}
    )

    with unconfigured_test_client.session_transaction() as sess:
        assert sess[client_key.PENDING_KEY]["manual"]["kty"] == "EC"


@pytest.mark.parametrize(
    ("alg", "expected"),
    [(None, "RS256"), ("PS384", "PS384")],
)
def test_pasting_a_jwk_selects_its_algorithm(
    unconfigured_test_client, csrf_token, alg, expected
):
    """Test the alg of a pasted JWK becomes the signing algorithm."""
    server_session(unconfigured_test_client)
    extra = {"alg": alg} if alg else {}
    res = unconfigured_test_client.post(
        "/en/client/manual",
        data={
            "csrf_token": csrf_token(unconfigured_test_client),
            "token_endpoint_auth_method": "private_key_jwt",
            "key_source": "import",
            "private_key": rsa_jwk(**extra),
            "signing_alg": "RS256",
        },
        headers={**HTMX_HEADERS, "HX-Source": "textarea#private_key"},
    )

    assert f'<option selected value="{expected}">' in res.text
    assert ('value="PS512"' in res.text) is (alg is None)


def test_manual_configuration_with_a_generated_key(unconfigured_testapp):
    """Test the client keeps the generated key, and serves its public key."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["client_id"] = "keyed-client"
    form["token_endpoint_auth_method"] = "private_key_jwt"
    form.submit("save")

    with unconfigured_testapp.session_transaction() as sess:
        config = sess["oauth_config"]
        assert client_key.PENDING_KEY not in sess
    assert config["client_secret"] is None
    assert config["token_endpoint_auth_signing_alg"] == "RS256"

    data = config["client_key"]
    res = unconfigured_testapp.get(f"/jwks/{client_key.key_id(data)}.json")
    public = res.json["keys"][0]
    assert public["kid"] == data["kid"]
    assert "alg" not in public
    assert "d" not in public

    res = unconfigured_testapp.get("/en/client")
    assert "Client key" in res.text
    assert "Download the private key" in res.text

    res = unconfigured_testapp.get("/client/key.pem")
    assert res.content_type == "application/x-pem-file"
    assert res.headers["Cache-Control"] == "no-store"
    assert client_key.import_private_key(res.text)["d"] == data["d"]


def test_manual_configuration_with_an_imported_key(unconfigured_testapp, ec_key):
    """Test an imported EC key gets an algorithm that fits it."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["client_id"] = "keyed-client"
    form["token_endpoint_auth_method"] = "private_key_jwt"
    form["key_source"] = "import"
    form["private_key"] = ec_key
    form["key_id"] = "billing-2026"
    form.submit("save")

    with unconfigured_testapp.session_transaction() as sess:
        config = sess["oauth_config"]
    assert config["client_key"]["kid"] == "billing-2026"
    assert config["token_endpoint_auth_signing_alg"] == "ES256"


@pytest.mark.parametrize(
    ("private_key", "message"),
    [
        ("", "Paste the private key of the client."),
        ("garbage", "not an RSA, EC or Ed25519 key"),
    ],
)
def test_manual_configuration_refuses_a_wrong_key(
    unconfigured_testapp, private_key, message
):
    """Test the imported key must be a private key the playground can use."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["client_id"] = "keyed-client"
    form["token_endpoint_auth_method"] = "private_key_jwt"
    form["key_source"] = "import"
    form["private_key"] = private_key
    res = form.submit("save")

    assert message in res.text
    assert "Paste a valid private key to see its public key." in res.text
    with unconfigured_testapp.session_transaction() as sess:
        assert "oauth_config" not in sess


def test_manual_configuration_refuses_a_key_without_algorithm(unconfigured_testapp):
    """Test a key no algorithm of the playground can use is refused."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["client_id"] = "keyed-client"
    form["token_endpoint_auth_method"] = "private_key_jwt"
    form["key_source"] = "import"
    form["private_key"] = (
        jwk.generate_key("EC", "secp256k1", private=True).as_pem(private=True).decode()
    )
    res = form.submit("save")

    assert "The playground cannot sign with this key." in res.text


def test_signing_algorithms_follow_the_server(unconfigured_testapp):
    """Test the algorithms the server does not advertise are labelled."""
    with unconfigured_testapp.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {
            **METADATA,
            "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        }
    res = unconfigured_testapp.get("/en/client/manual")
    select = res.forms["client-form"]["signing_alg"]

    assert select.value == "ES256"
    assert "PS512 (not advertised)" in res.text


def test_dynamic_registration_sends_the_public_key(unconfigured_testapp):
    """Test the registration request holds the public key, and the client keeps it."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    form["auth_method"] = "private_key_jwt"
    form["signing_alg"] = "Ed25519"
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "keyed-client",
            "token_endpoint_auth_method": "private_key_jwt",
        }
        form.submit("register")

    sent = mock_post.call_args.kwargs["json"]
    assert sent["token_endpoint_auth_method"] == "private_key_jwt"
    assert sent["token_endpoint_auth_signing_alg"] == "Ed25519"
    assert "jwks_uri" not in sent
    with unconfigured_testapp.session_transaction() as sess:
        config = sess["oauth_config"]
    assert sent["jwks"]["keys"][0]["kid"] == config["client_key"]["kid"]
    assert config["token_endpoint_auth_method"] == "private_key_jwt"


def test_dynamic_registration_with_a_jwks_uri(unconfigured_testapp):
    """Test the provider can download the key during the registration."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    form["auth_method"] = "private_key_jwt"
    form["jwks_delivery"] = "jwks_uri"

    downloaded = []

    def register(url, json, **kwargs):
        key_id = json["jwks_uri"].rsplit("/", 1)[-1].removesuffix(".json")
        downloaded.append(client_key.published_jwks(key_id))
        return mock_post.return_value

    with patch("requests.post", side_effect=register) as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "keyed-client",
            "token_endpoint_auth_method": "private_key_jwt",
        }
        form.submit("register")

    assert "alg" not in downloaded[0]["keys"][0]
    sent = mock_post.call_args.kwargs["json"]
    assert "jwks" not in sent
    assert sent["jwks_uri"].startswith("http://client.test/jwks/")


def test_dynamic_registration_preview_follows_the_delivery(
    unconfigured_test_client, csrf_token
):
    """Test the preview shows the jwks_uri when the provider downloads the key."""
    server_session(unconfigured_test_client)
    res = unconfigured_test_client.post(
        "/client/dynamic-registration",
        data={
            "csrf_token": csrf_token(unconfigured_test_client),
            "client_type": "confidential",
            "auth_method": "private_key_jwt",
            "key_source": "generate",
            "jwks_delivery": "jwks_uri",
        },
        headers={
            **HTMX_HEADERS,
            "HX-Source": "input#registration-jwks_delivery-1",
            "HX-Target": "article#registration-key_preview",
        },
    )

    assert "Sent in the registration request" in res.text
    assert '"jwks_uri": "http://client.test/jwks/' in res.text


def test_dynamic_registration_without_the_key(unconfigured_testapp):
    """Test a server that picks private_key_jwt by itself leaves the client unusable."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "client",
            "client_secret": "secret",
            "token_endpoint_auth_method": "private_key_jwt",
        }
        res = form.submit("register").maybe_follow()

    assert "the playground has no key for it" in res.text
    with unconfigured_testapp.session_transaction() as sess:
        assert "oauth_config" not in sess


def test_forgetting_the_client_stops_serving_its_key(unconfigured_testapp):
    """Test the jwks_uri answers 404 once the client is forgotten."""
    data = key_session(unconfigured_testapp)
    with unconfigured_testapp.app.test_request_context():
        client_key.publish_key(data)
    url = f"/jwks/{client_key.key_id(data)}.json"
    assert unconfigured_testapp.get(url).status_int == 200

    form = unconfigured_testapp.get("/en/server").forms["change-server-form"]
    form.submit()

    assert unconfigured_testapp.get(url, status=404).status_int == 404


def test_unknown_jwks_uri(unconfigured_testapp):
    """Test an unknown key is not found."""
    unconfigured_testapp.get("/jwks/unknown.json", status=404)


def test_the_imported_key_is_served_before_saving(unconfigured_testapp, ec_key):
    """Test the jwks_uri of an imported key works before the client is saved."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["token_endpoint_auth_method"] = "private_key_jwt"
    form["key_source"] = "import"
    form["private_key"] = ec_key
    form.submit()
    data = client_key.import_private_key(ec_key)

    res = unconfigured_testapp.get(f"/jwks/{client_key.key_id(data)}.json")
    assert res.json["keys"][0]["kid"] == data["kid"]


def test_env_client_signs_with_an_advertised_algorithm(unconfigured_app):
    """Test the algorithm follows the metadata, loaded after the client is set up."""
    unconfigured_app.config.update(
        OAUTH_CLIENT_ID="c",
        OAUTH_AUTH_SERVER="https://test.example.com",
        OAUTH_CLIENT_KEY=client_key.generate_key("RS256"),
    )
    metadata = {
        **METADATA,
        "token_endpoint_auth_signing_alg_values_supported": ["PS256"],
    }
    with (
        patch(
            "auth_playground.endpoints.fetch_server_metadata",
            return_value=(metadata, None),
        ),
        unconfigured_app.test_request_context(),
    ):
        unconfigured_app.preprocess_request()
        load_server_metadata()
        _overwrite, kwargs = g.oauth._registry["default"]

    auth = next(m for m in kwargs["client_auth_methods"] if m.name == "private_key_jwt")
    assert auth.alg == "PS256"


def test_no_private_key_to_download(unconfigured_testapp):
    """Test a client without a key has nothing to download."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})
    unconfigured_testapp.get("/client/key.pem", status=404)


@pytest.mark.usefixtures("provider_metadata")
def test_token_preview_shows_the_client_assertion(unconfigured_test_client):
    """Test the preview shows the header and the claims the client signs."""
    data = key_session(unconfigured_test_client, alg="ES256")
    res = unconfigured_test_client.get("/en/request/client_credentials")

    assert "client_assertion=[generated]" in res.text
    assert "Client assertion" in res.text
    assert f"&#34;kid&#34;: &#34;{data['kid']}&#34;" in res.text
    assert "&#34;alg&#34;: &#34;ES256&#34;" in res.text
    assert "&#34;aud&#34;: &#34;https://test.example.com/oauth/token&#34;" in res.text


@pytest.mark.usefixtures("provider_metadata")
def test_token_preview_shows_the_client_secret_jwt_assertion(unconfigured_test_client):
    """Test client_secret_jwt shows its assertion too, signed with HS256."""
    server_session(
        unconfigured_test_client,
        {
            "client_id": "c",
            "client_secret": "s",
            "token_endpoint_auth_method": "client_secret_jwt",
        },
    )
    res = unconfigured_test_client.get("/en/request/client_credentials")

    assert "&#34;alg&#34;: &#34;HS256&#34;" in res.text


@pytest.fixture
def keyed_client(iam_server):
    """Register a private_key_jwt client at the provider, with its public key."""
    data = client_key.generate_key("ES256")
    client = iam_server.models.Client(
        client_id="auth-playground-keyed",
        client_name="Auth Playground Keyed",
        redirect_uris=["http://client.test/authorize_callback"],
        grant_types=["password"],
        response_types=["code"],
        token_endpoint_auth_method="private_key_jwt",
        jwks=json.dumps(client_key.public_jwks(data)),
        scope=["openid", "profile"],
    )
    iam_server.backend.save(client)
    yield client, data
    iam_server.backend.delete(client)


@pytest.fixture
def keyed_app(iam_server, keyed_client, unconfigured_app):
    """Configure the client and its private key as the environment would."""
    client, data = keyed_client
    unconfigured_app.config["OAUTH_CLIENT_ID"] = client.client_id
    unconfigured_app.config["OAUTH_AUTH_SERVER"] = iam_server.url
    unconfigured_app.config["OAUTH_CLIENT_KEY"] = data
    return unconfigured_app


def test_env_client_gets_tokens_with_its_key(keyed_app, keyed_client, iam_server):
    """Test the provider accepts the assertion, signed with the key and its kid.

    Canaille accepts private_key_jwt for the password grant, but not for
    client credentials.
    """
    _client, data = keyed_client
    user = iam_server.random_user(password="correct horse battery staple")
    testapp = TestApp(keyed_app)
    form = testapp.get("/en/request/password").forms["password-form"]
    form["username"] = user.user_name
    form["password"] = "correct horse battery staple"
    with patch.object(
        requests.Session, "send", autospec=True, side_effect=requests.Session.send
    ) as send:
        res = form.submit("request_tokens").follow()

    assert f"Tokens obtained for {user.user_name}." in res.text
    token_request = next(
        call.args[1] for call in send.call_args_list if call.args[1].method == "POST"
    )
    body = dict(url_decode(token_request.body))
    token = jwt.decode(body["client_assertion"], client_key.load_key(data))
    assert token.header["kid"] == data["kid"]
    assert token.header["alg"] == "ES256"


def test_env_client_key_is_read_only(keyed_app, keyed_client):
    """Test the key of the environment is shown, served, but never downloaded."""
    _client, data = keyed_client
    testapp = TestApp(keyed_app)
    res = testapp.get("/en/client")

    assert "Client key" in res.text
    assert data["kid"] in res.text
    assert "Download the private key" not in res.text
    testapp.get("/client/key.pem", status=404)
    res = testapp.get(f"/jwks/{client_key.key_id(data)}.json")
    assert res.json["keys"][0]["kid"] == data["kid"]


def test_env_private_key_is_read_at_startup(monkeypatch):
    """Test OAUTH_CLIENT_PRIVATE_KEY is imported when the application starts."""
    data = client_key.generate_key("EdDSA")
    monkeypatch.setenv(
        "OAUTH_CLIENT_PRIVATE_KEY", client_key.private_pem(data).decode()
    )
    app = create_app()

    assert app.config["OAUTH_CLIENT_KEY"]["d"] == data["d"]


def test_each_form_keeps_its_own_generated_key(unconfigured_test_client, csrf_token):
    """Test the registration form does not replace the key of the manual form."""
    server_session(unconfigured_test_client)
    token = csrf_token(unconfigured_test_client)
    unconfigured_test_client.post(
        "/en/client/manual",
        data={
            "csrf_token": token,
            "token_endpoint_auth_method": "private_key_jwt",
            "key_source": "generate",
            "signing_alg": "ES256",
        },
    )
    unconfigured_test_client.post(
        "/client/dynamic-registration",
        data={
            "csrf_token": token,
            "client_type": "confidential",
            "auth_method": "private_key_jwt",
            "key_source": "generate",
            "signing_alg": "RS256",
        },
        headers={**HTMX_HEADERS, "HX-Source": "select#registration-signing_alg"},
    )

    with unconfigured_test_client.session_transaction() as sess:
        keys = sess[client_key.PENDING_KEY]
    assert keys["manual"]["kty"] == "EC"
    assert keys["registration"]["kty"] == "RSA"


def test_env_private_key_must_be_usable(monkeypatch):
    """Test the application refuses to start with a key it cannot sign with."""
    key = jwk.generate_key("OKP", "Ed448", private=True)
    monkeypatch.setenv("OAUTH_CLIENT_PRIVATE_KEY", key.as_pem(private=True).decode())

    with pytest.raises(InvalidKeyError):
        create_app()


@pytest.mark.parametrize(
    ("registered_alg", "expected"),
    [(None, "RS256"), ("PS256", "PS256")],
)
def test_dynamic_registration_keeps_the_algorithm_of_the_server(
    unconfigured_testapp, registered_alg, expected
):
    """Test the client signs with the algorithm the server registered."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    form["auth_method"] = "private_key_jwt"
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "keyed-client",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": registered_alg,
        }
        form.submit("register")

    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["token_endpoint_auth_signing_alg"] == expected


def test_dynamic_registration_refuses_an_algorithm_the_key_cannot_use(
    unconfigured_testapp,
):
    """Test a server algorithm that does not fit the key leaves the client unusable."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    form["auth_method"] = "private_key_jwt"
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "keyed-client",
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": "ES256",
        }
        res = form.submit("register").maybe_follow()

    assert "the ES256 signing algorithm, which its key cannot use" in res.text
    with unconfigured_testapp.session_transaction() as sess:
        assert "oauth_config" not in sess


def test_dynamic_registration_shows_the_key_error(unconfigured_testapp):
    """Test a wrong imported key is explained, not reported as an invalid request."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    form["auth_method"] = "private_key_jwt"
    form["key_source"] = "import"
    form["private_key"] = "garbage"
    res = form.submit("register").maybe_follow()

    assert "not an RSA, EC or Ed25519 key" in res.text


def test_the_key_is_published_again_with_the_session(unconfigured_testapp):
    """Test the jwks_uri lives as long as the session, which each change renews."""
    data = key_session(unconfigured_testapp)
    url = f"/jwks/{client_key.key_id(data)}.json"
    unconfigured_testapp.get(url, status=404)

    with unconfigured_testapp.session_transaction() as sess:
        sess["something"] = "changed"
    unconfigured_testapp.get("/en/request/client_credentials")
    unconfigured_testapp.post("/logout/local", status="*")

    assert unconfigured_testapp.get(url).json["keys"][0]["kid"] == data["kid"]


def test_saving_the_server_config_publishes_the_key_again(unconfigured_testapp):
    """Test the key is published again when only the server config changes."""
    data = key_session(unconfigured_testapp)
    url = f"/jwks/{client_key.key_id(data)}.json"
    serialize = ServerConfig.serialize
    with patch.object(
        ServerConfig,
        "serialize",
        autospec=True,
        side_effect=lambda config: {**serialize(config), "server_type": "other"},
    ):
        unconfigured_testapp.get(url, status=404)

    assert unconfigured_testapp.get(url).json["keys"][0]["kid"] == data["kid"]

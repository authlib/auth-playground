from unittest.mock import patch

import pytest

from tests.fake_provider import server_session
from tests.test_userinfo import get_userinfo
from tests.test_userinfo import sign_in


def advertise_userinfo_algs(testapp, algs):
    """Make the fake provider advertise the algorithms of the UserInfo response."""
    server_session(testapp)
    with testapp.session_transaction() as sess:
        sess["server_metadata"] = {
            **sess["server_metadata"],
            "userinfo_signing_alg_values_supported": algs,
        }


def test_the_setting_is_hidden_without_advertised_algorithms(unconfigured_testapp):
    """Test the UserInfo response setting is hidden when the provider signs nothing."""
    server_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client/manual")

    assert '<div id="wrap-userinfo_signed_response_alg" hidden>' in res.text


def test_a_static_client_stores_the_setting(unconfigured_testapp):
    """Test the algorithm set at the provider is stored with the client."""
    advertise_userinfo_algs(unconfigured_testapp, ["RS256", "none"])
    res = unconfigured_testapp.get("/en/client/manual")
    assert "Signed with RS256" in res.text
    assert "Signed with none" not in res.text

    form = res.forms["client-form"]
    form["client_id"] = "client"
    form["client_secret"] = "secret"
    form["userinfo_signed_response_alg"] = "RS256"
    form.submit("save")

    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["userinfo_signed_response_alg"] == "RS256"


def test_a_static_client_without_signed_responses(unconfigured_testapp):
    """Test the setting is not stored when the response is not signed."""
    advertise_userinfo_algs(unconfigured_testapp, ["RS256"])
    form = unconfigured_testapp.get("/en/client/manual").forms["client-form"]
    form["client_id"] = "client"
    form["client_secret"] = "secret"
    form.submit("save")

    with unconfigured_testapp.session_transaction() as sess:
        assert "userinfo_signed_response_alg" not in sess["oauth_config"]


def test_dynamic_registration_asks_for_signed_responses(unconfigured_testapp):
    """Test the requested algorithm is sent, and the registered one is kept."""
    advertise_userinfo_algs(unconfigured_testapp, ["RS256", "ES256"])
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    form["userinfo_signed_response_alg"] = "RS256"
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "registered",
            "client_secret": "secret",
            "userinfo_signed_response_alg": "ES256",
        }
        form.submit("register")

    assert mock_post.call_args.kwargs["json"]["userinfo_signed_response_alg"] == "RS256"
    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["userinfo_signed_response_alg"] == "ES256"


@pytest.mark.parametrize("registered", [None, "none", ["RS256"]])
def test_dynamic_registration_ignored_by_the_provider(unconfigured_testapp, registered):
    """Test the setting is not kept when the provider did not register it."""
    advertise_userinfo_algs(unconfigured_testapp, "RS256")
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    form["userinfo_signed_response_alg"] = "RS256"
    client_data = {"client_id": "registered", "client_secret": "secret"}
    if registered:
        client_data["userinfo_signed_response_alg"] = registered
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = client_data
        res = form.submit("register").maybe_follow()

    assert "The provider did not register userinfo_signed_response_alg." in res.text
    with unconfigured_testapp.session_transaction() as sess:
        assert "userinfo_signed_response_alg" not in sess["oauth_config"]


def test_dynamic_registration_without_signed_responses(unconfigured_testapp):
    """Test the registration request does not ask for a signed response by default."""
    advertise_userinfo_algs(unconfigured_testapp, ["RS256"])
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "registered",
            "client_secret": "secret",
        }
        form.submit("register")

    assert "userinfo_signed_response_alg" not in mock_post.call_args.kwargs["json"]
    with unconfigured_testapp.session_transaction() as sess:
        assert "userinfo_signed_response_alg" not in sess["oauth_config"]


def ask_for_signed_responses(testapp, alg):
    """Store the algorithm of the UserInfo response with the client."""
    with testapp.session_transaction() as sess:
        sess["oauth_config"] = {
            **sess.get("oauth_config", {}),
            "userinfo_signed_response_alg": alg,
        }


def test_the_signed_response_is_shown(iam_server, iam_client, user, testapp):
    """Test the JWT of a signed response is shown with its header and claims."""
    iam_client.userinfo_signed_response_alg = "RS256"
    iam_server.backend.save(iam_client)
    sign_in(iam_server, iam_client, user, testapp)
    ask_for_signed_responses(testapp, "RS256")
    res = testapp.get("/en/tokens")
    assert "The client expects a response signed with RS256." in res.text

    res = get_userinfo(testapp)

    assert "User info received" in res.text
    assert (
        "Signed with RS256. Authlib checked the signature, iss, aud and sub."
        in res.text
    )
    with testapp.session_transaction() as sess:
        userinfo = sess["userinfo"]
    assert userinfo["jwt"] in res.text
    assert userinfo["header"]["alg"] == "RS256"
    assert userinfo["claims"]["sub"] == user.user_name


def test_an_unsigned_response_is_rejected(iam_server, iam_client, user, testapp):
    """Test Authlib rejects a response that is not signed as the client asked."""
    sign_in(iam_server, iam_client, user, testapp)
    ask_for_signed_responses(testapp, "RS256")

    res = get_userinfo(testapp)

    assert "The UserInfo response is not signed." in res.text
    with testapp.session_transaction() as sess:
        assert "userinfo" not in sess

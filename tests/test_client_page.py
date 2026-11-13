from unittest.mock import patch

import pytest

from auth_playground.oauth import response_grant_types
from tests.fake_provider import server_session


def register(testapp, **client_data):
    """Register a client with the dynamic registration form."""
    form = testapp.get("/en/client").forms["dynamic-registration-form"]
    with patch("requests.post") as mock_post:
        mock_post.return_value.json.return_value = {
            "client_id": "registered",
            "client_secret": "secret",
            "registration_access_token": "reg-token",
            "registration_client_uri": "https://test.example.com/oauth/register/1",
            **client_data,
        }
        form.submit("register")


def test_the_page_shows_the_configured_client(unconfigured_testapp):
    """Test the page sums up the client, instead of showing the setup forms."""
    server_session(unconfigured_testapp, {"client_id": "manual", "client_secret": "s"})

    res = unconfigured_testapp.get("/en/client")

    assert "<code>manual</code>" in res.text
    assert "Confidential" in res.text
    assert "JSON, not signed" in res.text
    assert "Grant types:" not in res.text
    assert "Registration:" not in res.text
    assert "Change client forgets this client and its tokens." in res.text
    assert "change-client-form" in res.forms
    assert "unregister-form" not in res.forms
    assert "client-form" not in res.forms


def test_a_registered_client_shows_its_grant_types(unconfigured_testapp):
    """Test the grant types the provider registered are stored and shown."""
    server_session(unconfigured_testapp)
    register(unconfigured_testapp, grant_types=["authorization_code", "refresh_token"])

    res = unconfigured_testapp.get("/en/client")

    with unconfigured_testapp.session_transaction() as sess:
        assert sess["oauth_config"]["grant_types"] == [
            "authorization_code",
            "refresh_token",
        ]
    assert "<code>authorization_code</code>" in res.text
    assert "Dynamic (RFC 7591), managed with RFC 7592" in res.text
    assert "Unregister client also deletes it at the provider." in res.text
    assert "change-client-form" in res.forms
    assert "unregister-form" in res.forms


def test_changing_a_registered_client_keeps_it_at_the_provider(unconfigured_testapp):
    """Test changing the client forgets its registration without deleting it."""
    server_session(unconfigured_testapp)
    register(unconfigured_testapp)

    with patch("requests.delete") as mock_delete:
        res = unconfigured_testapp.get("/en/client")
        res = res.forms["change-client-form"].submit("change").follow()

    mock_delete.assert_not_called()
    assert "dynamic-registration-form" in res.forms
    with unconfigured_testapp.session_transaction() as sess:
        assert "oauth_config" not in sess
        assert "registration_access_token" not in sess


def test_changing_the_client_needs_a_valid_request(unconfigured_test_client):
    """Test a request without CSRF token keeps the client."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    res = unconfigured_test_client.post("/en/client/change", follow_redirects=True)

    assert b"Invalid request" in res.data
    with unconfigured_test_client.session_transaction() as sess:
        assert sess["oauth_config"]["client_id"] == "c"


def test_a_client_from_the_environment_cannot_change(test_client):
    """Test the client set by the environment stays."""
    res = test_client.post("/en/client/change")

    assert res.status_code == 302
    assert res.location.endswith("/en/client")


@pytest.mark.parametrize(
    "grant_types",
    [None, "authorization_code", [], ["authorization_code", 1]],
)
def test_unexpected_registered_grant_types_are_unknown(grant_types):
    """Test grant types the playground cannot read are not kept."""
    assert response_grant_types({"grant_types": grant_types}) is None


def test_a_grant_type_not_registered_is_marked(unconfigured_testapp):
    """Test the request tab warns about a grant type the client cannot use."""
    server_session(unconfigured_testapp)
    register(unconfigured_testapp, grant_types=["authorization_code", "refresh_token"])

    res = unconfigured_testapp.get("/en/tokens/request?grant=password")

    assert "Password (ROPC) · deprecated · not advertised · not registered" in res.text
    assert (
        "This client is not registered for the password grant type, "
        "only for authorization_code, refresh_token." in res.text
    )


def test_a_manual_client_has_no_registration_warning(unconfigured_testapp):
    """Test the grant types of a client entered by hand are not known."""
    server_session(unconfigured_testapp, {"client_id": "c", "client_secret": "s"})

    res = unconfigured_testapp.get("/en/tokens/request?grant=password")

    assert "not registered" not in res.text

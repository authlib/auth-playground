from unittest.mock import patch

import pytest

from tests.fake_provider import server_session


def test_the_client_page_offers_both_methods(unconfigured_testapp):
    """Test the client page links to the two ways to set up a client."""
    server_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client")

    assert 'href="/en/client/dynamic"' in res.text
    assert 'href="/en/client/manual"' in res.text
    assert "client-form" not in res.forms
    assert "Register or enter a client" in res.text


def test_the_step_tells_the_chosen_method(unconfigured_testapp):
    """Test the client step shows the method of the page, and leads to the choice."""
    server_session(unconfigured_testapp)

    res = unconfigured_testapp.get("/en/client/dynamic")

    assert "<small>Dynamic registration</small>" in res.text
    assert "Register or enter a client" not in res.text
    assert '<a href="/en/client" aria-current="step">' in res.text


def test_the_manual_page_is_the_client_page_without_registration(
    unconfigured_test_client,
):
    """Test the client page leads to the manual form when it is the only method."""
    with unconfigured_test_client.session_transaction() as sess:
        sess["issuer_url"] = "https://test.example.com"
        sess["server_metadata"] = {"issuer": "https://test.example.com"}

    res = unconfigured_test_client.get("/en/client", follow_redirects=True)

    assert "<small>Manual configuration</small>" in res.text
    assert "client-form" in res.text


@pytest.mark.parametrize("path", ["/en/client/dynamic", "/en/client/manual"])
def test_the_setup_pages_send_back_to_the_client(unconfigured_test_client, path):
    """Test a configured client is shown instead of the setup forms."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    res = unconfigured_test_client.get(path)

    assert res.status_code == 302
    assert res.location.endswith("/en/client")


def test_a_refused_registration_form_shows_its_errors(unconfigured_testapp):
    """Test the errors of the registration form are shown in the form."""
    server_session(unconfigured_testapp)
    form = unconfigured_testapp.get("/en/client/dynamic").forms[
        "dynamic-registration-form"
    ]
    for checkbox in form.fields["grant_types"]:
        checkbox.checked = False

    res = form.submit("register")

    assert '<small id="grant_types-error">Choose at least one grant type.</small>' in (
        res.text
    )
    assert "dynamic-registration-form" in res.forms


def test_the_server_page_offers_both_methods_in_debug(unconfigured_app):
    """Test the server page links to the discovery and the static configuration."""
    unconfigured_app.config["DEBUG"] = True

    res = unconfigured_app.test_client().get("/en/server")

    assert 'href="/en/server/discover"' in res.text
    assert 'href="/en/server/static"' in res.text


def test_the_server_page_goes_to_discovery_in_production(unconfigured_app):
    """Test the server page has nothing to choose without the debug mode."""
    unconfigured_app.config["DEBUG"] = False

    res = unconfigured_app.test_client().get("/en/server")

    assert res.status_code == 302
    assert res.location.endswith("/en/server/discover")


def test_the_static_configuration_page(unconfigured_app):
    """Test the static configuration page lists the environment variables."""
    unconfigured_app.config["DEBUG"] = True

    res = unconfigured_app.test_client().get("/en/server/static")

    assert "OAUTH_AUTH_SERVER" in res.text
    assert "<small>Static configuration</small>" in res.text


def test_the_static_configuration_is_hidden_in_production(unconfigured_app):
    """Test the static configuration page needs the debug mode."""
    unconfigured_app.config["DEBUG"] = False

    res = unconfigured_app.test_client().get("/en/server/static")

    assert res.status_code == 302
    assert res.location.endswith("/en/server")


def test_the_discovery_sends_back_to_the_provider(unconfigured_test_client):
    """Test a configured provider is shown instead of the discovery form."""
    server_session(unconfigured_test_client)

    res = unconfigured_test_client.get("/en/server/discover")

    assert res.status_code == 302
    assert res.location.endswith("/en/server")


def test_the_discovery_is_closed_for_a_provider_from_the_environment(app, test_client):
    """Test the provider set by the environment cannot be replaced."""
    res = test_client.get("/en/server/discover")

    assert res.status_code == 302
    assert res.location.endswith("/en/server")


def test_a_stale_manual_form_keeps_the_configured_client(unconfigured_test_client):
    """Test the manual form from another tab does not replace the client."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    res = unconfigured_test_client.post(
        "/en/client/manual", data={"client_id": "other", "client_secret": "s"}
    )

    assert res.location.endswith("/en/client")
    with unconfigured_test_client.session_transaction() as sess:
        assert sess["oauth_config"]["client_id"] == "c"
    assert "A client is already set." in unconfigured_test_client.get(res.location).text


def test_a_post_to_a_fixed_path_is_not_a_provider_url(unconfigured_test_client):
    """Test the provider shortcut does not catch a POST to another page."""
    res = unconfigured_test_client.post("/en/server/static")

    assert res.status_code == 405


def test_a_stale_registration_form_keeps_the_configured_client(
    unconfigured_test_client, csrf_token
):
    """Test the dynamic registration form from another tab does not replace the client."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    with patch("requests.post") as mock_post:
        res = unconfigured_test_client.post(
            "/client/dynamic-registration",
            data={"csrf_token": csrf_token(unconfigured_test_client)},
        )

    mock_post.assert_not_called()
    assert res.location.endswith("/en/client")
    assert "A client is already set." in unconfigured_test_client.get(res.location).text


def test_a_stale_discovery_form_keeps_the_provider(unconfigured_test_client):
    """Test the discovery form from another tab does not replace the provider."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    res = unconfigured_test_client.post(
        "/en/server/discover", data={"issuer_url": "https://other.example.com"}
    )

    assert res.location.endswith("/en/server")
    assert "A provider is already set." in (
        unconfigured_test_client.get(res.location).text
    )
    with unconfigured_test_client.session_transaction() as sess:
        assert sess["issuer_url"] == "https://test.example.com"


def test_the_index_leads_to_the_request_or_the_tokens(unconfigured_test_client):
    """Test the home page leads to the grant types, then to the tokens."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})

    res = unconfigured_test_client.get("/en/")
    assert res.location.endswith("/en/request")

    with unconfigured_test_client.session_transaction() as sess:
        sess["token"] = {"access_token": "a"}
    res = unconfigured_test_client.get("/en/")
    assert res.location.endswith("/en/tokens")


def test_a_done_request_step_keeps_the_grant_of_the_tokens(unconfigured_test_client):
    """Test the request step names the grant of the tokens, not the grant viewed."""
    server_session(unconfigured_test_client, {"client_id": "c", "client_secret": "s"})
    with unconfigured_test_client.session_transaction() as sess:
        sess["token"] = {"access_token": "a"}
        sess["token_info"] = {"grant": "client_credentials"}

    res = unconfigured_test_client.get("/en/request/password")

    assert "<small>Client credentials</small>" in res.text
    assert "<small>Password (ROPC)</small>" not in res.text

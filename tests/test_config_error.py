def test_config_error_page_displays(unconfigured_test_client):
    """Test that config error page is shown when OAuth is not configured."""
    res = unconfigured_test_client.get("/config-error")
    assert res.status_code == 200
    assert b"Configuration Required" in res.data
    assert b"OAUTH_CLIENT_ID" in res.data
    assert b"OAUTH_CLIENT_SECRET" in res.data
    assert b"OAUTH_AUTH_SERVER" in res.data


def test_index_redirects_to_config_error_when_unconfigured(unconfigured_test_client):
    """Test that index redirects to config error when OAuth is not configured."""
    res = unconfigured_test_client.get("/")
    assert res.status_code == 302
    assert "/config-error" in res.location


def test_config_error_shows_redirect_uris(unconfigured_test_client):
    """Test that config error page shows redirect URIs."""
    res = unconfigured_test_client.get("/config-error")
    assert res.status_code == 200
    assert b"login_callback" in res.data
    assert b"logout_callback" in res.data


def test_tos_redirects_when_unconfigured(unconfigured_test_client):
    """Test that /tos redirects to config error when unconfigured."""
    res = unconfigured_test_client.get("/tos")
    assert res.status_code == 302
    assert "/config-error" in res.location


def test_policy_redirects_when_unconfigured(unconfigured_test_client):
    """Test that /policy redirects to config error when unconfigured."""
    res = unconfigured_test_client.get("/policy")
    assert res.status_code == 302
    assert "/config-error" in res.location

def test_static_configuration_visible_in_debug_mode(unconfigured_app):
    """Test that static configuration section is visible in debug mode."""
    unconfigured_app.config["DEBUG"] = True
    test_client = unconfigured_app.test_client()

    res = test_client.get("/en/server")
    assert res.status_code == 200
    assert b"Static configuration" in res.data


def test_static_configuration_hidden_in_production_mode(unconfigured_app):
    """Test that static configuration section is hidden in production mode."""
    unconfigured_app.config["DEBUG"] = False
    test_client = unconfigured_app.test_client()

    res = test_client.get("/en/server")
    assert res.status_code == 200
    assert b"Static configuration" not in res.data

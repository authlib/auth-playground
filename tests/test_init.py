from auth_playground.session import ServerConfig


def test_server_config_not_reloaded_when_already_in_g(app, test_client):
    """Test that server_config is not reloaded if already present in g."""
    from flask import g

    with app.app_context():
        existing_config = ServerConfig(issuer_url="https://existing.example.com")
        g.server_config = existing_config

        with test_client:
            res = test_client.get("/en/")

            assert res.status_code == 302


def test_root_redirects_to_language_based_on_accept_language(unconfigured_app):
    """Test root URL redirects based on Accept-Language header."""
    test_client = unconfigured_app.test_client()

    res = test_client.get("/", headers={"Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8"})
    assert res.status_code == 302
    assert res.location.startswith("/fr/")

    res = test_client.get("/", headers={"Accept-Language": "en-US,en;q=0.9"})
    assert res.status_code == 302
    assert res.location.startswith("/en/")

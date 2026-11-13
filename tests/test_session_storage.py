from flask.sessions import SecureCookieSession

from auth_playground.session import ServerConfig


def test_server_config_save_keeps_session_unmodified():
    """Test saving an unchanged server configuration does not modify the session."""
    config = ServerConfig(issuer_url="https://test.example.com")
    session = SecureCookieSession({"issuer_url": "https://test.example.com"})

    config.save(session)

    assert not session.modified


def test_server_config_save_updates_changed_values():
    """Test saving a server configuration stores the new values only."""
    config = ServerConfig(issuer_url="https://new.example.com")
    session = SecureCookieSession(
        {"issuer_url": "https://old.example.com", "server_type": "oidc"}
    )

    config.save(session)

    assert session.modified
    assert session["issuer_url"] == "https://new.example.com"
    assert "server_type" not in session


def test_read_only_request_does_not_store_the_session(test_client):
    """Test a request that changes nothing does not store the session again."""
    test_client.get("/en/request")
    app = test_client.application
    calls = []
    original = app.session_interface.save_session

    def save_session(app, session, response):
        calls.append(app.session_interface.should_set_storage(app, session))
        return original(app, session, response)

    app.session_interface.save_session = save_session
    test_client.get("/en/request")

    assert calls == [False]

def test_index_shows_signup_when_unauthenticated(test_client):
    """Test that unauthenticated users see signup and signin buttons."""
    res = test_client.get("/")
    assert res.status_code == 200
    assert b"Sign up" in res.data
    assert b"Sign in" in res.data


def test_registration_redirects_to_iam(iam_server, iam_client, test_client):
    """Test that registration redirects to IAM with prompt=create."""
    res = test_client.get("/register")
    assert res.status_code == 302
    assert "prompt=create" in res.location


def test_login_flow_fast(iam_server, iam_client, user, test_client):
    """Test login flow using iam_server helpers."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/login")
    assert res.status_code == 302

    res = iam_server.test_client.get(res.location)
    assert res.status_code == 302

    res = test_client.get(res.location)
    assert res.status_code == 302

    with test_client.session_transaction() as sess:
        assert "user" in sess
        assert sess["user"]["sub"] == user.user_name


def test_login_callback_stores_user_in_session(
    iam_server, iam_client, user, test_client
):
    """Test that login callback stores user info in session."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/login")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    with test_client.session_transaction() as sess:
        assert "user" in sess
        assert "token" in sess
        assert "id_token" in sess["token"]
        assert sess["user"]["sub"] == user.user_name


def test_consent_redirects_with_prompt(test_client):
    """Test that consent route includes prompt=consent parameter."""
    res = test_client.get("/consent")
    assert res.status_code == 302
    assert "prompt=consent" in res.location


def test_logout_redirects_to_end_session(iam_server, iam_client, user, test_client):
    """Test that logout redirects to end_session_endpoint."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/login")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    with test_client.session_transaction() as sess:
        assert "user" in sess
        assert "token" in sess

    res = test_client.get("/logout")
    assert res.status_code == 302
    assert "end" in res.location.lower()


def test_logout_callback_clears_session(test_client):
    """Test that logout callback clears user and token from session."""
    with test_client.session_transaction() as sess:
        sess["user"] = {"sub": "testuser"}
        sess["token"] = {"id_token": "test_token"}

    res = test_client.get("/logout_callback")
    assert res.status_code == 302

    with test_client.session_transaction() as sess:
        assert "user" not in sess
        assert "token" not in sess


def test_logout_local_clears_session_without_contacting_provider(test_client):
    """Test that local logout clears session without redirecting to provider."""
    with test_client.session_transaction() as sess:
        sess["user"] = {"sub": "testuser"}
        sess["token"] = {"id_token": "test_token", "access_token": "test_access"}

    res = test_client.get("/logout/local")
    assert res.status_code == 302
    assert res.location.endswith("/")
    assert "end" not in res.location.lower()

    with test_client.session_transaction() as sess:
        assert "user" not in sess
        assert "token" not in sess


def test_authenticated_user_can_access_index(iam_server, iam_client, user, test_client):
    """Test that authenticated users can access the index page."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/login")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    res = test_client.get("/")
    assert res.status_code == 200
    assert b"Auth Playground" in res.data


def test_login_with_prompt_login(iam_server, iam_client, user, test_client):
    """Test login with prompt=login when already logged in."""
    with test_client.session_transaction() as sess:
        sess["user"] = {"sub": user.user_name}

    res = test_client.get("/login")
    assert res.status_code == 302
    assert "prompt=login" in res.location


def test_tos_route(iam_server, iam_client, user, test_client):
    """Test that /tos route works and shows index template."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/login")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    res = test_client.get("/tos")
    assert res.status_code == 200
    assert b"Auth Playground" in res.data


def test_policy_route(iam_server, iam_client, user, test_client):
    """Test that /policy route works and shows index template."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/login")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    res = test_client.get("/policy")
    assert res.status_code == 200
    assert b"Auth Playground" in res.data


def test_refresh_token_form_displays_when_refresh_token_present(test_client):
    """Test that refresh token form is displayed when user has refresh token."""
    # Manually set a session with a refresh token
    with test_client.session_transaction() as sess:
        sess["token"] = {
            "access_token": "test_access_token",
            "refresh_token": "test_refresh_token",
            "id_token": "test_id_token",
        }
        sess["user"] = {"sub": "testuser"}

    res = test_client.get("/")
    assert res.status_code == 200
    assert b"Renew tokens" in res.data


def test_refresh_token_without_token_in_session(test_client):
    """Test that refresh fails when no refresh token in session."""
    with test_client.session_transaction() as sess:
        sess["token"] = {}

    res = test_client.post("/refresh", follow_redirects=True)
    assert res.status_code == 200
    assert b"No refresh token available" in res.data


def test_refresh_token_success(iam_server, iam_client, user, test_client):
    """Test successful token refresh."""
    iam_server.login(user)
    iam_server.consent(user, iam_client)

    res = test_client.get("/login")
    res = iam_server.test_client.get(res.location)
    res = test_client.get(res.location)

    with test_client.session_transaction() as sess:
        old_access_token = sess["token"]["access_token"]
        old_id_token = sess["token"].get("id_token")
        old_refresh_token = sess["token"].get("refresh_token")
        assert old_refresh_token is not None, "Refresh token should exist after login"

    res = test_client.post("/refresh", follow_redirects=True)

    assert res.status_code == 200
    assert b"Token successfully refreshed" in res.data
    assert b"error" not in res.data.lower() or b"successfully" in res.data.lower()

    with test_client.session_transaction() as sess:
        new_access_token = sess["token"]["access_token"]
        new_id_token = sess["token"].get("id_token")

        assert new_access_token != old_access_token, "Access token should be renewed"

        assert old_id_token is not None, "Old ID token should exist"
        assert new_id_token is not None, "ID token should still be present"

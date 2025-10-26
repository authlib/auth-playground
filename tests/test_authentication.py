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

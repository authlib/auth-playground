from auth_playground.session import ServerConfig


def test_server_config_display_name_oidc():
    """Test display name for OIDC server type."""
    config = ServerConfig(server_type="oidc")
    assert config.display_name == "OpenID Provider"


def test_server_config_display_name_oauth2():
    """Test display name for OAuth2 server type."""
    config = ServerConfig(server_type="oauth2")
    assert config.display_name == "OAuth 2.0 Authorization Server"


def test_server_config_specs_returns_none_without_metadata():
    """Test specs property returns None when metadata is missing."""
    config = ServerConfig()
    assert config.specs is None


def test_server_config_serialize_with_all_fields():
    """Test serialization with all fields populated."""
    config = ServerConfig(
        metadata={"issuer": "https://test.example.com"},
        issuer_url="https://test.example.com",
        server_type="oidc",
        registration_access_token="token123",
        registration_client_uri="https://test.example.com/client",
    )
    serialized = config.serialize()

    assert serialized["server_metadata"] == {"issuer": "https://test.example.com"}
    assert serialized["issuer_url"] == "https://test.example.com"
    assert serialized["server_type"] == "oidc"
    assert serialized["registration_access_token"] == "token123"
    assert serialized["registration_client_uri"] == "https://test.example.com/client"


def test_server_config_deserialize_empty_session():
    """Test deserialization returns None for empty session."""
    result = ServerConfig.deserialize({})
    assert result is None


def test_server_config_deserialize_with_metadata():
    """Test deserialization with metadata in session."""
    session_data = {
        "server_metadata": {"issuer": "https://test.example.com"},
        "issuer_url": "https://test.example.com",
        "server_type": "oidc",
    }
    config = ServerConfig.deserialize(session_data)

    assert config.metadata == {"issuer": "https://test.example.com"}
    assert config.issuer_url == "https://test.example.com"
    assert config.server_type == "oidc"


def test_server_config_save_removes_none_values():
    """Test save method removes None values from session."""
    config = ServerConfig(
        metadata={"issuer": "https://test.example.com"},
        issuer_url="https://test.example.com",
        server_type="oidc",
        registration_access_token=None,
        registration_client_uri=None,
    )
    session_data = {
        "registration_access_token": "old-token",
        "registration_client_uri": "old-uri",
    }

    config.save(session_data)

    assert "server_metadata" in session_data
    assert "issuer_url" in session_data
    assert "server_type" in session_data
    assert "registration_access_token" not in session_data
    assert "registration_client_uri" not in session_data


def test_server_config_clear_removes_all_fields():
    """Test clear method removes all ServerConfig fields from session."""
    session_data = {
        "server_metadata": {"issuer": "https://test.example.com"},
        "issuer_url": "https://test.example.com",
        "server_type": "oidc",
        "registration_access_token": "token",
        "registration_client_uri": "uri",
        "other_field": "should remain",
    }

    ServerConfig.clear(session_data)

    assert "server_metadata" not in session_data
    assert "issuer_url" not in session_data
    assert "server_type" not in session_data
    assert "registration_access_token" not in session_data
    assert "registration_client_uri" not in session_data
    assert "other_field" in session_data


def test_server_config_specs_property():
    """Test specs property returns ServerSpecs instance."""
    config = ServerConfig(
        metadata={
            "issuer": "https://test.example.com",
            "authorization_endpoint": "https://test.example.com/oauth/authorize",
        }
    )
    specs = config.specs

    assert specs is not None
    assert hasattr(specs, "_metadata")
    assert specs.oauth_2_authorization_framework is True

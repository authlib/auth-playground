from auth_playground.specs import ServerSpecs


class TestServerSpecs:
    """Test cases for ServerSpecs."""

    def test_minimal_oauth_server(self):
        """Test detection of minimal OAuth 2.0 server."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "response_types_supported": ["code"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_authorization_framework
        assert specs.oauth_2_bearer_token_usage
        assert specs.oauth_2_authorization_server_metadata
        assert not specs.oidc_core

    def test_openid_connect_server(self):
        """Test detection of OpenID Connect server."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks",
            "response_types_supported": ["code", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oidc_core
        assert specs.oidc_discovery
        assert specs.json_web_token
        assert specs.json_web_signature
        assert specs.json_web_key

    def test_pkce_support(self):
        """Test detection of PKCE support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "code_challenge_methods_supported": ["S256", "plain"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_pkce

    def test_par_support(self):
        """Test detection of PAR support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "pushed_authorization_request_endpoint": "https://example.com/par",
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_pushed_authorization_requests

    def test_token_management_endpoints(self):
        """Test detection of token management endpoints."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "revocation_endpoint": "https://example.com/revoke",
            "introspection_endpoint": "https://example.com/introspect",
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_token_revocation
        assert specs.oauth_2_token_introspection

    def test_dpop_support(self):
        """Test detection of DPoP support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "dpop_signing_alg_values_supported": ["ES256", "RS256"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_dpop

    def test_mtls_support(self):
        """Test detection of mTLS support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "tls_client_certificate_bound_access_tokens": True,
            "mtls_endpoint_aliases": {
                "token_endpoint": "https://mtls.example.com/token"
            },
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_mtls

    def test_rar_support(self):
        """Test detection of Rich Authorization Requests support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "authorization_details_types_supported": [
                "payment_initiation",
                "account_information",
            ],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_rich_authorization_requests

    def test_ciba_support(self):
        """Test detection of CIBA support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "backchannel_authentication_endpoint": "https://example.com/bc-authorize",
            "backchannel_token_delivery_modes_supported": ["poll", "ping"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oidc_ciba

    def test_device_flow_support(self):
        """Test detection of Device Authorization Grant support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "device_authorization_endpoint": "https://example.com/device",
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_device_authorization_grant

    def test_jarm_support(self):
        """Test detection of JARM support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "authorization_signing_alg_values_supported": ["RS256", "ES256"],
            "authorization_encryption_alg_values_supported": ["RSA-OAEP"],
            "authorization_encryption_enc_values_supported": ["A256GCM"],
            "response_modes_supported": ["query.jwt", "fragment.jwt", "form_post.jwt"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_jarm

        metadata_jwt_only = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "response_modes_supported": ["jwt"],
        }

        specs_jwt_only = ServerSpecs(metadata_jwt_only)

        assert specs_jwt_only.oauth_2_jarm

    def test_openid_logout_support(self):
        """Test detection of OpenID Connect logout mechanisms."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "end_session_endpoint": "https://example.com/logout",
            "frontchannel_logout_supported": True,
            "backchannel_logout_supported": True,
            "check_session_iframe": "https://example.com/check_session",
        }

        specs = ServerSpecs(metadata)

        assert specs.oidc_rpinitiated_logout
        assert specs.oidc_frontchannel_logout
        assert specs.oidc_backchannel_logout
        assert specs.oidc_session_management

    def test_jar_support(self):
        """Test detection of JWT-Secured Authorization Request support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "require_signed_request_object": True,
            "request_object_signing_alg_values_supported": ["RS256", "ES256"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_jwt_secured_authorization_request

    def test_issuer_identification_support(self):
        """Test detection of Authorization Server Issuer Identification."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "authorization_response_iss_parameter_supported": True,
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_authorization_server_issuer_identification

    def test_step_up_authentication(self):
        """Test detection of Step Up Authentication support."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "acr_values_supported": [
                "urn:mace:incommon:iap:silver",
                "urn:mace:incommon:iap:bronze",
            ],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_step_up_authentication_challenge

    def test_dynamic_registration_support(self):
        """Test detection of Dynamic Client Registration."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "registration_endpoint": "https://example.com/register",
            "jwks_uri": "https://example.com/jwks",
            "response_types_supported": ["code", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_dynamic_client_registration
        assert specs.oidc_registration

    def test_openid4vci_support(self):
        """Test detection of OpenID for Verifiable Credential Issuance."""
        metadata = {
            "credential_issuer": "https://example.com",
            "credential_endpoint": "https://example.com/credential",
            "authorization_servers": ["https://example.com"],
        }

        specs = ServerSpecs(metadata)

        assert specs.openid_for_verifiable_credential_issuance

    def test_openid4vp_support(self):
        """Test detection of OpenID for Verifiable Presentations."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "vp_formats_supported": ["jwt_vp", "ldp_vp"],
        }

        specs = ServerSpecs(metadata)

        assert specs.openid_for_verifiable_presentations

    def test_fapi_advanced_heuristic(self):
        """Test heuristic detection of FAPI Advanced profile."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "jwks_uri": "https://example.com/jwks",
            "pushed_authorization_request_endpoint": "https://example.com/par",
            "require_signed_request_object": True,
            "authorization_signing_alg_values_supported": ["PS256"],
            "response_modes_supported": ["jwt"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_pushed_authorization_requests
        assert specs.oauth_2_jwt_secured_authorization_request
        assert specs.oauth_2_jarm
        assert specs.fapi_1_advanced
        assert specs.fapi_1_baseline

    def test_form_post_response_mode(self):
        """Test detection of Form Post Response Mode."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "response_modes_supported": ["query", "fragment", "form_post"],
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_multiple_response_types
        assert specs.oauth_2_form_post_response_mode

    def test_to_dict(self):
        """Test conversion to dictionary."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "code_challenge_methods_supported": ["S256"],
        }

        specs = ServerSpecs(metadata)
        result = specs.to_dict()

        assert isinstance(result, dict)
        assert "oauth_2_pkce" in result
        assert result["oauth_2_pkce"] is True
        assert result["oauth_2_device_authorization_grant"] is False

    def test_get_supported_specs(self):
        """Test getting list of supported specs."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "code_challenge_methods_supported": ["S256"],
            "dpop_signing_alg_values_supported": ["ES256"],
        }

        specs = ServerSpecs(metadata)
        supported = specs.get_supported_specs()

        assert isinstance(supported, list)
        assert "oauth_2_pkce" in supported
        assert "oauth_2_dpop" in supported
        assert "oauth_2_device_authorization_grant" not in supported

    def test_get_spec_display_name(self):
        """Test getting human-readable spec names."""
        specs = ServerSpecs()

        assert "PKCE" in specs.get_spec_display_name("oauth_2_pkce")
        assert "OpenID Connect Core" in specs.get_spec_display_name("oidc_core")
        assert "DPoP" in specs.get_spec_display_name("oauth_2_dpop")

    def test_get_spec_url(self):
        """Test getting spec URLs."""
        specs = ServerSpecs()

        assert (
            specs.get_spec_url("oauth_2_pkce")
            == "https://datatracker.ietf.org/doc/html/rfc7636"
        )
        assert (
            specs.get_spec_url("oidc_core")
            == "https://openid.net/specs/openid-connect-core-1_0.html"
        )
        assert (
            specs.get_spec_url("oauth_2_dpop")
            == "https://datatracker.ietf.org/doc/html/rfc9449"
        )
        assert specs.get_spec_url("unknown_spec") == "#"

    def test_get_unsupported_specs(self):
        """Test getting list of unsupported specs."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "code_challenge_methods_supported": ["S256"],
        }

        specs = ServerSpecs(metadata)
        unsupported = specs.get_unsupported_specs()

        assert isinstance(unsupported, list)
        assert "oauth_2_device_authorization_grant" in unsupported
        assert "oauth_2_dpop" in unsupported
        assert "oauth_2_pkce" not in unsupported

    def test_get_unknown_specs(self):
        """Test getting list of unknown specs."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
        }

        specs = ServerSpecs(metadata)
        unknown = specs.get_unknown_specs()

        assert isinstance(unknown, list)
        assert "oauth_2_jwt_access_tokens" in unknown
        assert "oauth_2_security_best_current_practice" in unknown

    def test_empty_metadata(self):
        """Test detection with empty metadata."""
        metadata = {}

        specs = ServerSpecs(metadata)

        assert not specs.oauth_2_authorization_framework
        assert not specs.oidc_core

    def test_comprehensive_server(self):
        """Test detection on a comprehensive modern server with many features."""
        metadata = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/jwks",
            "registration_endpoint": "https://example.com/register",
            "revocation_endpoint": "https://example.com/revoke",
            "introspection_endpoint": "https://example.com/introspect",
            "device_authorization_endpoint": "https://example.com/device",
            "pushed_authorization_request_endpoint": "https://example.com/par",
            "end_session_endpoint": "https://example.com/logout",
            "response_types_supported": ["code", "id_token", "token id_token"],
            "response_modes_supported": ["query", "fragment", "form_post", "jwt"],
            "subject_types_supported": ["public", "pairwise"],
            "id_token_signing_alg_values_supported": ["RS256", "ES256"],
            "code_challenge_methods_supported": ["S256"],
            "grant_types_supported": [
                "authorization_code",
                "refresh_token",
                "urn:ietf:params:oauth:grant-type:device_code",
            ],
            "dpop_signing_alg_values_supported": ["ES256", "RS256"],
            "authorization_details_types_supported": ["payment_initiation"],
            "require_signed_request_object": True,
            "authorization_response_iss_parameter_supported": True,
            "acr_values_supported": ["urn:mace:incommon:iap:silver"],
            "frontchannel_logout_supported": True,
            "backchannel_logout_supported": True,
            "tls_client_certificate_bound_access_tokens": True,
        }

        specs = ServerSpecs(metadata)

        assert specs.oauth_2_authorization_framework
        assert specs.oidc_core
        assert specs.oauth_2_pkce
        assert specs.oauth_2_pushed_authorization_requests
        assert specs.oauth_2_jwt_secured_authorization_request
        assert specs.oauth_2_authorization_server_issuer_identification
        assert specs.oauth_2_step_up_authentication_challenge
        assert specs.oauth_2_dpop
        assert specs.oauth_2_mtls
        assert specs.oauth_2_token_revocation
        assert specs.oauth_2_token_introspection
        assert specs.oauth_2_device_authorization_grant
        assert specs.oauth_2_rich_authorization_requests
        assert specs.oidc_rpinitiated_logout
        assert specs.oidc_frontchannel_logout
        assert specs.oidc_backchannel_logout

        supported = specs.get_supported_specs()
        assert len(supported) >= 20

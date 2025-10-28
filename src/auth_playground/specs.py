class ServerSpecs:
    """Detects which OAuth 2.0 and OpenID Connect specifications a server implements."""

    def __init__(self, server_metadata: dict | None = None):
        """Initialize ServerSpecs with server metadata."""
        self._metadata = server_metadata or {}

    @property
    def oauth_2_authorization_framework(self) -> bool:
        """RFC 6749 - OAuth 2.0 Authorization Framework."""
        return "authorization_endpoint" in self._metadata

    @property
    def oauth_2_bearer_token_usage(self) -> bool:
        """RFC 6750 - OAuth 2.0 Bearer Token Usage."""
        return self.oauth_2_authorization_framework

    @property
    def oidc_core(self) -> bool:
        """OpenID Connect Core 1.0."""
        return all(
            key in self._metadata
            for key in [
                "issuer",
                "jwks_uri",
                "id_token_signing_alg_values_supported",
                "response_types_supported",
                "subject_types_supported",
            ]
        )

    @property
    def oidc_discovery(self) -> bool:
        """OpenID Connect Discovery 1.0."""
        return self.oidc_core

    @property
    def oauth_2_token_revocation(self) -> bool:
        """RFC 7009 - OAuth 2.0 Token Revocation."""
        return "revocation_endpoint" in self._metadata

    @property
    def oauth_2_token_introspection(self) -> bool:
        """RFC 7662 - OAuth 2.0 Token Introspection."""
        return "introspection_endpoint" in self._metadata

    @property
    def oauth_2_dynamic_client_registration(self) -> bool:
        """RFC 7591 - OAuth 2.0 Dynamic Client Registration."""
        return "registration_endpoint" in self._metadata

    @property
    def oauth_2_dynamic_client_registration_management(self) -> bool:
        """RFC 7592 - OAuth 2.0 Dynamic Client Registration Management."""
        return self.oauth_2_dynamic_client_registration

    @property
    def oidc_registration(self) -> bool:
        """OpenID Connect Dynamic Client Registration 1.0."""
        return self.oauth_2_dynamic_client_registration and self.oidc_core

    @property
    def oauth_2_pkce(self) -> bool:
        """RFC 7636 - Proof Key for Code Exchange (PKCE)."""
        return "code_challenge_methods_supported" in self._metadata

    @property
    def oauth_2_pushed_authorization_requests(self) -> bool:
        """RFC 9126 - OAuth 2.0 Pushed Authorization Requests (PAR)."""
        return "pushed_authorization_request_endpoint" in self._metadata

    @property
    def oauth_2_jwt_secured_authorization_request(self) -> bool:
        """RFC 9101 - JWT-Secured Authorization Request (JAR)."""
        return (
            "require_signed_request_object" in self._metadata
            or "request_object_signing_alg_values_supported" in self._metadata
        )

    @property
    def oauth_2_authorization_server_issuer_identification(self) -> bool:
        """RFC 9207 - OAuth 2.0 Authorization Server Issuer Identification."""
        return "authorization_response_iss_parameter_supported" in self._metadata

    @property
    def oauth_2_step_up_authentication_challenge(self) -> bool:
        """RFC 9470 - OAuth 2.0 Step Up Authentication Challenge Protocol."""
        return "acr_values_supported" in self._metadata

    @property
    def oauth_2_authorization_server_metadata(self) -> bool:
        """RFC 8414 - OAuth 2.0 Authorization Server Metadata."""
        return "issuer" in self._metadata

    @property
    def oauth_2_jwt_access_tokens(self) -> bool | None:
        """RFC 9068 - JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens."""
        return None

    @property
    def json_web_token(self) -> bool:
        """RFC 7519 - JSON Web Token (JWT)."""
        return self.oidc_core

    @property
    def json_web_signature(self) -> bool:
        """RFC 7515 - JSON Web Signature (JWS)."""
        return self.oidc_core

    @property
    def json_web_encryption(self) -> bool | None:
        """RFC 7516 - JSON Web Encryption (JWE)."""
        return None

    @property
    def json_web_key(self) -> bool:
        """RFC 7517 - JSON Web Key (JWK)."""
        return "jwks_uri" in self._metadata

    @property
    def json_web_algorithms(self) -> bool | None:
        """RFC 7518 - JSON Web Algorithms (JWA)."""
        return None

    @property
    def oauth_2_device_authorization_grant(self) -> bool:
        """RFC 8628 - OAuth 2.0 Device Authorization Grant."""
        return "device_authorization_endpoint" in self._metadata

    @property
    def oauth_2_token_exchange(self) -> bool | None:
        """RFC 8693 - OAuth 2.0 Token Exchange."""
        return None

    @property
    def oidc_ciba(self) -> bool:
        """OpenID Connect Client-Initiated Backchannel Authentication Flow."""
        return "backchannel_authentication_endpoint" in self._metadata

    @property
    def oauth_2_mtls(self) -> bool:
        """RFC 8705 - OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens."""
        return (
            "tls_client_certificate_bound_access_tokens" in self._metadata
            or "mtls_endpoint_aliases" in self._metadata
        )

    @property
    def oauth_2_dpop(self) -> bool:
        """RFC 9449 - OAuth 2.0 Demonstrating Proof of Possession (DPoP)."""
        return "dpop_signing_alg_values_supported" in self._metadata

    @property
    def oauth_2_rich_authorization_requests(self) -> bool:
        """RFC 9396 - OAuth 2.0 Rich Authorization Requests."""
        return "authorization_details_types_supported" in self._metadata

    @property
    def oauth_2_multiple_response_types(self) -> bool:
        """OAuth 2.0 Multiple Response Types."""
        return "response_modes_supported" in self._metadata

    @property
    def oauth_2_form_post_response_mode(self) -> bool:
        """OAuth 2.0 Form Post Response Mode."""
        response_modes = self._metadata.get("response_modes_supported", [])
        return "form_post" in response_modes

    @property
    def oauth_2_jarm(self) -> bool:
        """JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)."""
        response_modes = self._metadata.get("response_modes_supported", [])
        return "authorization_signing_alg_values_supported" in self._metadata or any(
            mode.endswith(".jwt") or mode == "jwt" for mode in response_modes
        )

    @property
    def oidc_session_management(self) -> bool:
        """OpenID Connect Session Management 1.0."""
        return "check_session_iframe" in self._metadata

    @property
    def oidc_frontchannel_logout(self) -> bool:
        """OpenID Connect Front-Channel Logout 1.0."""
        return "frontchannel_logout_supported" in self._metadata

    @property
    def oidc_backchannel_logout(self) -> bool:
        """OpenID Connect Back-Channel Logout 1.0."""
        return "backchannel_logout_supported" in self._metadata

    @property
    def oidc_rpinitiated_logout(self) -> bool:
        """OpenID Connect RP-Initiated Logout 1.0."""
        return "end_session_endpoint" in self._metadata

    @property
    def oidc_prompt_create(self) -> bool:
        """OpenID Connect Prompt Create 1.0."""
        prompt_values = self._metadata.get("prompt_values_supported", [])
        return "create" in prompt_values

    @property
    def fapi_1_baseline(self) -> bool:
        """Financial-grade API 1.0 - Part 1: Baseline."""
        if (
            self.oauth_2_pushed_authorization_requests
            and self.oauth_2_jwt_secured_authorization_request
            and self.oauth_2_jarm
        ):
            return True
        elif self.oauth_2_pkce and self.oidc_core:
            return True
        return False

    @property
    def fapi_1_advanced(self) -> bool:
        """Financial-grade API 1.0 - Part 2: Advanced."""
        return (
            self.oauth_2_pushed_authorization_requests
            and self.oauth_2_jwt_secured_authorization_request
            and self.oauth_2_jarm
        )

    @property
    def openid_for_verifiable_credential_issuance(self) -> bool:
        """OpenID for Verifiable Credential Issuance."""
        return (
            "credential_issuer" in self._metadata
            or "credential_endpoint" in self._metadata
        )

    @property
    def openid_for_verifiable_presentations(self) -> bool:
        """OpenID for Verifiable Presentations."""
        return "vp_formats_supported" in self._metadata

    @property
    def oauth_2_resource_indicators(self) -> bool:
        """RFC 8707 - Resource Indicators for OAuth 2.0."""
        return "resource_signing_alg_values_supported" in self._metadata or bool(
            self._metadata.get("resource")
        )

    @property
    def oauth_2_assertion_framework(self) -> bool | None:
        """RFC 7521 - Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants."""
        return None

    @property
    def oauth_2_saml_profile(self) -> bool | None:
        """RFC 7522 - Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0."""
        return None

    @property
    def oauth_2_jwt_profile(self) -> bool | None:
        """RFC 7523 - JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and Authorization Grants."""
        return None

    @property
    def jwt_proof_of_possession(self) -> bool | None:
        """RFC 7800 - Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)."""
        return None

    @property
    def jwt_best_current_practices(self) -> bool | None:
        """RFC 8725 - JSON Web Token Best Current Practices."""
        return None

    @property
    def oauth_2_security_best_current_practice(self) -> bool | None:
        """RFC 9700 - OAuth 2.0 Security Best Current Practice."""
        return None

    @property
    def jwk_thumbprint_uri(self) -> bool | None:
        """RFC 9278 - JWK Thumbprint URI."""
        return None

    @property
    def oauth_2_jwt_introspection_response(self) -> bool | None:
        """RFC 9701 - JWT Response for OAuth Token Introspection."""
        return None

    @property
    def ietf_urn_sub_namespace_oauth(self) -> bool | None:
        """RFC 6755 - An IETF URN Sub-Namespace for OAuth."""
        return None

    @property
    def oauth_2_threat_model_security_considerations(self) -> bool | None:
        """RFC 6819 - OAuth 2.0 Threat Model and Security Considerations."""
        return None

    @property
    def oauth_2_native_apps(self) -> bool:
        """RFC 8252 - OAuth 2.0 for Native Apps."""
        return self._metadata.get("require_pushed_authorization_requests", False) or (
            self.oauth_2_pkce and self.oauth_2_pushed_authorization_requests
        )

    def _get_all_property_names(self) -> list[str]:
        """Get a list of all property names."""
        return [
            name
            for name in dir(self)
            if isinstance(getattr(type(self), name, None), property)
        ]

    def to_dict(self) -> dict[str, bool | None]:
        """Convert the specs state to a dictionary."""
        return {
            field_name: getattr(self, field_name)
            for field_name in self._get_all_property_names()
        }

    def get_supported_specs(self) -> list[str]:
        """Get a list of supported specification names."""
        return [
            field_name
            for field_name, supported in self.to_dict().items()
            if supported is True
        ]

    def get_unsupported_specs(self) -> list[str]:
        """Get a list of unsupported specification names."""
        return [
            field_name
            for field_name, supported in self.to_dict().items()
            if supported is False
        ]

    def get_unknown_specs(self) -> list[str]:
        """Get a list of specifications with unknown support."""
        return [
            field_name
            for field_name, supported in self.to_dict().items()
            if supported is None
        ]

    def get_spec_url(self, field_name: str) -> str:
        """Get the URL for a specification."""
        urls = {
            "oauth_2_authorization_framework": "https://datatracker.ietf.org/doc/html/rfc6749",
            "oauth_2_bearer_token_usage": "https://datatracker.ietf.org/doc/html/rfc6750",
            "ietf_urn_sub_namespace_oauth": "https://datatracker.ietf.org/doc/html/rfc6755",
            "oauth_2_threat_model_security_considerations": "https://datatracker.ietf.org/doc/html/rfc6819",
            "oauth_2_token_revocation": "https://datatracker.ietf.org/doc/html/rfc7009",
            "json_web_signature": "https://datatracker.ietf.org/doc/html/rfc7515",
            "json_web_encryption": "https://datatracker.ietf.org/doc/html/rfc7516",
            "json_web_key": "https://datatracker.ietf.org/doc/html/rfc7517",
            "json_web_algorithms": "https://datatracker.ietf.org/doc/html/rfc7518",
            "json_web_token": "https://datatracker.ietf.org/doc/html/rfc7519",
            "oauth_2_assertion_framework": "https://datatracker.ietf.org/doc/html/rfc7521",
            "oauth_2_saml_profile": "https://datatracker.ietf.org/doc/html/rfc7522",
            "oauth_2_jwt_profile": "https://datatracker.ietf.org/doc/html/rfc7523",
            "oauth_2_dynamic_client_registration": "https://datatracker.ietf.org/doc/html/rfc7591",
            "oauth_2_dynamic_client_registration_management": "https://datatracker.ietf.org/doc/html/rfc7592",
            "oauth_2_pkce": "https://datatracker.ietf.org/doc/html/rfc7636",
            "oauth_2_token_introspection": "https://datatracker.ietf.org/doc/html/rfc7662",
            "jwt_proof_of_possession": "https://datatracker.ietf.org/doc/html/rfc7800",
            "oauth_2_native_apps": "https://datatracker.ietf.org/doc/html/rfc8252",
            "oauth_2_authorization_server_metadata": "https://datatracker.ietf.org/doc/html/rfc8414",
            "oauth_2_device_authorization_grant": "https://datatracker.ietf.org/doc/html/rfc8628",
            "oauth_2_token_exchange": "https://datatracker.ietf.org/doc/html/rfc8693",
            "oauth_2_mtls": "https://datatracker.ietf.org/doc/html/rfc8705",
            "oauth_2_resource_indicators": "https://datatracker.ietf.org/doc/html/rfc8707",
            "jwt_best_current_practices": "https://datatracker.ietf.org/doc/html/rfc8725",
            "oauth_2_jwt_access_tokens": "https://datatracker.ietf.org/doc/html/rfc9068",
            "oauth_2_jwt_secured_authorization_request": "https://datatracker.ietf.org/doc/html/rfc9101",
            "oauth_2_pushed_authorization_requests": "https://datatracker.ietf.org/doc/html/rfc9126",
            "oauth_2_authorization_server_issuer_identification": "https://datatracker.ietf.org/doc/html/rfc9207",
            "jwk_thumbprint_uri": "https://datatracker.ietf.org/doc/html/rfc9278",
            "oauth_2_rich_authorization_requests": "https://datatracker.ietf.org/doc/html/rfc9396",
            "oauth_2_dpop": "https://datatracker.ietf.org/doc/html/rfc9449",
            "oauth_2_step_up_authentication_challenge": "https://datatracker.ietf.org/doc/html/rfc9470",
            "oauth_2_security_best_current_practice": "https://datatracker.ietf.org/doc/html/rfc9700",
            "oauth_2_jwt_introspection_response": "https://datatracker.ietf.org/doc/html/rfc9701",
            "oidc_core": "https://openid.net/specs/openid-connect-core-1_0.html",
            "oidc_discovery": "https://openid.net/specs/openid-connect-discovery-1_0.html",
            "oidc_registration": "https://openid.net/specs/openid-connect-registration-1_0.html",
            "oidc_session_management": "https://openid.net/specs/openid-connect-session-1_0.html",
            "oidc_frontchannel_logout": "https://openid.net/specs/openid-connect-frontchannel-1_0.html",
            "oidc_backchannel_logout": "https://openid.net/specs/openid-connect-backchannel-1_0.html",
            "oidc_rpinitiated_logout": "https://openid.net/specs/openid-connect-rpinitiated-1_0.html",
            "oidc_prompt_create": "https://openid.net/specs/openid-connect-prompt-create-1_0.html",
            "oauth_2_multiple_response_types": "https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html",
            "oauth_2_form_post_response_mode": "https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html",
            "oauth_2_jarm": "https://openid.net/specs/oauth-v2-jarm.html",
            "oidc_ciba": "https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html",
            "fapi_1_baseline": "https://openid.net/specs/openid-financial-api-part-1-1_0.html",
            "fapi_1_advanced": "https://openid.net/specs/openid-financial-api-part-2-1_0.html",
            "openid_for_verifiable_credential_issuance": "https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html",
            "openid_for_verifiable_presentations": "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html",
        }
        return urls.get(field_name, "#")

    def get_spec_display_name(self, field_name: str) -> str:
        """Get a human-readable display name for a specification."""
        display_names = {
            "oauth_2_authorization_framework": "RFC 6749 - OAuth 2.0 Authorization Framework",
            "oauth_2_bearer_token_usage": "RFC 6750 - OAuth 2.0 Bearer Token Usage",
            "ietf_urn_sub_namespace_oauth": "RFC 6755 - IETF URN Sub-Namespace for OAuth",
            "oauth_2_threat_model_security_considerations": "RFC 6819 - OAuth 2.0 Threat Model and Security Considerations",
            "oauth_2_token_revocation": "RFC 7009 - OAuth 2.0 Token Revocation",
            "json_web_signature": "RFC 7515 - JSON Web Signature (JWS)",
            "json_web_encryption": "RFC 7516 - JSON Web Encryption (JWE)",
            "json_web_key": "RFC 7517 - JSON Web Key (JWK)",
            "json_web_algorithms": "RFC 7518 - JSON Web Algorithms (JWA)",
            "json_web_token": "RFC 7519 - JSON Web Token (JWT)",
            "oauth_2_assertion_framework": "RFC 7521 - Assertion Framework for OAuth 2.0",
            "oauth_2_saml_profile": "RFC 7522 - SAML 2.0 Profile for OAuth 2.0",
            "oauth_2_jwt_profile": "RFC 7523 - JWT Profile for OAuth 2.0",
            "oauth_2_dynamic_client_registration": "RFC 7591 - OAuth 2.0 Dynamic Client Registration",
            "oauth_2_dynamic_client_registration_management": "RFC 7592 - OAuth 2.0 Dynamic Client Registration Management",
            "oauth_2_pkce": "RFC 7636 - PKCE",
            "oauth_2_token_introspection": "RFC 7662 - OAuth 2.0 Token Introspection",
            "jwt_proof_of_possession": "RFC 7800 - Proof-of-Possession Key Semantics for JWTs",
            "oauth_2_native_apps": "RFC 8252 - OAuth 2.0 for Native Apps",
            "oauth_2_authorization_server_metadata": "RFC 8414 - OAuth 2.0 Authorization Server Metadata",
            "oauth_2_device_authorization_grant": "RFC 8628 - Device Authorization Grant",
            "oauth_2_token_exchange": "RFC 8693 - OAuth 2.0 Token Exchange",
            "oauth_2_mtls": "RFC 8705 - OAuth 2.0 Mutual-TLS",
            "oauth_2_resource_indicators": "RFC 8707 - Resource Indicators for OAuth 2.0",
            "jwt_best_current_practices": "RFC 8725 - JWT Best Current Practices",
            "oauth_2_jwt_access_tokens": "RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens",
            "oauth_2_jwt_secured_authorization_request": "RFC 9101 - JWT-Secured Authorization Request (JAR)",
            "oauth_2_pushed_authorization_requests": "RFC 9126 - Pushed Authorization Requests (PAR)",
            "oauth_2_authorization_server_issuer_identification": "RFC 9207 - Authorization Server Issuer Identification",
            "jwk_thumbprint_uri": "RFC 9278 - JWK Thumbprint URI",
            "oauth_2_rich_authorization_requests": "RFC 9396 - Rich Authorization Requests (RAR)",
            "oauth_2_dpop": "RFC 9449 - Demonstrating Proof of Possession (DPoP)",
            "oauth_2_step_up_authentication_challenge": "RFC 9470 - Step Up Authentication Challenge",
            "oauth_2_security_best_current_practice": "RFC 9700 - OAuth 2.0 Security Best Current Practice",
            "oauth_2_jwt_introspection_response": "RFC 9701 - JWT Response for OAuth Token Introspection",
            "oidc_core": "OpenID Connect Core 1.0",
            "oidc_discovery": "OpenID Connect Discovery 1.0",
            "oidc_registration": "OpenID Connect Dynamic Registration 1.0",
            "oidc_session_management": "OpenID Connect Session Management 1.0",
            "oidc_frontchannel_logout": "OpenID Connect Front-Channel Logout 1.0",
            "oidc_backchannel_logout": "OpenID Connect Back-Channel Logout 1.0",
            "oidc_rpinitiated_logout": "OpenID Connect RP-Initiated Logout 1.0",
            "oidc_prompt_create": "OpenID Connect Prompt Create 1.0",
            "oauth_2_multiple_response_types": "OAuth 2.0 Multiple Response Types",
            "oauth_2_form_post_response_mode": "OAuth 2.0 Form Post Response Mode",
            "oauth_2_jarm": "JWT Secured Authorization Response Mode (JARM)",
            "oidc_ciba": "OpenID Connect CIBA",
            "fapi_1_baseline": "FAPI 1.0 Baseline",
            "fapi_1_advanced": "FAPI 1.0 Advanced",
            "openid_for_verifiable_credential_issuance": "OpenID for Verifiable Credential Issuance",
            "openid_for_verifiable_presentations": "OpenID for Verifiable Presentations",
        }
        return display_names.get(field_name, field_name.replace("_", " ").title())

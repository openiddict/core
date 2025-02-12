/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

namespace OpenIddict.Abstractions;

public static class OpenIddictConstants
{
    public static class Algorithms
    {
        public const string EcdsaSha256 = "ES256";
        public const string EcdsaSha384 = "ES384";
        public const string EcdsaSha512 = "ES512";
        public const string HmacSha256 = "HS256";
        public const string HmacSha384 = "HS384";
        public const string HmacSha512 = "HS512";
        public const string RsaSha256 = "RS256";
        public const string RsaSha384 = "RS384";
        public const string RsaSha512 = "RS512";
        public const string RsaSsaPssSha256 = "PS256";
        public const string RsaSsaPssSha384 = "PS384";
        public const string RsaSsaPssSha512 = "PS512";
    }

    public static class ApplicationTypes
    {
        public const string Native = "native";
        public const string Web = "web";
    }

    public static class AuthenticationMethodReferences
    {
        public const string Face = "face";
        public const string Fingerprint = "fpt";
        public const string Geolocation = "geo";
        public const string HardwareKey = "hwk";
        public const string Iris = "iris";
        public const string KnowledgeBased = "kba";
        public const string MultiChannel = "mca";
        public const string MultiFactor = "mfa";
        public const string OneTimePassword = "otp";
        public const string Password = "pwd";
        public const string PersonalIdentificationNumber = "pin";
        public const string Retina = "retina";
        public const string RiskBased = "rba";
        public const string ShortMessageService = "sms";
        public const string SmartCard = "sc";
        public const string SoftwareKey = "swk";
        public const string Telephone = "tel";
        public const string UserPresence = "user";
        public const string Voiceprint = "vbm";
        public const string WindowsIntegratedAuthentication = "wia";
    }

    public static class AuthorizationTypes
    {
        public const string AdHoc = "ad-hoc";
        public const string Permanent = "permanent";
    }

    public static class Claims
    {
        public const string AccessTokenHash = "at_hash";
        public const string Active = "active";
        public const string Address = "address";
        public const string Audience = "aud";
        public const string AuthenticationContextReference = "acr";
        public const string AuthenticationMethodReference = "amr";
        public const string AuthenticationTime = "auth_time";
        public const string AuthorizationServer = "as";
        public const string AuthorizedParty = "azp";
        public const string Birthdate = "birthdate";
        public const string ClientId = "client_id";
        public const string CodeHash = "c_hash";
        public const string Country = "country";
        public const string Email = "email";
        public const string EmailVerified = "email_verified";
        public const string ExpiresAt = "exp";
        public const string FamilyName = "family_name";
        public const string Formatted = "formatted";
        public const string Gender = "gender";
        public const string GivenName = "given_name";
        public const string IssuedAt = "iat";
        public const string Issuer = "iss";
        public const string Locale = "locale";
        public const string Locality = "locality";
        public const string JwtId = "jti";
        public const string KeyId = "kid";
        public const string MiddleName = "middle_name";
        public const string Name = "name";
        public const string Nickname = "nickname";
        public const string Nonce = "nonce";
        public const string NotBefore = "nbf";
        public const string PhoneNumber = "phone_number";
        public const string PhoneNumberVerified = "phone_number_verified";
        public const string Picture = "picture";
        public const string PostalCode = "postal_code";
        public const string PreferredUsername = "preferred_username";
        public const string Profile = "profile";
        public const string Region = "region";
        public const string RequestForgeryProtection = "rfp";
        public const string Role = "role";
        public const string Scope = "scope";
        public const string StreetAddress = "street_address";
        public const string Subject = "sub";
        public const string TargetLinkUri = "target_link_uri";
        public const string TokenType = "token_type";
        public const string TokenUsage = "token_usage";
        public const string UpdatedAt = "updated_at";
        public const string Username = "username";
        public const string Website = "website";
        public const string Zoneinfo = "zoneinfo";

        public static class Prefixes
        {
            public const string Private = "oi_";
        }

        public static class Private
        {
            public const string AccessTokenLifetime = "oi_act_lft";
            public const string Audience = "oi_aud";
            public const string AuthorizationCodeLifetime = "oi_auc_lft";
            public const string AuthorizationId = "oi_au_id";
            public const string ClaimDestinationsMap = "oi_cl_dstn";
            public const string CodeChallenge = "oi_cd_chlg";
            public const string CodeChallengeMethod = "oi_cd_chlg_meth";
            public const string CodeVerifier = "oi_cd_vrf";
            public const string CreationDate = "oi_crt_dt";
            public const string DeviceCodeId = "oi_dvc_id";
            public const string DeviceCodeLifetime = "oi_dvc_lft";
            public const string EndpointType = "oi_ept_typ";
            public const string ExpirationDate = "oi_exp_dt";
            public const string GrantType = "oi_grt_typ";
            public const string HostProperties = "oi_hst_props";
            public const string IdentityTokenLifetime = "oi_idt_lft";
            public const string InstanceId = "oi_instc_id";
            public const string Issuer = "oi_iss";
            public const string Nonce = "oi_nce";
            public const string PostLogoutRedirectUri = "oi_pstlgt_reduri";
            public const string ProviderName = "oi_prvd_name";
            public const string Presenter = "oi_prst";
            public const string RedirectUri = "oi_reduri";
            public const string RefreshTokenLifetime = "oi_reft_lft";
            public const string RegistrationId = "oi_reg_id";
            public const string RequestParameters = "oi_req_prms";
            public const string RequestTokenLifetime = "oi_reqt_lft";
            public const string RequestTokenType = "oi_reqt_typ";
            public const string Resource = "oi_rsrc";
            public const string ResponseType = "oi_rsp_typ";
            public const string SigningAlgorithm = "oi_sign_alg";
            public const string Scope = "oi_scp";
            public const string StateTokenLifetime = "oi_stet_lft";
            public const string TokenId = "oi_tkn_id";
            public const string TokenType = "oi_tkn_typ";
            public const string UserCodeLifetime = "oi_usrc_lft";
        }
    }
 
    public static class ClaimRequestMembers
    {
        public const string Essential = "essential";
        public const string IdToken = "id_token";
        public const string UserInfo = "userinfo";
        public const string Value = "value";
        public const string Values = "values";
    }

    public static class ClientAssertionTypes
    {
        public const string JwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
        public const string Saml2Bearer = "urn:ietf:params:oauth:client-assertion-type:saml2-bearer";
    }

    public static class ClientAuthenticationMethods
    {
        public const string ClientSecretBasic = "client_secret_basic";
        public const string ClientSecretJwt = "client_secret_jwt";
        public const string ClientSecretPost = "client_secret_post";
        public const string None = "none";
        public const string PrivateKeyJwt = "private_key_jwt";
        public const string SelfSignedTlsClientAuth = "self_signed_tls_client_auth";
        public const string TlsClientAuth = "tls_client_auth";
    }

    public static class ClientTypes
    {
        public const string Confidential = "confidential";
        public const string Public = "public";
    }

    public static class CodeChallengeMethods
    {
        public const string Plain = "plain";
        public const string Sha256 = "S256";
    }

    public static class ConsentTypes
    {
        public const string Explicit = "explicit";
        public const string External = "external";
        public const string Implicit = "implicit";
        public const string Systematic = "systematic";
    }

    public static class Destinations
    {
        public const string AccessToken = "access_token";
        public const string IdentityToken = "id_token";
    }

    public static class Errors
    {
        public const string AccessDenied = "access_denied";
        public const string AccountSelectionRequired = "account_selection_required";
        public const string AuthorizationPending = "authorization_pending";
        public const string ConsentRequired = "consent_required";
        public const string ExpiredToken = "expired_token";
        public const string InsufficientAccess = "insufficient_access";
        public const string InsufficientScope = "insufficient_scope";
        public const string InteractionRequired = "interaction_required";
        public const string InvalidClient = "invalid_client";
        public const string InvalidGrant = "invalid_grant";
        public const string InvalidRequest = "invalid_request";
        public const string InvalidRequestObject = "invalid_request_object";
        public const string InvalidRequestUri = "invalid_request_uri";
        public const string InvalidScope = "invalid_scope";
        public const string InvalidToken = "invalid_token";
        public const string LoginRequired = "login_required";
        public const string MissingToken = "missing_token";
        public const string RegistrationNotSupported = "registration_not_supported";
        public const string RequestNotSupported = "request_not_supported";
        public const string RequestUriNotSupported = "request_uri_not_supported";
        public const string ServerError = "server_error";
        public const string SlowDown = "slow_down";
        public const string TemporarilyUnavailable = "temporarily_unavailable";
        public const string UnauthorizedClient = "unauthorized_client";
        public const string UnsupportedGrantType = "unsupported_grant_type";
        public const string UnsupportedResponseType = "unsupported_response_type";
        public const string UnsupportedTokenType = "unsupported_token_type";
    }

    public static class GrantTypes
    {
        public const string AuthorizationCode = "authorization_code";
        public const string ClientCredentials = "client_credentials";
        public const string DeviceCode = "urn:ietf:params:oauth:grant-type:device_code";
        public const string Implicit = "implicit";
        public const string Password = "password";
        public const string RefreshToken = "refresh_token";
    }

    public static class JsonWebTokenTypes
    {
        public const string AccessToken = "at+jwt";
        public const string Jwt = "JWT";

        public static class Prefixes
        {
            public const string Application = "application/";
        }

        public static class Private
        {
            public const string AuthorizationCode = "oi_auc+jwt";
            public const string DeviceCode = "oi_dvc+jwt";
            public const string RefreshToken = "oi_reft+jwt";
            public const string RequestToken = "oi_reqt+jwt";
            public const string StateToken = "oi_stet+jwt";
            public const string UserCode = "oi_usrc+jwt";
        }
    }

    public static class Metadata
    {
        public const string AcrValuesSupported = "acr_values_supported";
        public const string AuthorizationEndpoint = "authorization_endpoint";
        public const string AuthorizationResponseIssParameterSupported = "authorization_response_iss_parameter_supported";
        public const string ClaimsLocalesSupported = "claims_locales_supported";
        public const string ClaimsParameterSupported = "claims_parameter_supported";
        public const string ClaimsSupported = "claims_supported";
        public const string ClaimTypesSupported = "claim_types_supported";
        public const string CodeChallengeMethodsSupported = "code_challenge_methods_supported";
        public const string DeviceAuthorizationEndpoint = "device_authorization_endpoint";
        public const string DeviceAuthorizationEndpointAuthMethodsSupported = "device_authorization_endpoint_auth_methods_supported";
        public const string DisplayValuesSupported = "display_values_supported";
        public const string EndSessionEndpoint = "end_session_endpoint";
        public const string GrantTypesSupported = "grant_types_supported";
        public const string IdTokenEncryptionAlgValuesSupported = "id_token_encryption_alg_values_supported";
        public const string IdTokenEncryptionEncValuesSupported = "id_token_encryption_enc_values_supported";
        public const string IdTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported";
        public const string IntrospectionEndpoint = "introspection_endpoint";
        public const string IntrospectionEndpointAuthMethodsSupported = "introspection_endpoint_auth_methods_supported";
        public const string IntrospectionEndpointAuthSigningAlgValuesSupported = "introspection_endpoint_auth_signing_alg_values_supported";
        public const string Issuer = "issuer";
        public const string JwksUri = "jwks_uri";
        public const string MtlsEndpointAliases = "mtls_endpoint_aliases";
        public const string OpPolicyUri = "op_policy_uri";
        public const string OpTosUri = "op_tos_uri";
        public const string PromptValuesSupported = "prompt_values_supported";
        public const string PushedAuthorizationRequestEndpoint = "pushed_authorization_request_endpoint";
        public const string PushedAuthorizationRequestEndpointAuthMethodsSupported = "pushed_authorization_request_endpoint_auth_methods_supported";
        public const string RequestObjectEncryptionAlgValuesSupported = "request_object_encryption_alg_values_supported";
        public const string RequestObjectEncryptionEncValuesSupported = "request_object_encryption_enc_values_supported";
        public const string RequestObjectSigningAlgValuesSupported = "request_object_signing_alg_values_supported";
        public const string RequestParameterSupported = "request_parameter_supported";
        public const string RequestUriParameterSupported = "request_uri_parameter_supported";
        public const string RequirePushedAuthorizationRequests = "require_pushed_authorization_requests";
        public const string RequireRequestUriRegistration = "require_request_uri_registration";
        public const string ResponseModesSupported = "response_modes_supported";
        public const string ResponseTypesSupported = "response_types_supported";
        public const string RevocationEndpoint = "revocation_endpoint";
        public const string RevocationEndpointAuthMethodsSupported = "revocation_endpoint_auth_methods_supported";
        public const string RevocationEndpointAuthSigningAlgValuesSupported = "revocation_endpoint_auth_signing_alg_values_supported";
        public const string ScopesSupported = "scopes_supported";
        public const string ServiceDocumentation = "service_documentation";
        public const string SubjectTypesSupported = "subject_types_supported";
        public const string TlsClientCertificateBoundAccessTokens = "tls_client_certificate_bound_access_tokens";
        public const string TokenEndpoint = "token_endpoint";
        public const string TokenEndpointAuthMethodsSupported = "token_endpoint_auth_methods_supported";
        public const string TokenEndpointAuthSigningAlgValuesSupported = "token_endpoint_auth_signing_alg_values_supported";
        public const string UiLocalesSupported = "ui_locales_supported";
        public const string UserInfoEncryptionAlgValuesSupported = "userinfo_encryption_alg_values_supported";
        public const string UserInfoEncryptionEncValuesSupported = "userinfo_encryption_enc_values_supported";
        public const string UserInfoEndpoint = "userinfo_endpoint";
        public const string UserInfoSigningAlgValuesSupported = "userinfo_signing_alg_values_supported";
    }

    public static class Parameters
    {
        public const string AccessToken = "access_token";
        public const string Active = "active";
        public const string AcrValues = "acr_values";
        public const string Assertion = "assertion";
        public const string Audience = "audience";
        public const string Claims = "claims";
        public const string ClaimsLocales = "claims_locales";
        public const string ClientAssertion = "client_assertion";
        public const string ClientAssertionType = "client_assertion_type";
        public const string ClientId = "client_id";
        public const string ClientSecret = "client_secret";
        public const string Code = "code";
        public const string CodeChallenge = "code_challenge";
        public const string CodeChallengeMethod = "code_challenge_method";
        public const string CodeVerifier = "code_verifier";
        public const string DeviceCode = "device_code";
        public const string Display = "display";
        public const string Error = "error";
        public const string ErrorDescription = "error_description";
        public const string ErrorUri = "error_uri";
        public const string ExpiresIn = "expires_in";
        public const string GrantType = "grant_type";
        public const string IdentityProvider = "identity_provider";
        public const string IdToken = "id_token";
        public const string IdTokenHint = "id_token_hint";
        public const string Interval = "interval";
        public const string Iss = "iss";
        public const string LoginHint = "login_hint";
        public const string Keys = "keys";
        public const string MaxAge = "max_age";
        public const string Nonce = "nonce";
        public const string Password = "password";
        public const string PostLogoutRedirectUri = "post_logout_redirect_uri";
        public const string Prompt = "prompt";
        public const string Realm = "realm";
        public const string RedirectUri = "redirect_uri";
        public const string RefreshToken = "refresh_token";
        public const string Registration = "registration";
        public const string Request = "request";
        [Obsolete("This property is obsolete and will be removed in a future version.")]
        public const string RequestId = "request_id";
        public const string RequestUri = "request_uri";
        public const string Resource = "resource";
        public const string ResponseMode = "response_mode";
        public const string ResponseType = "response_type";
        public const string Scope = "scope";
        public const string State = "state";
        public const string Token = "token";
        public const string TokenType = "token_type";
        public const string TokenTypeHint = "token_type_hint";
        public const string UiLocales = "ui_locales";
        public const string UserCode = "user_code";
        public const string Username = "username";
        public const string VerificationUri = "verification_uri";
        public const string VerificationUriComplete = "verification_uri_complete";
    }

    public static class Permissions
    {
        public static class Endpoints
        {
            public const string Authorization = "ept:authorization";
            public const string DeviceAuthorization = "ept:device_authorization";
            public const string EndSession = "ept:end_session";
            public const string Introspection = "ept:introspection";
            public const string PushedAuthorization = "ept:pushed_authorization";
            public const string Revocation = "ept:revocation";
            public const string Token = "ept:token";
        }

        public static class GrantTypes
        {
            public const string AuthorizationCode = "gt:authorization_code";
            public const string ClientCredentials = "gt:client_credentials";
            public const string DeviceCode = "gt:urn:ietf:params:oauth:grant-type:device_code";
            public const string Implicit = "gt:implicit";
            public const string Password = "gt:password";
            public const string RefreshToken = "gt:refresh_token";
        }

        public static class Prefixes
        {
            public const string Endpoint = "ept:";
            public const string GrantType = "gt:";
            public const string ResponseType = "rst:";
            public const string Scope = "scp:";
        }

        public static class ResponseTypes
        {
            public const string Code = "rst:code";
            public const string CodeIdToken = "rst:code id_token";
            public const string CodeIdTokenToken = "rst:code id_token token";
            public const string CodeToken = "rst:code token";
            public const string IdToken = "rst:id_token";
            public const string IdTokenToken = "rst:id_token token";
            public const string None = "rst:none";
            public const string Token = "rst:token";
        }

        public static class Scopes
        {
            public const string Address = "scp:address";
            public const string Email = "scp:email";
            public const string Phone = "scp:phone";
            public const string Profile = "scp:profile";
            public const string Roles = "scp:roles";
        }
    }

    public static class PromptValues
    {
        public const string Consent = "consent";
        public const string Create = "create";
        public const string Login = "login";
        public const string None = "none";
        public const string SelectAccount = "select_account";
    }

    public static class Properties
    {
        public const string Destinations = ".destinations";
    }

    public static class RequestTokenTypes
    {
        public static class Private
        {
            public const string CachedAuthorizationRequest = "cached_authorization_request";
            public const string CachedEndSessionRequest = "cached_end_session_request";
            public const string PushedAuthorizationRequest = "pushed_authorization_request";
        }
    }

    public static class RequestUris
    {
        public static class Prefixes
        {
            public const string Generic = "urn:ietf:params:oauth:request_uri:";
        }
    }

    public static class Requirements
    {
        public static class Features
        {
            public const string ProofKeyForCodeExchange = "ft:pkce";
            public const string PushedAuthorizationRequests = "ft:par";
        }

        public static class Prefixes
        {
            public const string Feature = "ft:";
        }
    }

    public static class ResponseModes
    {
        public const string FormPost = "form_post";
        public const string Fragment = "fragment";
        public const string Query = "query";
    }

    public static class ResponseTypes
    {
        public const string Code = "code";
        public const string IdToken = "id_token";
        public const string None = "none";
        public const string Token = "token";
    }

    public static class Schemes
    {
        public const string Basic = "Basic";
        public const string Bearer = "Bearer";
    }

    public static class Scopes
    {
        public const string Address = "address";
        public const string Email = "email";
        public const string OfflineAccess = "offline_access";
        public const string OpenId = "openid";
        public const string Phone = "phone";
        public const string Profile = "profile";
        public const string Roles = "roles";
    }

    public static class Separators
    {
        public static readonly char[] Ampersand = ['&'];
        public static readonly char[] Comma = [','];
        public static readonly char[] Dash = ['-'];
        public static readonly char[] Dot = ['.'];
        public static readonly char[] DoubleQuote = ['"'];
        public static readonly char[] EqualsSign = ['='];
        public static readonly char[] Hash = ['#'];
        public static readonly char[] QuestionMark = ['?'];
        public static readonly char[] Semicolon = [';'];
        public static readonly char[] Space = [' '];
    }

    public static class Settings
    {
        public static class Prefixes
        {
            public const string TokenLifetime = "tkn_lft:";
        }

        public static class TokenLifetimes
        {
            public const string AccessToken = "tkn_lft:act";
            public const string AuthorizationCode = "tkn_lft:auc";
            public const string DeviceCode = "tkn_lft:dvc";
            public const string IdentityToken = "tkn_lft:idt";
            public const string RefreshToken = "tkn_lft:reft";
            public const string RequestToken = "tkn_lft:reqt";
            public const string UserCode = "tkn_lft:usrc";
        }
    }

    public static class Statuses
    {
        public const string Inactive = "inactive";
        public const string Redeemed = "redeemed";
        public const string Rejected = "rejected";
        public const string Revoked = "revoked";
        public const string Valid = "valid";
    }

    public static class SubjectTypes
    {
        public const string Pairwise = "pairwise";
        public const string Public = "public";
    }

    public static class TokenBindingMethods
    {
        public const string SelfSignedTlsClientCertificate = "self_signed_tls_client_certificate";
        public const string TlsClientCertificate = "tls_client_certificate";
    }

    public static class TokenFormats
    {
        public const string Jwt = "urn:ietf:params:oauth:token-type:jwt";
        public const string Saml1 = "urn:ietf:params:oauth:token-type:saml1";
        public const string Saml2 = "urn:ietf:params:oauth:token-type:saml2";

        public static class Private
        {
            public const string DataProtection = "urn:openiddict:params:oauth:token-type:dp";
        }
    }

    public static class TokenTypeHints
    {
        public const string AccessToken = "access_token";
        public const string AuthorizationCode = "authorization_code";
        public const string ClientAssertion = "client_assertion";
        public const string DeviceCode = "device_code";
        public const string IdToken = "id_token";
        public const string RefreshToken = "refresh_token";
        public const string StateToken = "state_token";
        public const string UserInfoToken = "userinfo_token";
        public const string UserCode = "user_code";

        public static class Private
        {
            public const string RequestToken = "request_token";
        }
    }

    public static class TokenTypes
    {
        public const string Bearer = "Bearer";
    }
}

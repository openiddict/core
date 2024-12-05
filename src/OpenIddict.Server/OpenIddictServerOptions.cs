/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

/// <summary>
/// Provides various settings needed to configure the OpenIddict server handler.
/// </summary>
public sealed class OpenIddictServerOptions
{
    /// <summary>
    /// Gets or sets the optional URI used to uniquely identify the authorization server.
    /// The URI must be absolute and may contain a path, but no query string or fragment part.
    /// </summary>
    public Uri? Issuer { get; set; }

    /// <summary>
    /// Gets the list of encryption credentials used by the OpenIddict server services.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// Note: the encryption credentials are not used to protect/unprotect tokens issued
    /// by ASP.NET Core Data Protection, that uses its own key ring, configured separately.
    /// </summary>
    /// <remarks>
    /// Note: OpenIddict automatically sorts the credentials based on the following algorithm:
    /// <list type="bullet">
    ///   <item><description>Symmetric keys are always preferred when they can be used for the operation (e.g token encryption).</description></item>
    ///   <item><description>X.509 keys are always preferred to non-X.509 asymmetric keys.</description></item>
    ///   <item><description>X.509 keys with the furthest expiration date are preferred.</description></item>
    ///   <item><description>X.509 keys whose backing certificate is not yet valid are never preferred.</description></item>
    /// </list>
    /// </remarks>
    public List<EncryptingCredentials> EncryptionCredentials { get; } = [];

    /// <summary>
    /// Gets the list of signing credentials used by the OpenIddict server services.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// Note: the signing credentials are not used to protect/unprotect tokens issued
    /// by ASP.NET Core Data Protection, that uses its own key ring, configured separately.
    /// </summary>
    /// <remarks>
    /// Note: OpenIddict automatically sorts the credentials based on the following algorithm:
    /// <list type="bullet">
    ///   <item><description>Symmetric keys are always preferred when they can be used for the operation (e.g token signing).</description></item>
    ///   <item><description>X.509 keys are always preferred to non-X.509 asymmetric keys.</description></item>
    ///   <item><description>X.509 keys with the furthest expiration date are preferred.</description></item>
    ///   <item><description>X.509 keys whose backing certificate is not yet valid are never preferred.</description></item>
    /// </list>n
    /// </remarks>
    public IOpenIddictCredentialList<SigningCredentials> SigningCredentials { get; } = new OpenIddictSigningOpenIddictCredentialList([], null);

    /// <summary>
    /// Gets the absolute and relative URIs associated to the authorization endpoint.
    /// </summary>
    public List<Uri> AuthorizationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the configuration endpoint.
    /// </summary>
    public List<Uri> ConfigurationEndpointUris { get; } =
    [
        new Uri(".well-known/openid-configuration", UriKind.Relative),
        new Uri(".well-known/oauth-authorization-server", UriKind.Relative)
    ];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the device authorization endpoint.
    /// </summary>
    public List<Uri> DeviceAuthorizationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the end session endpoint.
    /// </summary>
    public List<Uri> EndSessionEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the introspection endpoint.
    /// </summary>
    public List<Uri> IntrospectionEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the JSON Web Key Set endpoint.
    /// </summary>
    public List<Uri> JsonWebKeySetEndpointUris { get; } =
    [
        new Uri(".well-known/jwks", UriKind.Relative)
    ];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the revocation endpoint.
    /// </summary>
    public List<Uri> RevocationEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the token endpoint.
    /// </summary>
    public List<Uri> TokenEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the userinfo endpoint.
    /// </summary>
    public List<Uri> UserInfoEndpointUris { get; } = [];

    /// <summary>
    /// Gets the absolute and relative URIs associated to the end-user verification endpoint.
    /// </summary>
    public List<Uri> EndUserVerificationEndpointUris { get; } = [];

    /// <summary>
    /// Gets or sets the JWT handler used to protect and unprotect tokens.
    /// </summary>
    public JsonWebTokenHandler JsonWebTokenHandler { get; set; } = new()
    {
        SetDefaultTimesOnTokenCreation = false
    };

    /// <summary>
    /// Gets the token validation parameters used by the OpenIddict server services.
    /// </summary>
    public TokenValidationParameters TokenValidationParameters { get; } = new()
    {
        AuthenticationType = TokenValidationParameters.DefaultAuthenticationType,
        ClockSkew = TimeSpan.Zero,
        NameClaimType = OpenIddictConstants.Claims.Name,
        RoleClaimType = OpenIddictConstants.Claims.Role,
        // In previous versions of OpenIddict (1.x and 2.x), all the JWT tokens (access and identity tokens)
        // were issued with the generic "typ": "JWT" header. To prevent confused deputy and token substitution
        // attacks, a special "token_usage" claim was added to the JWT payload to convey the actual token type.
        // This validator overrides the default logic used by IdentityModel to resolve the type from this claim.
        TypeValidator = static (type, token, parameters) =>
        {
            // If available, try to resolve the actual type from the "token_usage" claim.
            if (((JsonWebToken) token).TryGetPayloadValue(OpenIddictConstants.Claims.TokenUsage, out string usage))
            {
                type = usage switch
                {
                    TokenTypeHints.AccessToken => JsonWebTokenTypes.AccessToken,
                    TokenTypeHints.IdToken     => JsonWebTokenTypes.Jwt,

                    _ => throw new NotSupportedException(SR.GetResourceString(SR.ID0269))
                };
            }

            // At this point, throw an exception if the type cannot be resolved from the "typ" header
            // (provided via the type delegate parameter) or inferred from the token_usage claim.
            if (string.IsNullOrEmpty(type))
            {
                throw new SecurityTokenInvalidTypeException(SR.GetResourceString(SR.ID0270));
            }

            // Note: unlike IdentityModel, this custom validator deliberately uses case-insensitive comparisons.
            if (parameters.ValidTypes is not null && parameters.ValidTypes.Any() &&
               !parameters.ValidTypes.Contains(type, StringComparer.OrdinalIgnoreCase))
            {
                throw new SecurityTokenInvalidTypeException(SR.GetResourceString(SR.ID0271))
                {
                    InvalidType = type
                };
            }

            return type;
        },
        // Note: audience and lifetime are manually validated by OpenIddict itself.
        ValidateAudience = false,
        ValidateLifetime = false,
    };

    /// <summary>
    /// Gets or sets the period of time authorization codes remain valid after being issued. The default value is 5 minutes.
    /// While not recommended, this property can be set to <see langword="null"/> to issue authorization codes that never expire.
    /// </summary>
    public TimeSpan? AuthorizationCodeLifetime { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets or sets the period of time access tokens remain valid after being issued. The default value is 1 hour.
    /// The client application is expected to refresh or acquire a new access token after the token has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue access tokens that never expire.
    /// </summary>
    public TimeSpan? AccessTokenLifetime { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// Gets or sets the period of time device codes remain valid after being issued. The default value is 10 minutes.
    /// The client application is expected to start a whole new authentication flow after the device code has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue device codes that never expire.
    /// Note: the same value should be chosen for both <see cref="UserCodeLifetime"/> and this property.
    /// </summary>
    /// <remarks>
    /// The expiration date of a device code is automatically extended when the user approves the
    /// authorization demand to give the client application enough time to redeem the device code.
    /// </remarks>
    public TimeSpan? DeviceCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Gets or sets the period of time identity tokens remain valid after being issued. The default value is 20 minutes.
    /// The client application is expected to refresh or acquire a new identity token after the token has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue identity tokens that never expire.
    /// </summary>
    public TimeSpan? IdentityTokenLifetime { get; set; } = TimeSpan.FromMinutes(20);

    /// <summary>
    /// Gets or sets the period of time refresh tokens remain valid after being issued. The default value is 14 days.
    /// The client application is expected to start a whole new authentication flow after the refresh token has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue refresh tokens that never expire.
    /// </summary>
    public TimeSpan? RefreshTokenLifetime { get; set; } = TimeSpan.FromDays(14);

    /// <summary>
    /// Gets or sets the period of time rolling refresh tokens marked as redeemed can still be
    /// used to make concurrent refresh token requests. The default value is 30 seconds.
    /// </summary>
    public TimeSpan? RefreshTokenReuseLeeway { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Gets the charset used by OpenIddict to generate random user codes.
    /// </summary>
    /// <remarks>
    /// Note: user codes are meant to be used by humans, who may have to type them manually.
    /// To ensure they remain easy enough to type even by users with non-Latin keyboards,
    /// user codes generated by OpenIddict only include ASCII digits by default.
    /// </remarks>
    public HashSet<string> UserCodeCharset { get; } = new(StringComparer.Ordinal)
    {
        "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"
    };

    /// <summary>
    /// Gets or sets the format string used by OpenIddict to display user codes. While not recommended,
    /// a <see langword="null"/> value can be used to disable the user code formatting logic.
    /// </summary>
    /// <remarks>
    /// If no value is explicitly set, a default format using dash separators
    /// is used to make user codes easier to read by the end users.
    /// </remarks>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public string? UserCodeDisplayFormat { get; set; }

    /// <summary>
    /// Gets or sets the length of the user codes generated by OpenIddict (by default, 12 characters).
    /// </summary>
    public int UserCodeLength { get; set; } = 12;

    /// <summary>
    /// Gets or sets the period of time user codes remain valid after being issued. The default value is 10 minutes.
    /// The client application is expected to start a whole new authentication flow after the user code has expired.
    /// While not recommended, this property can be set to <see langword="null"/> to issue user codes that never expire.
    /// Note: the same value should be chosen for both <see cref="DeviceCodeLifetime"/> and this property.
    /// </summary>
    public TimeSpan? UserCodeLifetime { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Gets or sets a boolean indicating whether the degraded mode is enabled. When this degraded mode
    /// is enabled, all the security checks that depend on the OpenIddict core managers are disabled.
    /// This option MUST be enabled with extreme caution and custom handlers MUST be registered to
    /// properly validate OpenID Connect requests.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public bool EnableDegradedMode { get; set; }

    /// <summary>
    /// Gets the list of the handlers responsible for processing the OpenIddict server operations.
    /// Note: the list is automatically sorted based on the order assigned to each handler descriptor.
    /// As such, it MUST NOT be mutated after options initialization to preserve the exact order.
    /// </summary>
    public List<OpenIddictServerHandlerDescriptor> Handlers { get; } = new(OpenIddictServerHandlers.DefaultHandlers);

    /// <summary>
    /// Gets or sets a boolean determining whether client identification is optional.
    /// Enabling this option allows client applications to communicate with the token,
    /// introspection and revocation endpoints without having to send their client identifier.
    /// </summary>
    public bool AcceptAnonymousClients { get; set; }

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect claims supported by this application.
    /// </summary>
    public HashSet<string> Claims { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.Claims.Audience,
        OpenIddictConstants.Claims.ExpiresAt,
        OpenIddictConstants.Claims.IssuedAt,
        OpenIddictConstants.Claims.Issuer,
        OpenIddictConstants.Claims.Subject
    };

    /// <summary>
    /// Gets or sets a boolean indicating whether access token encryption should be disabled.
    /// Disabling encryption is NOT recommended and SHOULD only be done when issuing tokens
    /// to third-party resource servers/APIs you don't control and don't fully trust.
    /// Note: disabling encryption has no effect when using ASP.NET Core Data Protection.
    /// </summary>
    public bool DisableAccessTokenEncryption { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether authorization storage should be disabled.
    /// When disabled, ad-hoc authorizations are not created when an authorization code or
    /// refresh token is issued and can't be revoked to prevent associated tokens from being used.
    /// </summary>
    public bool DisableAuthorizationStorage { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether rolling tokens are disabled.
    /// When disabled, refresh tokens used in a token request are not marked
    /// as redeemed and can still be used until they expire. Disabling
    /// rolling refresh tokens is NOT recommended, for security reasons.
    /// </summary>
    public bool DisableRollingRefreshTokens { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether sliding expiration is disabled
    /// for refresh tokens. When this option is set to <see langword="true"/>,
    /// refresh tokens are issued with a fixed expiration date: when they expire,
    /// a complete authorization flow must be started to retrieve a new refresh token.
    /// </summary>
    public bool DisableSlidingRefreshTokenExpiration { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether token storage should be disabled.
    /// When disabled, no database entry is created for the tokens and codes
    /// returned by OpenIddict. Using this option is generally NOT recommended
    /// as it prevents the tokens and codes from being revoked (if needed).
    /// </summary>
    /// <remarks>
    /// Note: disabling token storage prevents the device authorization flow
    /// from being used and automatically turns sliding expiration off.
    /// </remarks>
    public bool DisableTokenStorage { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether scope validation is disabled.
    /// </summary>
    public bool DisableScopeValidation { get; set; }

    /// <summary>
    /// Gets the OAuth 2.0 client assertion types enabled for this application.
    /// </summary>
    public HashSet<string> ClientAssertionTypes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.ClientAssertionTypes.JwtBearer
    };

    /// <summary>
    /// Gets the OAuth 2.0 client authentication methods enabled for this application.
    /// </summary>
    public HashSet<string> ClientAuthenticationMethods { get; } = new(StringComparer.Ordinal)
    {
        // Note: client_secret_basic is deliberately not added here as it requires
        // a dedicated event handler (typically provided by the host integration)
        // to extract the client credentials from the standard Authorization header.
        //
        // Both the ASP.NET Core and OWIN hosts support the client_secret_basic
        // authentication method and automatically add it to this list at runtime.
        OpenIddictConstants.ClientAuthenticationMethods.ClientSecretPost,
        OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt
    };

    /// <summary>
    /// Gets the OAuth 2.0 code challenge methods enabled for this application.
    /// </summary>
    public HashSet<string> CodeChallengeMethods { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.CodeChallengeMethods.Plain,
        OpenIddictConstants.CodeChallengeMethods.Sha256
    };

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect flows enabled for this application.
    /// </summary>
    public HashSet<string> GrantTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the OpenID Connect prompt values enabled for this application.
    /// </summary>
    public HashSet<string> PromptValues { get; } = new(StringComparer.Ordinal)
    {
        // By default, only include the mandatory values defined in the core OpenID Connect specification.
        // See https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest for more information.
        OpenIddictConstants.PromptValues.Consent,
        OpenIddictConstants.PromptValues.Login,
        OpenIddictConstants.PromptValues.None,
        OpenIddictConstants.PromptValues.SelectAccount
    };

    /// <summary>
    /// Gets or sets a boolean indicating whether PKCE must be used by client applications
    /// when requesting an authorization code (e.g when using the code or hybrid flows).
    /// If this property is set to <see langword="true"/>, authorization requests that
    /// lack the code_challenge will be automatically rejected by OpenIddict.
    /// </summary>
    public bool RequireProofKeyForCodeExchange { get; set; }

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect response types enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> ResponseTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect response modes enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> ResponseModes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.ResponseModes.FormPost,
        OpenIddictConstants.ResponseModes.Fragment,
        OpenIddictConstants.ResponseModes.Query
    };

    /// <summary>
    /// Gets the OpenID Connect subject types enabled for this application.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Advanced)]
    public HashSet<string> SubjectTypes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.SubjectTypes.Public
    };

    /// <summary>
    /// Gets or sets a boolean indicating whether endpoint permissions should be ignored.
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </summary>
    public bool IgnoreEndpointPermissions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether grant type permissions should be ignored.
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </summary>
    public bool IgnoreGrantTypePermissions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether response type permissions should be ignored.
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </summary>
    public bool IgnoreResponseTypePermissions { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether scope permissions should be ignored.
    /// Setting this property to <see langword="true"/> is NOT recommended.
    /// </summary>
    public bool IgnoreScopePermissions { get; set; }

    /// <summary>
    /// Gets the OAuth 2.0/OpenID Connect scopes enabled for this application.
    /// </summary>
    public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.Scopes.OpenId
    };

    /// <summary>
    /// Gets or sets a boolean indicating whether reference access tokens should be used.
    /// When set to <see langword="true"/>, the token payload is stored in the database
    /// and a crypto-secure random identifier is returned to the client application.
    /// Enabling this option is useful when storing a very large number of claims
    /// in the tokens, but it is RECOMMENDED to enable column encryption
    /// in the database or use the ASP.NET Core Data Protection integration,
    /// that provides additional protection against token leakage.
    /// </summary>
    public bool UseReferenceAccessTokens { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether reference refresh tokens should be used.
    /// When set to <see langword="true"/>, the token payload is stored in the database
    /// and a crypto-secure random identifier is returned to the client application.
    /// Enabling this option is useful when storing a very large number of claims
    /// in the tokens, but it is RECOMMENDED to enable column encryption
    /// in the database or use the ASP.NET Core Data Protection integration,
    /// that provides additional protection against token leakage.
    /// </summary>
    public bool UseReferenceRefreshTokens { get; set; }

#if SUPPORTS_TIME_PROVIDER
    /// <summary>
    /// Gets or sets the time provider.
    /// </summary>
    public TimeProvider? TimeProvider { get; set; }
#endif
}

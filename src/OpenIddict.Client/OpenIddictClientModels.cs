/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;

namespace OpenIddict.Client;

/// <summary>
/// Exposes various records used to represent client requests and responses.
/// </summary>
public static class OpenIddictClientModels
{
    /// <summary>
    /// Represents an interactive authentication request.
    /// </summary>
    public sealed record class InteractiveAuthenticationRequest
    {
        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the nonce that was returned during the challenge operation.
        /// </summary>
        public required string Nonce { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }
    }

    /// <summary>
    /// Represents an interactive authentication result.
    /// </summary>
    public sealed record class InteractiveAuthenticationResult
    {
        /// <summary>
        /// Gets or sets the authorization code, if available.
        /// </summary>
        public required string? AuthorizationCode { get; init; }

        /// <summary>
        /// Gets or sets the authorization response.
        /// </summary>
        public required OpenIddictResponse AuthorizationResponse { get; init; }

        /// <summary>
        /// Gets or sets the backchannel access token, if available.
        /// </summary>
        public required string? BackchannelAccessToken { get; init; }

        /// <summary>
        /// Gets or sets the expiration date of the backchannel access token, if available.
        /// </summary>
        public required DateTimeOffset? BackchannelAccessTokenExpirationDate { get; init; }

        /// <summary>
        /// Gets or sets the backchannel identity token, if available.
        /// </summary>
        public required string? BackchannelIdentityToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the backchannel identity token, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? BackchannelIdentityTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets the frontchannel access token, if available.
        /// </summary>
        public required string? FrontchannelAccessToken { get; init; }

        /// <summary>
        /// Gets or sets the expiration date of the frontchannel access token, if available.
        /// </summary>
        public required DateTimeOffset? FrontchannelAccessTokenExpirationDate { get; init; }

        /// <summary>
        /// Gets or sets the frontchannel identity token, if available.
        /// </summary>
        public required string? FrontchannelIdentityToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the frontchannel identity token, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? FrontchannelIdentityTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets a merged principal containing all the claims
        /// extracted from the identity token and userinfo token principals.
        /// </summary>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the refresh token, if available.
        /// </summary>
        public required string? RefreshToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the state token, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? StateTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets the token response.
        /// </summary>
        public required OpenIddictResponse TokenResponse { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the userinfo token or response, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? UserInfoTokenPrincipal { get; init; }
    }

    /// <summary>
    /// Represents an interactive challenge request.
    /// </summary>
    public sealed record class InteractiveChallengeRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the authorization request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalAuthorizationRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the code challenge method that will be used for the authorization request.
        /// </summary>
        /// <remarks>
        /// Note: setting this property is generally not recommended, as OpenIddict automatically
        /// negotiates the best code challenge method supported by both the client and the server.
        /// </remarks>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public string? CodeChallengeMethod { get; init; }

        /// <summary>
        /// Gets or sets the grant type that will be used for the authorization request.
        /// If this property is set to a non-null value, the <see cref="ResponseType"/>
        /// property must also be explicitly set to a non-null value.
        /// </summary>
        /// <remarks>
        /// Note: setting this property is generally not recommended, as OpenIddict automatically
        /// negotiates the best grant type supported by both the client and the server.
        /// </remarks>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public string? GrantType { get; init; }

        /// <summary>
        /// Gets or sets the optional identity token hint that will
        /// be sent to the authorization server, if applicable.
        /// </summary>
        public string? IdentityTokenHint { get; set; }

        /// <summary>
        /// Gets or sets the optional login hint that will be sent to the authorization server, if applicable.
        /// </summary>
        public string? LoginHint { get; set; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets or sets the response mode that will be used for the authorization request.
        /// </summary>
        /// <remarks>
        /// Note: setting this property is generally not recommended, as OpenIddict automatically
        /// negotiates the best response mode supported by both the client and the server.
        /// </remarks>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public string? ResponseMode { get; init; }

        /// <summary>
        /// Gets or sets the response type that will be used for the authorization request.
        /// If this property is set to a non-null value, the <see cref="GrantType"/>
        /// property must also be explicitly set to a non-null value.
        /// </summary>
        /// <remarks>
        /// Note: setting this property is generally not recommended, as OpenIddict automatically
        /// negotiates the best response type supported by both the client and the server.
        /// </remarks>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public string? ResponseType { get; init; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents an interactive challenge result.
    /// </summary>
    public sealed record class InteractiveChallengeResult
    {
        /// <summary>
        /// Gets or sets the nonce that is used as a unique identifier for the challenge operation.
        /// </summary>
        public required string Nonce { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }
    }

    /// <summary>
    /// Represents an interactive sign-out request.
    /// </summary>
    public sealed record class InteractiveSignOutRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the end session request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalEndSessionRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the optional identity token hint that will
        /// be sent to the authorization server, if applicable.
        /// </summary>
        public string? IdentityTokenHint { get; set; }

        /// <summary>
        /// Gets or sets the optional login hint that will be sent to the authorization server, if applicable.
        /// </summary>
        public string? LoginHint { get; set; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents an interactive sign-out result.
    /// </summary>
    public sealed record class InteractiveSignOutResult
    {
        /// <summary>
        /// Gets or sets the nonce that is used as a unique identifier for the sign-out operation.
        /// </summary>
        public required string Nonce { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }
    }

    /// <summary>
    /// Represents a client credentials authentication request.
    /// </summary>
    public sealed record class ClientCredentialsAuthenticationRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the token request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalTokenRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents a client credentials authentication result.
    /// </summary>
    public sealed record class ClientCredentialsAuthenticationResult
    {
        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public required string AccessToken { get; init; }

        /// <summary>
        /// Gets or sets the expiration date of the access token, if available.
        /// </summary>
        public required DateTimeOffset? AccessTokenExpirationDate { get; init; }

        /// <summary>
        /// Gets or sets the identity token, if available.
        /// </summary>
        /// <remarks>
        /// Note: this property is generally not set, unless when dealing with an identity
        /// provider that returns an identity token for the client credentials grant.
        /// </remarks>
        public required string? IdentityToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the identity token, if available.
        /// </summary>
        /// <remarks>
        /// Note: this property is generally not set, unless when dealing with an identity
        /// provider that returns an identity token for the client credentials grant.
        /// </remarks>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? IdentityTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets a merged principal containing all the claims
        /// extracted from the identity token and userinfo token principals.
        /// </summary>
        /// <remarks>
        /// Note: in most cases, an empty principal will be returned, unless the authorization server
        /// supports returning a non-standard identity token for the client credentials grant.
        /// </remarks>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the refresh token, if available.
        /// </summary>
        public required string? RefreshToken { get; init; }

        /// <summary>
        /// Gets or sets the token response.
        /// </summary>
        public required OpenIddictResponse TokenResponse { get; init; }

        /// <summary>
        /// Gets or sets the userinfo token, if available.
        /// </summary>
        /// <remarks>
        /// Note: this property is generally not set, unless when dealing with non-standard providers.
        /// </remarks>
        public required string? UserInfoToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the userinfo token or response, if available.
        /// </summary>
        /// <remarks>
        /// Note: this property is generally not set, unless when dealing with non-standard providers.
        /// </remarks>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? UserInfoTokenPrincipal { get; init; }
    }

    /// <summary>
    /// Represents a custom grant authentication request.
    /// </summary>
    public sealed record class CustomGrantAuthenticationRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the token request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalTokenRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets a boolean indicating whether userinfo should be disabled.
        /// </summary>
        public bool DisableUserInfo { get; set; }

        /// <summary>
        /// Gets or sets the custom grant type that will be used for the authentication request.
        /// </summary>
        public required string GrantType { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents a custom grant authentication result.
    /// </summary>
    public sealed record class CustomGrantAuthenticationResult
    {
        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public required string AccessToken { get; init; }

        /// <summary>
        /// Gets or sets the expiration date of the access token, if available.
        /// </summary>
        public required DateTimeOffset? AccessTokenExpirationDate { get; init; }

        /// <summary>
        /// Gets or sets the identity token, if available.
        /// </summary>
        public required string? IdentityToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the identity token, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? IdentityTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets a merged principal containing all the claims
        /// extracted from the identity token and userinfo token principals.
        /// </summary>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the refresh token, if available.
        /// </summary>
        public required string? RefreshToken { get; init; }

        /// <summary>
        /// Gets or sets the token response.
        /// </summary>
        public required OpenIddictResponse TokenResponse { get; init; }

        /// <summary>
        /// Gets or sets the userinfo token, if available.
        /// </summary>
        public required string? UserInfoToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the userinfo token or response, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? UserInfoTokenPrincipal { get; init; }
    }

    /// <summary>
    /// Represents a device authentication request.
    /// </summary>
    public sealed record class DeviceAuthenticationRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the token request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalTokenRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the device code that will be sent to the authorization server.
        /// </summary>
        public required string DeviceCode { get; init; }

        /// <summary>
        /// Gets or sets a boolean indicating whether userinfo should be disabled.
        /// </summary>
        public bool DisableUserInfo { get; set; }

        /// <summary>
        /// Gets or sets the maximum duration during which token requests will be sent
        /// (typically, the same value as the "expires_in" parameter returned by the
        /// authorization server during the challenge phase or a lower value).
        /// </summary>
        public required TimeSpan Timeout { get; init; }

        /// <summary>
        /// Gets or sets the interval at which token requests will be sent (typically, the same
        /// value as the one returned by the authorization server during the challenge phase).
        /// </summary>
        public required TimeSpan Interval { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents a device authentication result.
    /// </summary>
    public sealed record class DeviceAuthenticationResult
    {
        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public required string AccessToken { get; init; }

        /// <summary>
        /// Gets or sets the expiration date of the access token, if available.
        /// </summary>
        public required DateTimeOffset? AccessTokenExpirationDate { get; init; }

        /// <summary>
        /// Gets or sets the identity token, if available.
        /// </summary>
        public required string? IdentityToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the identity token, if available.
        /// </summary>
        /// 
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? IdentityTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets a merged principal containing all the claims
        /// extracted from the identity token and userinfo token principals.
        /// </summary>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the refresh token, if available.
        /// </summary>
        public required string? RefreshToken { get; init; }

        /// <summary>
        /// Gets or sets the token response.
        /// </summary>
        public required OpenIddictResponse TokenResponse { get; init; }

        /// <summary>
        /// Gets or sets the userinfo token, if available.
        /// </summary>
        public required string? UserInfoToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the userinfo token or response, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? UserInfoTokenPrincipal { get; init; }
    }

    /// <summary>
    /// Represents a device challenge request.
    /// </summary>
    public sealed record class DeviceChallengeRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the device authorization request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalDeviceAuthorizationRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents a device challenge result.
    /// </summary>
    public sealed record class DeviceChallengeResult
    {
        /// <summary>
        /// Gets or sets the device authorization response.
        /// </summary>
        public required OpenIddictResponse DeviceAuthorizationResponse { get; init; }

        /// <summary>
        /// Gets or sets the device code.
        /// </summary>
        public required string DeviceCode { get; init; }

        /// <summary>
        /// Gets or sets the remaining lifetime of the device and user codes.
        /// </summary>
        public required TimeSpan ExpiresIn { get; init; }

        /// <summary>
        /// Gets or sets the interval at which token requests should be sent.
        /// </summary>
        public required TimeSpan Interval { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the user code.
        /// </summary>
        public required string UserCode { get; init; }

        /// <summary>
        /// Gets or sets the verification URI.
        /// </summary>
        public required Uri VerificationUri { get; init; }

        /// <summary>
        /// Gets or sets the complete verification URI, if available.
        /// </summary>
        public Uri? VerificationUriComplete { get; init; }
    }

    /// <summary>
    /// Represents an introspection request.
    /// </summary>
    public sealed record class IntrospectionRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the introspection request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalIntrospectionRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the token that will be sent to the authorization server.
        /// </summary>
        public required string Token { get; init; }

        /// <summary>
        /// Gets the token type hint that will be sent to the authorization server.
        /// </summary>
        public string? TokenTypeHint { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents an introspection result.
    /// </summary>
    public sealed record class IntrospectionResult
    {
        /// <summary>
        /// Gets or sets a merged principal containing all the claims
        /// extracted from the identity token and userinfo token principals.
        /// </summary>
        /// <remarks>
        /// Note: in most cases, an empty principal will be returned, unless the authorization server
        /// supports returning a non-standard identity token for the client credentials grant.
        /// </remarks>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the introspection response.
        /// </summary>
        public required OpenIddictResponse IntrospectionResponse { get; init; }
    }

    /// <summary>
    /// Represents a resource owner password credentials authentication request.
    /// </summary>
    public sealed record class PasswordAuthenticationRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the token request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalTokenRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets a boolean indicating whether userinfo should be disabled.
        /// </summary>
        public bool DisableUserInfo { get; set; }

        /// <summary>
        /// Gets or sets the password that will be sent to the authorization server.
        /// </summary>
        public required string Password { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the username that will be sent to the authorization server.
        /// </summary>
        public required string Username { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents a resource owner password credentials authentication result.
    /// </summary>
    public sealed record class PasswordAuthenticationResult
    {
        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public required string AccessToken { get; init; }

        /// <summary>
        /// Gets or sets the expiration date of the access token, if available.
        /// </summary>
        public required DateTimeOffset? AccessTokenExpirationDate { get; init; }

        /// <summary>
        /// Gets or sets the identity token, if available.
        /// </summary>
        public required string? IdentityToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the identity token, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? IdentityTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets a merged principal containing all the claims
        /// extracted from the identity token and userinfo token principals.
        /// </summary>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the refresh token, if available.
        /// </summary>
        public required string? RefreshToken { get; init; }

        /// <summary>
        /// Gets or sets the token response.
        /// </summary>
        public required OpenIddictResponse TokenResponse { get; init; }

        /// <summary>
        /// Gets or sets the userinfo token, if available.
        /// </summary>
        public required string? UserInfoToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the userinfo token or response, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? UserInfoTokenPrincipal { get; init; }
    }

    /// <summary>
    /// Represents a refresh token authentication request.
    /// </summary>
    public sealed record class RefreshTokenAuthenticationRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the token request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalTokenRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets a boolean indicating whether userinfo should be disabled, which may be required
        /// when sending a refresh token that was acquired using a user-less flow (e.g client credentials).
        /// </summary>
        public bool DisableUserInfo { get; set; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server.
        /// </summary>
        public List<string>? Scopes { get; init; }

        /// <summary>
        /// Gets or sets the refresh token that will be sent to the authorization server.
        /// </summary>
        public required string RefreshToken { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents a refresh token authentication result.
    /// </summary>
    public sealed record class RefreshTokenAuthenticationResult
    {
        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public required string AccessToken { get; init; }

        /// <summary>
        /// Gets or sets the expiration date of the access token, if available.
        /// </summary>
        public required DateTimeOffset? AccessTokenExpirationDate { get; init; }

        /// <summary>
        /// Gets or sets the identity token, if available.
        /// </summary>
        public required string? IdentityToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the identity token, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? IdentityTokenPrincipal { get; init; }

        /// <summary>
        /// Gets or sets a merged principal containing all the claims
        /// extracted from the identity token and userinfo token principals.
        /// </summary>
        public required ClaimsPrincipal Principal { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the refresh token, if available.
        /// </summary>
        public required string? RefreshToken { get; init; }

        /// <summary>
        /// Gets or sets the token response.
        /// </summary>
        public required OpenIddictResponse TokenResponse { get; init; }

        /// <summary>
        /// Gets or sets the userinfo token, if available.
        /// </summary>
        public required string? UserInfoToken { get; init; }

        /// <summary>
        /// Gets or sets the principal extracted from the userinfo token or response, if available.
        /// </summary>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public required ClaimsPrincipal? UserInfoTokenPrincipal { get; init; }
    }

    /// <summary>
    /// Represents an revocation request.
    /// </summary>
    public sealed record class RevocationRequest
    {
        /// <summary>
        /// Gets or sets the parameters that will be added to the revocation request.
        /// </summary>
        public Dictionary<string, OpenIddictParameter>? AdditionalRevocationRequestParameters { get; init; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        public CancellationToken CancellationToken { get; init; }

        /// <summary>
        /// Gets or sets the application-specific properties that will be added to the context.
        /// </summary>
        public Dictionary<string, string?>? Properties { get; init; }

        /// <summary>
        /// Gets or sets the provider name used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations use the same provider name.
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public string? ProviderName { get; init; }

        /// <summary>
        /// Gets or sets the unique identifier of the client registration that will be used.
        /// </summary>
        public string? RegistrationId { get; init; }

        /// <summary>
        /// Gets the token that will be sent to the authorization server.
        /// </summary>
        public required string Token { get; init; }

        /// <summary>
        /// Gets the token type hint that will be sent to the authorization server.
        /// </summary>
        public string? TokenTypeHint { get; init; }

        /// <summary>
        /// Gets or sets the issuer used to resolve the client registration.
        /// </summary>
        /// <remarks>
        /// Note: if multiple client registrations point to the same issuer,
        /// the <see cref="RegistrationId"/> property must be explicitly set.
        /// </remarks>
        public Uri? Issuer { get; init; }
    }

    /// <summary>
    /// Represents an revocation result.
    /// </summary>
    public sealed record class RevocationResult
    {
        /// <summary>
        /// Gets or sets the application-specific properties that were present in the context.
        /// </summary>
        public required Dictionary<string, string?> Properties { get; init; }

        /// <summary>
        /// Gets or sets the revocation response.
        /// </summary>
        public required OpenIddictResponse RevocationResponse { get; init; }
    }
}

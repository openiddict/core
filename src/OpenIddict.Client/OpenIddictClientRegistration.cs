/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Security.Claims;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Client;

/// <summary>
/// Contains the properties used to configure a client/server link.
/// </summary>
[DebuggerDisplay("{Issuer,nq}")]
public sealed class OpenIddictClientRegistration
{
    /// <summary>
    /// Gets or sets the unique identifier assigned to the registration.
    /// </summary>
    public string? RegistrationId { get; set; }

    /// <summary>
    /// Gets or sets the client identifier assigned by the authorization server.
    /// </summary>
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the client secret assigned by the authorization server, if applicable.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets a boolean indicating whether pushed authorization requests are disabled.
    /// When pushed authorization requests are disabled, PAR is not used by the OpenIddict client,
    /// even if the remote authorization server exposes a pushed authorization endpoint. If the
    /// authorization server requires using PAR but this property is set to <see langword="null"/>,
    /// an exception is automatically thrown when starting an interactive authentication challenge.
    /// </summary>
    public bool DisablePushedAuthorizationRequests { get; set; }

    /// <summary>
    /// Gets or sets the URI of the redirection endpoint that will handle the callback.
    /// </summary>
    /// <remarks>
    /// Note: this value is automatically added to
    /// <see cref="OpenIddictClientOptions.RedirectionEndpointUris"/>.
    /// </remarks>
    public Uri? RedirectUri { get; set; }

    /// <summary>
    /// Gets or sets the URI of the post-logout redirection endpoint that will handle the callback.
    /// </summary>
    /// <remarks>
    /// Note: this value is automatically added to
    /// <see cref="OpenIddictClientOptions.PostLogoutRedirectionEndpointUris"/>.
    /// </remarks>
    public Uri? PostLogoutRedirectUri { get; set; }

    /// <summary>
    /// Gets the list of encryption credentials used to create tokens for this client.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// </summary>
    public List<EncryptingCredentials> EncryptionCredentials { get; } = [];

    /// <summary>
    /// Gets the list of signing credentials used to create tokens for this client.
    /// Multiple credentials can be added to support key rollover, but if X.509 keys
    /// are used, at least one of them must have a valid creation/expiration date.
    /// </summary>
    public List<SigningCredentials> SigningCredentials { get; } = [];

    /// <summary>
    /// Gets the client authentication methods allowed by the client instance.
    /// If no value is explicitly set, all the methods enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final client authentication method used in backchannel requests is chosen by OpenIddict based
    /// on the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> ClientAuthenticationMethods { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the code challenge methods allowed by the client instance.
    /// If no value is explicitly set, all the methods enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final code challenge method used in authorization requests is chosen by OpenIddict based
    /// on the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> CodeChallengeMethods { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the grant types allowed by the client instance.
    /// If no value is explicitly set, all the modes enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final grant type used in authorization requests is chosen by OpenIddict based on
    /// the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> GrantTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the response modes allowed by the client instance.
    /// If no value is explicitly set, all the modes enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final response method used in authorization requests is chosen by OpenIddict based on
    /// the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> ResponseModes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the response type combinations allowed by the client instance.
    /// If no value is explicitly set, all the types enabled in the client options can be used.
    /// </summary>
    /// <remarks>
    /// The final response type used in authorization requests is chosen by OpenIddict based on
    /// the client options, the server configuration and the values registered in this property.
    /// </remarks>
    public HashSet<string> ResponseTypes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets or sets the issuer that will be attached to the <see cref="Claim"/>
    /// instances created by the OpenIddict client stack for this registration.
    /// </summary>
    /// <remarks>
    /// Note: if this property is not explicitly set, the provider name (if set)
    /// or the issuer URI are automatically used as a fallback value.
    /// </remarks>
    public string? ClaimsIssuer { get; set; }

    /// <summary>
    /// Gets or sets the URI of the authorization server.
    /// </summary>
    public Uri? Issuer { get; set; }

    /// <summary>
    /// Gets or sets the provider display name.
    /// </summary>
    public string? ProviderDisplayName { get; set; }

    /// <summary>
    /// Gets or sets the provider name.
    /// </summary>
    /// <remarks>
    /// The provider name can be safely used as a stable public identifier.
    /// </remarks>
    public string? ProviderName { get; set; }

    /// <summary>
    /// Gets or sets the provider settings, if applicable.
    /// </summary>
    public dynamic? ProviderSettings { get; set; }

    /// <summary>
    /// Gets or sets the provider type, if applicable.
    /// </summary>
    /// <remarks>
    /// Note: when manually set, the specified value MUST match the type of an existing
    /// provider supported by the OpenIddict.Client.WebIntegration companion package.
    /// </remarks>
    public string? ProviderType { get; set; }

    /// <summary>
    /// Gets or sets the static server configuration, if applicable.
    /// </summary>
    public OpenIddictConfiguration? Configuration { get; set; }

    /// <summary>
    /// Gets or sets the configuration manager used to retrieve and cache the server configuration.
    /// </summary>
    public IConfigurationManager<OpenIddictConfiguration>? ConfigurationManager { get; set; }

    /// <summary>
    /// Gets or sets the URI of the configuration endpoint exposed by the server.
    /// When the URI is relative, <see cref="Issuer"/> must be set and absolute.
    /// </summary>
    public Uri? ConfigurationEndpoint { get; set; }

    /// <summary>
    /// Gets or sets the token validation parameters associated with the authorization server.
    /// </summary>
    public TokenValidationParameters TokenValidationParameters { get; } = new TokenValidationParameters
    {
        AuthenticationType = TokenValidationParameters.DefaultAuthenticationType,
        ClockSkew = TimeSpan.Zero,
        NameClaimType = Claims.Name,
        RoleClaimType = Claims.Role,
        // Note: audience and lifetime are manually validated by OpenIddict itself.
        ValidateAudience = false,
        ValidateLifetime = false
    };

    /// <summary>
    /// Gets the list of scopes sent by default as part of
    /// authorization requests and device authorization requests.
    /// </summary>
    public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

    /// <summary>
    /// Gets the bag used to store additional provider-specific properties.
    /// </summary>
    public Dictionary<string, object?> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);
}

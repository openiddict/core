/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;

namespace OpenIddict.Server;

/// <summary>
/// Contains the methods required to ensure that the OpenIddict server configuration is valid.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerConfiguration : IPostConfigureOptions<OpenIddictServerOptions>
{
    private readonly IServiceProvider _provider;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerConfiguration"/> class.
    /// </summary>
    /// <param name="provider">The service provider.</param>
    public OpenIddictServerConfiguration(IServiceProvider provider)
        => _provider = provider ?? throw new ArgumentNullException(nameof(provider));

    /// <inheritdoc/>
    public void PostConfigure(string? name, OpenIddictServerOptions options)
    {
        if (options is null)
        {
            throw new ArgumentNullException(nameof(options));
        }

#if SUPPORTS_TIME_PROVIDER
        options.TimeProvider ??= _provider.GetService<TimeProvider>() ?? TimeProvider.System;
#endif

        // Explicitly disable all the features that are implicitly excluded when the degraded mode is active.
        if (options.EnableDegradedMode)
        {
            options.DisableAuthorizationStorage = options.DisableTokenStorage = options.DisableRollingRefreshTokens = true;
            options.IgnoreEndpointPermissions = options.IgnoreGrantTypePermissions = true;
            options.IgnoreResponseTypePermissions = options.IgnoreScopePermissions = true;
            options.UseReferenceAccessTokens = options.UseReferenceRefreshTokens = false;
        }

        // Explicitly disable rolling refresh tokens when token storage is disabled.
        if (options.DisableTokenStorage)
        {
            options.DisableRollingRefreshTokens = true;
        }

        if (options.JsonWebTokenHandler is null)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0075));
        }

        // Ensure at least one flow has been enabled.
        if (options.GrantTypes.Count is 0 && options.ResponseTypes.Count is 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0076));
        }

        var uris = options.AuthorizationEndpointUris.Distinct()
            .Concat(options.ConfigurationEndpointUris.Distinct())
            .Concat(options.JsonWebKeySetEndpointUris.Distinct())
            .Concat(options.DeviceAuthorizationEndpointUris.Distinct())
            .Concat(options.IntrospectionEndpointUris.Distinct())
            .Concat(options.EndSessionEndpointUris.Distinct())
            .Concat(options.RevocationEndpointUris.Distinct())
            .Concat(options.TokenEndpointUris.Distinct())
            .Concat(options.UserInfoEndpointUris.Distinct())
            .Concat(options.EndUserVerificationEndpointUris.Distinct())
            .ToList();

        // Ensure endpoint URIs are unique across endpoints.
        if (uris.Count != uris.Distinct().Count())
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0285));
        }

        // Ensure the authorization endpoint has been enabled when
        // the authorization code or implicit grants are supported.
        if (options.AuthorizationEndpointUris.Count is 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                             options.GrantTypes.Contains(GrantTypes.Implicit)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0077));
        }

        // Ensure the device authorization endpoint has been enabled when the device grant is supported.
        if (options.DeviceAuthorizationEndpointUris.Count is 0 && options.GrantTypes.Contains(GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0078));
        }

        // Ensure the token endpoint has been enabled when the authorization code,
        // client credentials, device, password or refresh token grants are supported.
        if (options.TokenEndpointUris.Count is 0 && (options.GrantTypes.Contains(GrantTypes.AuthorizationCode) ||
                                                     options.GrantTypes.Contains(GrantTypes.ClientCredentials) ||
                                                     options.GrantTypes.Contains(GrantTypes.DeviceCode) ||
                                                     options.GrantTypes.Contains(GrantTypes.Password) ||
                                                     options.GrantTypes.Contains(GrantTypes.RefreshToken)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0079));
        }

        // Ensure the end-user verification endpoint has been enabled when the device grant is supported.
        if (options.EndUserVerificationEndpointUris.Count is 0 && options.GrantTypes.Contains(GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0080));
        }

        // Ensure the device grant is allowed when the device authorization endpoint is enabled.
        if (options.DeviceAuthorizationEndpointUris.Count > 0 && !options.GrantTypes.Contains(GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0084));
        }

        // Ensure the grant types/response types configuration is consistent.
        foreach (var type in options.ResponseTypes)
        {
            var types = type.Split(Separators.Space, StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);
            if (types.Contains(ResponseTypes.Code) && !options.GrantTypes.Contains(GrantTypes.AuthorizationCode))
            {
                throw new InvalidOperationException(SR.FormatID0281(ResponseTypes.Code));
            }

            if (types.Contains(ResponseTypes.IdToken) && !options.GrantTypes.Contains(GrantTypes.Implicit))
            {
                throw new InvalidOperationException(SR.FormatID0282(ResponseTypes.IdToken));
            }

            if (types.Contains(ResponseTypes.Token) && !options.GrantTypes.Contains(GrantTypes.Implicit))
            {
                throw new InvalidOperationException(SR.FormatID0282(ResponseTypes.Token));
            }
        }

        // Ensure at least one client authentication method is enabled (unless no non-interactive endpoint was enabled).
        if (options.ClientAuthenticationMethods.Count is 0 && (options.DeviceAuthorizationEndpointUris.Count        is not 0 ||
                                                               options.IntrospectionEndpointUris.Count is not 0 ||
                                                               options.RevocationEndpointUris.Count    is not 0 ||
                                                               options.TokenEndpointUris.Count         is not 0))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0419));
        }

        // Ensure the client authentication methods/client assertion types configuration is consistent.
        if (options.ClientAuthenticationMethods.Contains(ClientAuthenticationMethods.PrivateKeyJwt) &&
           !options.ClientAssertionTypes.Contains(ClientAssertionTypes.JwtBearer))
        {
            throw new InvalidOperationException(SR.FormatID0420(
                ClientAssertionTypes.JwtBearer, ClientAuthenticationMethods.PrivateKeyJwt));
        }

        if (options.ClientAuthenticationMethods.Contains(ClientAuthenticationMethods.ClientSecretJwt) &&
           !options.ClientAssertionTypes.Contains(ClientAssertionTypes.JwtBearer))
        {
            throw new InvalidOperationException(SR.FormatID0420(
                ClientAssertionTypes.JwtBearer, ClientAuthenticationMethods.ClientSecretJwt));
        }

        // Ensure at least one supported subject type is listed.
        if (options.SubjectTypes.Count is 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0421));
        }

        // Ensure reference tokens support was not enabled when token storage is disabled.
        if (options.DisableTokenStorage && (options.UseReferenceAccessTokens || options.UseReferenceRefreshTokens))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0083));
        }

        // Prevent the device authorization flow from being used if token storage is disabled, unless the degraded
        // mode has been enabled (in this case, additional checks will be enforced later to require custom handlers).
        if (options.DisableTokenStorage && !options.EnableDegradedMode && options.GrantTypes.Contains(GrantTypes.DeviceCode))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0367));
        }

        if (options.EncryptionCredentials.Count is 0)
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0085));
        }
        
        if (!options.SigningCredentials.Exists(static credentials => credentials.Key is AsymmetricSecurityKey))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0086));
        }

        var now = (
#if SUPPORTS_TIME_PROVIDER
                options.TimeProvider?.GetUtcNow().DateTime ??
#endif
                DateTimeOffset.UtcNow
            )
            .LocalDateTime;

        // If all the registered encryption credentials are backed by a X.509 certificate, at least one of them must be valid.
        if (options.EncryptionCredentials.TrueForAll(credentials => credentials.Key is X509SecurityKey x509SecurityKey &&
               (x509SecurityKey.Certificate.NotBefore > now || x509SecurityKey.Certificate.NotAfter < now)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0087));
        }

        // If all the registered signing credentials are backed by a X.509 certificate, at least one of them must be valid.
        if (options.SigningCredentials.TrueForAll(credentials => credentials.Key is X509SecurityKey x509SecurityKey &&
                                                                          (x509SecurityKey.Certificate.NotBefore > now || x509SecurityKey.Certificate.NotAfter < now)))
        {
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0088));
        }

        if (options.EnableDegradedMode)
        {
            // If the degraded mode was enabled, ensure custom validation handlers
            // have been registered for the endpoints that require manual validation.

            if (options.AuthorizationEndpointUris.Count is not 0 && !options.Handlers.Exists(static descriptor =>
                descriptor.ContextType == typeof(ValidateAuthorizationRequestContext) &&
                descriptor.Type == OpenIddictServerHandlerType.Custom &&
                descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0089));
            }

            if (options.DeviceAuthorizationEndpointUris.Count is not 0 && !options.Handlers.Exists(static descriptor =>
                (descriptor.ContextType == typeof(ValidateDeviceAuthorizationRequestContext) ||
                 descriptor.ContextType == typeof(ProcessAuthenticationContext)) &&
                descriptor.Type == OpenIddictServerHandlerType.Custom &&
                descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0090));
            }

            if (options.IntrospectionEndpointUris.Count is not 0 && !options.Handlers.Exists(static descriptor =>
                (descriptor.ContextType == typeof(ValidateIntrospectionRequestContext) ||
                 descriptor.ContextType == typeof(ProcessAuthenticationContext)) &&
                descriptor.Type == OpenIddictServerHandlerType.Custom &&
                descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0091));
            }

            if (options.EndSessionEndpointUris.Count is not 0 && !options.Handlers.Exists(static descriptor =>
                descriptor.ContextType == typeof(ValidateEndSessionRequestContext) &&
                descriptor.Type == OpenIddictServerHandlerType.Custom &&
                descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0092));
            }

            if (options.RevocationEndpointUris.Count is not 0 && !options.Handlers.Exists(static descriptor =>
                (descriptor.ContextType == typeof(ValidateRevocationRequestContext) ||
                 descriptor.ContextType == typeof(ProcessAuthenticationContext)) &&
                descriptor.Type == OpenIddictServerHandlerType.Custom &&
                descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0093));
            }

            if (options.TokenEndpointUris.Count is not 0 && !options.Handlers.Exists(static descriptor =>
                (descriptor.ContextType == typeof(ValidateTokenRequestContext) ||
                 descriptor.ContextType == typeof(ProcessAuthenticationContext)) &&
                descriptor.Type == OpenIddictServerHandlerType.Custom &&
                descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0094));
            }

            if (options.EndUserVerificationEndpointUris.Count is not 0 && !options.Handlers.Exists(static descriptor =>
                descriptor.ContextType == typeof(ValidateEndUserVerificationRequestContext) &&
                descriptor.Type == OpenIddictServerHandlerType.Custom &&
                descriptor.FilterTypes.All(type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0095));
            }

            // If the degraded mode was enabled, ensure custom validation/generation handlers
            // have been registered to deal with device/user codes validation and generation.

            if (options.GrantTypes.Contains(GrantTypes.DeviceCode))
            {
                if (!options.Handlers.Exists(static descriptor =>
                    descriptor.ContextType == typeof(ValidateTokenContext) &&
                    descriptor.Type is OpenIddictServerHandlerType.Custom &&
                    descriptor.FilterTypes.All(static type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0096));
                }

                if (!options.Handlers.Exists(static descriptor =>
                    descriptor.ContextType == typeof(GenerateTokenContext) &&
                    descriptor.Type is OpenIddictServerHandlerType.Custom &&
                    descriptor.FilterTypes.All(static type => !typeof(RequireDegradedModeDisabled).IsAssignableFrom(type))))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0097));
                }
            }
        }

        // If token storage was disabled, user codes will be returned as-is by OpenIddict instead of being
        // automatically converted to reference identifiers (in this case, custom event handlers must be
        // registered to manually store the token payload in a database or cache and return a user code
        // that can be used and entered by a human user in a web form). Since the default logic is not
        // going be used, disable the formatting logic by setting UserCodeDisplayFormat to null here.
        if (options.DisableTokenStorage)
        {
            options.UserCodeLength = 0;
            options.UserCodeCharset.Clear();
            options.UserCodeDisplayFormat = null;
        }

        else
        {
            if (options.UserCodeLength is < 6)
            {
                throw new InvalidOperationException(SR.FormatID0439(6));
            }

            if (options.UserCodeCharset.Count is < 9)
            {
                throw new InvalidOperationException(SR.FormatID0440(9));
            }

            if (options.UserCodeCharset.Count != options.UserCodeCharset.Distinct(StringComparer.Ordinal).Count())
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0436));
            }

            foreach (var character in options.UserCodeCharset)
            {
#if SUPPORTS_TEXT_ELEMENT_ENUMERATOR
                // On supported platforms, ensure each character added to the
                // charset represents exactly one grapheme cluster/text element.
                var enumerator = StringInfo.GetTextElementEnumerator(character);
                if (!enumerator.MoveNext() || enumerator.MoveNext())
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0437));
                }
#else
                // On unsupported platforms, prevent non-ASCII characters from being used.
                if (character.Any(static character => (uint) character > '\x007f'))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0438));
                }
#endif
            }

            if (string.IsNullOrEmpty(options.UserCodeDisplayFormat))
            {
                var builder = new StringBuilder();

                var count = options.UserCodeLength % 5 is 0 ? 5 :
                            options.UserCodeLength % 4 is 0 ? 4 :
                            options.UserCodeLength % 3 is 0 ? 3 :
                            options.UserCodeLength % 2 is 0 ? 2 : 1;

                for (var index = 0; index < options.UserCodeLength; index++)
                {
                    if (index is > 0 && index % count is 0)
                    {
                        builder.Append(Separators.Dash[0]);
                    }

                    builder.Append('{');
                    builder.Append(index);
                    builder.Append('}');
                }

                options.UserCodeDisplayFormat = builder.ToString();
            }

            if (options.UserCodeCharset.Contains("-", StringComparer.Ordinal) &&
                options.UserCodeDisplayFormat.Any(static character => character is '-'))
            {
                throw new InvalidOperationException(SR.FormatID0441('-'));
            }
        }

        // Sort the handlers collection using the order associated with each handler.
        options.Handlers.Sort(static (left, right) => left.Order.CompareTo(right.Order));

        // Sort the encryption and signing credentials.
        options.EncryptionCredentials.Sort((left, right) => OpenIddictSecurityKeyExtensions.Compare(left.Key, right.Key, now));
        // options.SigningCredentials.Sort((left, right) => OpenIddictServerOptionsExtensions.Compare(left.Key, right.Key, now));

        // Generate a key identifier for the encryption/signing keys that don't already have one.
        foreach (var key in options.EncryptionCredentials.Select(credentials => credentials.Key)
            .Concat(options.SigningCredentials.Select(credentials => credentials.Key))
            .Where(key => string.IsNullOrEmpty(key.KeyId)))
        {
            key.KeyId = OpenIddictSecurityKeyExtensions.GetKeyIdentifier(key);
        }

        // Attach the signing credentials to the token validation parameters.
        options.TokenValidationParameters.IssuerSigningKeys =
            from credentials in options.SigningCredentials
            select credentials.Key;

        // Attach the encryption credentials to the token validation parameters.
        options.TokenValidationParameters.TokenDecryptionKeys =
            from credentials in options.EncryptionCredentials
            select credentials.Key;
    }
}

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Security.Claims;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;
using static OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants.Purposes;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;
using Schemes = OpenIddict.Server.DataProtection.OpenIddictServerDataProtectionConstants.Purposes.Schemes;

namespace OpenIddict.Server.DataProtection;

public static partial class OpenIddictServerDataProtectionHandlers
{
    public static class Protection
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Token validation:
             */
            ValidateDataProtectionToken.Descriptor,

            /*
             * Token generation:
             */
            OverrideGeneratedTokenFormat.Descriptor,
            GenerateDataProtectionToken.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for validating tokens generated using Data Protection.
        /// </summary>
        public sealed class ValidateDataProtectionToken : IOpenIddictServerHandler<ValidateTokenContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public ValidateDataProtectionToken(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options ?? throw new ArgumentNullException(nameof(options));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateTokenContext>()
                    .UseSingletonHandler<ValidateDataProtectionToken>()
                    .SetOrder(ValidateIdentityModelToken.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateTokenContext context)
            {
                // If a principal was already attached, don't overwrite it.
                if (context.Principal is not null)
                {
                    return default;
                }

                // If a specific token format is expected, return immediately if it doesn't match the expected value.
                if (context.TokenFormat is not null && context.TokenFormat is not TokenFormats.Private.DataProtection)
                {
                    return default;
                }

                // Note: ASP.NET Core Data Protection tokens created by the default implementation always start
                // with "CfDJ8", that corresponds to the base64 representation of the "09 F0 C9 F0" value used
                // by KeyRingBasedDataProtectionProvider as a Data Protection version identifier/magic header.
                //
                // Unless a custom provider implementation - that may use a different mechanism - has been
                // registered, return immediately if the token doesn't start with the expected magic header.
                //
                // See https://learn.microsoft.com/en-us/aspnet/core/security/data-protection/implementation/authenticated-encryption-details
                // for more information.
                if (!context.Token.StartsWith("CfDJ8", StringComparison.Ordinal) &&
                    string.Equals(_options.CurrentValue.DataProtectionProvider.GetType().FullName,
                        "Microsoft.AspNetCore.DataProtection.KeyManagement.KeyRingBasedDataProtectionProvider",
                        StringComparison.Ordinal))
                {
                    return default;
                }

                // Tokens generated using ASP.NET Core Data Protection are encrypted by symmetric keys
                // that are derived from both a master key resolved from the key ring and a specific value
                // known as "purpose" that helps ensure that Data Protection payloads can't be decrypted
                // without the correct "purpose" value, which is different for all types of tokens.
                //
                // While offering extensive protection at the cryptographic level, this prevents decrypting
                // unknown tokens without re-executing the entire decryption routine for each type of token
                // considered valid. To speed up this process when supporting multiple types is required,
                // the Data Protection integration relies on the "token_type_hint" parameter specified
                // by the client when it is available (e.g with introspection or revocation requests).

                var principal = context.ValidTokenTypes.Count switch
                {
                    // If no valid token type was set, all supported token types are allowed.
                    //
                    // Note: if a "token_type_hint" was specified by the client, use it to optimize
                    // the token decryption lookup but fall back to other types of tokens
                    // if the token can't be decrypted using the specified token type hint.
                    //
                    // In this case, common types (e.g access/refresh tokens) are checked first.
                    0 => context.TokenTypeHint switch
                    {
                        TokenTypeHints.AuthorizationCode =>
                            ValidateToken(TokenTypeHints.AuthorizationCode) ??
                            ValidateToken(TokenTypeHints.AccessToken)       ??
                            ValidateToken(TokenTypeHints.RefreshToken)      ??
                            ValidateToken(TokenTypeHints.DeviceCode)        ??
                            ValidateToken(TokenTypeHints.UserCode)          ??
                            ValidateToken(TokenTypeHints.Private.RequestToken),

                        TokenTypeHints.DeviceCode =>
                            ValidateToken(TokenTypeHints.DeviceCode)        ??
                            ValidateToken(TokenTypeHints.AccessToken)       ??
                            ValidateToken(TokenTypeHints.RefreshToken)      ??
                            ValidateToken(TokenTypeHints.AuthorizationCode) ??
                            ValidateToken(TokenTypeHints.UserCode)          ??
                            ValidateToken(TokenTypeHints.Private.RequestToken),

                        TokenTypeHints.RefreshToken =>
                            ValidateToken(TokenTypeHints.RefreshToken)      ??
                            ValidateToken(TokenTypeHints.AccessToken)       ??
                            ValidateToken(TokenTypeHints.AuthorizationCode) ??
                            ValidateToken(TokenTypeHints.DeviceCode)        ??
                            ValidateToken(TokenTypeHints.UserCode)          ??
                            ValidateToken(TokenTypeHints.Private.RequestToken),

                        TokenTypeHints.UserCode =>
                            ValidateToken(TokenTypeHints.UserCode)          ??
                            ValidateToken(TokenTypeHints.AccessToken)       ??
                            ValidateToken(TokenTypeHints.RefreshToken)      ??
                            ValidateToken(TokenTypeHints.AuthorizationCode) ??
                            ValidateToken(TokenTypeHints.DeviceCode)        ??
                            ValidateToken(TokenTypeHints.Private.RequestToken),

                        TokenTypeHints.Private.RequestToken =>
                            ValidateToken(TokenTypeHints.AccessToken)       ??
                            ValidateToken(TokenTypeHints.RefreshToken)      ??
                            ValidateToken(TokenTypeHints.AuthorizationCode) ??
                            ValidateToken(TokenTypeHints.DeviceCode)        ??
                            ValidateToken(TokenTypeHints.UserCode)          ??
                            ValidateToken(TokenTypeHints.Private.RequestToken),

                        _ =>
                            ValidateToken(TokenTypeHints.AccessToken)       ??
                            ValidateToken(TokenTypeHints.RefreshToken)      ??
                            ValidateToken(TokenTypeHints.AuthorizationCode) ??
                            ValidateToken(TokenTypeHints.DeviceCode)        ??
                            ValidateToken(TokenTypeHints.UserCode)          ??
                            ValidateToken(TokenTypeHints.Private.RequestToken),
                    },

                    // If a single valid token type was set, ignore the specified token type hint.
                    1 => context.ValidTokenTypes.ElementAt(0) switch
                    {
                        TokenTypeHints.AccessToken       => ValidateToken(TokenTypeHints.AccessToken),
                        TokenTypeHints.RefreshToken      => ValidateToken(TokenTypeHints.RefreshToken),
                        TokenTypeHints.AuthorizationCode => ValidateToken(TokenTypeHints.AuthorizationCode),
                        TokenTypeHints.DeviceCode        => ValidateToken(TokenTypeHints.DeviceCode),
                        TokenTypeHints.UserCode          => ValidateToken(TokenTypeHints.UserCode),

                        TokenTypeHints.Private.RequestToken => ValidateToken(TokenTypeHints.Private.RequestToken),

                        _ => null // The token type is not supported by the Data Protection integration (e.g identity tokens).
                    },

                    // If multiple valid types were set, use the specified token type hint
                    // and select the first non-null token that can be successfully decrypted.
                    _ => context.ValidTokenTypes.OrderBy(type => type switch
                    {
                        // If the token type hint corresponds to one of the valid types, test it first.
                        string value when value == context.TokenTypeHint => 0,

                        TokenTypeHints.AccessToken       => 1,
                        TokenTypeHints.RefreshToken      => 2,
                        TokenTypeHints.AuthorizationCode => 3,
                        TokenTypeHints.DeviceCode        => 4,
                        TokenTypeHints.UserCode          => 5,

                        TokenTypeHints.Private.RequestToken => 6,

                        _ => int.MaxValue
                    })
                    .Select(type => type switch
                    {
                        TokenTypeHints.AccessToken       => ValidateToken(TokenTypeHints.AccessToken),
                        TokenTypeHints.RefreshToken      => ValidateToken(TokenTypeHints.RefreshToken),
                        TokenTypeHints.AuthorizationCode => ValidateToken(TokenTypeHints.AuthorizationCode),
                        TokenTypeHints.DeviceCode        => ValidateToken(TokenTypeHints.DeviceCode),
                        TokenTypeHints.UserCode          => ValidateToken(TokenTypeHints.UserCode),

                        TokenTypeHints.Private.RequestToken => ValidateToken(TokenTypeHints.Private.RequestToken),

                        _ => null // The token type is not supported by the Data Protection integration (e.g identity tokens).
                    })
                    .Where(static principal => principal is not null)
                    .FirstOrDefault()
                };

                if (principal is null)
                {
                    context.Reject(
                        error: Errors.InvalidToken,
                        description: SR.GetResourceString(SR.ID2004),
                        uri: SR.FormatID8000(SR.ID2004));

                    return default;
                }

                context.Principal = principal;

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6152), context.Token, context.Principal.Claims);

                return default;

                ClaimsPrincipal? ValidateToken(string type)
                {
                    // Create a Data Protection protector using the provider registered in the options.
                    // 
                    // Note: reference tokens are encrypted using a different "purpose" string than non-reference tokens.
                    var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                        (type, context.IsReferenceToken) switch
                        {
                            (TokenTypeHints.AccessToken, true)
                                => [Handlers.Server, Formats.AccessToken, Features.ReferenceTokens, Schemes.Server],
                            (TokenTypeHints.AccessToken, false)
                                => [Handlers.Server, Formats.AccessToken, Schemes.Server],

                            (TokenTypeHints.AuthorizationCode, true)
                                => [Handlers.Server, Formats.AuthorizationCode, Features.ReferenceTokens, Schemes.Server],
                            (TokenTypeHints.AuthorizationCode, false)
                                => [Handlers.Server, Formats.AuthorizationCode, Schemes.Server],

                            (TokenTypeHints.DeviceCode, true)
                                => [Handlers.Server, Formats.DeviceCode, Features.ReferenceTokens, Schemes.Server],
                            (TokenTypeHints.DeviceCode, false)
                                => [Handlers.Server, Formats.DeviceCode, Schemes.Server],

                            (TokenTypeHints.RefreshToken, true)
                                => [Handlers.Server, Formats.RefreshToken, Features.ReferenceTokens, Schemes.Server],
                            (TokenTypeHints.RefreshToken, false)
                                => [Handlers.Server, Formats.RefreshToken, Schemes.Server],

                            (TokenTypeHints.UserCode, true)
                                => [Handlers.Server, Formats.UserCode, Features.ReferenceTokens, Schemes.Server],
                            (TokenTypeHints.UserCode, false)
                                => [Handlers.Server, Formats.UserCode, Schemes.Server],

                            (TokenTypeHints.Private.RequestToken, true)
                                => [Handlers.Server, Formats.RequestToken, Features.ReferenceTokens, Schemes.Server],
                            (TokenTypeHints.Private.RequestToken, false)
                                => [Handlers.Server, Formats.RequestToken, Schemes.Server],

                            _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                        });

                    try
                    {
                        using var buffer = new MemoryStream(protector.Unprotect(Base64UrlEncoder.DecodeBytes(context.Token)));
                        using var reader = new BinaryReader(buffer);

                        // Note: since the data format relies on a data protector using different "purposes" strings
                        // per token type, the token processed at this stage is guaranteed to be of the expected type.
                        return _options.CurrentValue.Formatter.ReadToken(reader)?.SetTokenType(type);
                    }

                    catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                    {
                        context.Logger.LogTrace(exception, SR.GetResourceString(SR.ID6153), context.Token);

                        return null;
                    }
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for overriding the default token format
        /// to generate ASP.NET Core Data Protection tokens instead of JSON Web Tokens.
        /// </summary>
        public sealed class OverrideGeneratedTokenFormat : IOpenIddictServerHandler<GenerateTokenContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public OverrideGeneratedTokenFormat(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options ?? throw new ArgumentNullException(nameof(options));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .UseSingletonHandler<OverrideGeneratedTokenFormat>()
                    .SetOrder(AttachSecurityCredentials.Descriptor.Order + 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(GenerateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // ASP.NET Core Data Protection can be used to format certain types of tokens in lieu
                // of the default token format (typically, JSON Web Token). By default, Data Protection
                // is automatically used for all the supported token types once the integration is enabled
                // but the default token format can be re-enabled in the options. Alternatively, the token
                // format can be overridden manually using a custom event handler registered after this one.

                context.TokenFormat = context.TokenType switch
                {
                    TokenTypeHints.AccessToken when !_options.CurrentValue.PreferDefaultAccessTokenFormat
                        => TokenFormats.Private.DataProtection,

                    TokenTypeHints.AuthorizationCode when !_options.CurrentValue.PreferDefaultAuthorizationCodeFormat
                        => TokenFormats.Private.DataProtection,

                    TokenTypeHints.DeviceCode when !_options.CurrentValue.PreferDefaultDeviceCodeFormat
                        => TokenFormats.Private.DataProtection,

                    TokenTypeHints.RefreshToken when !_options.CurrentValue.PreferDefaultRefreshTokenFormat
                        => TokenFormats.Private.DataProtection,

                    TokenTypeHints.UserCode when !_options.CurrentValue.PreferDefaultUserCodeFormat
                        => TokenFormats.Private.DataProtection,

                    TokenTypeHints.Private.RequestToken when !_options.CurrentValue.PreferDefaultRequestTokenFormat
                        => TokenFormats.Private.DataProtection,

                    _ => context.TokenFormat // Don't override the format if the token type is not supported.
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for generating a token using Data Protection.
        /// </summary>
        public sealed class GenerateDataProtectionToken : IOpenIddictServerHandler<GenerateTokenContext>
        {
            private readonly IOptionsMonitor<OpenIddictServerDataProtectionOptions> _options;

            public GenerateDataProtectionToken(IOptionsMonitor<OpenIddictServerDataProtectionOptions> options)
                => _options = options ?? throw new ArgumentNullException(nameof(options));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<GenerateTokenContext>()
                    .AddFilter<RequireDataProtectionTokenFormat>()
                    .UseSingletonHandler<GenerateDataProtectionToken>()
                    .SetOrder(GenerateIdentityModelToken.Descriptor.Order - 500)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(GenerateTokenContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If an access token was already attached by another handler, don't overwrite it.
                if (!string.IsNullOrEmpty(context.Token))
                {
                    return default;
                }

                // Create a Data Protection protector using the provider registered in the options.
                //
                // Note: reference tokens are encrypted using a different "purpose" string than non-reference tokens.
                var protector = _options.CurrentValue.DataProtectionProvider.CreateProtector(
                    (context.TokenType, context.IsReferenceToken) switch
                    {
                        (TokenTypeHints.AccessToken, true)
                            => [Handlers.Server, Formats.AccessToken, Features.ReferenceTokens, Schemes.Server],
                        (TokenTypeHints.AccessToken, false)
                            => [Handlers.Server, Formats.AccessToken, Schemes.Server],

                        (TokenTypeHints.AuthorizationCode, true)
                            => [Handlers.Server, Formats.AuthorizationCode, Features.ReferenceTokens, Schemes.Server],
                        (TokenTypeHints.AuthorizationCode, false)
                            => [Handlers.Server, Formats.AuthorizationCode, Schemes.Server],

                        (TokenTypeHints.DeviceCode, true)
                            => [Handlers.Server, Formats.DeviceCode, Features.ReferenceTokens, Schemes.Server],
                        (TokenTypeHints.DeviceCode, false)
                            => [Handlers.Server, Formats.DeviceCode, Schemes.Server],

                        (TokenTypeHints.RefreshToken, true)
                            => [Handlers.Server, Formats.RefreshToken, Features.ReferenceTokens, Schemes.Server],
                        (TokenTypeHints.RefreshToken, false)
                            => [Handlers.Server, Formats.RefreshToken, Schemes.Server],

                        (TokenTypeHints.UserCode, true)
                            => [Handlers.Server, Formats.UserCode, Features.ReferenceTokens, Schemes.Server],
                        (TokenTypeHints.UserCode, false)
                            => [Handlers.Server, Formats.UserCode, Schemes.Server],

                        (TokenTypeHints.Private.RequestToken, true)
                            => [Handlers.Server, Formats.RequestToken, Features.ReferenceTokens, Schemes.Server],
                        (TokenTypeHints.Private.RequestToken, false)
                            => [Handlers.Server, Formats.RequestToken, Schemes.Server],

                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0003))
                    });

                using var buffer = new MemoryStream();
                using var writer = new BinaryWriter(buffer);

                _options.CurrentValue.Formatter.WriteToken(writer, context.Principal);

                context.Token = Base64UrlEncoder.Encode(protector.Protect(buffer.ToArray()));

                context.Logger.LogTrace(SR.GetResourceString(SR.ID6016), context.TokenType,
                    context.Token, context.Principal.Claims);

                return default;
            }
        }
    }
}

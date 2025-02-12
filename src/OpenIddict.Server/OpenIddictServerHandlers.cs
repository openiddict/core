/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;

namespace OpenIddict.Server;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictServerHandlers
{
    public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
        /*
         * Top-level request processing:
         */
        InferEndpointType.Descriptor,

        /*
         * Authentication processing:
         */
        ValidateAuthenticationDemand.Descriptor,
        EvaluateValidatedTokens.Descriptor,
        ResolveValidatedTokens.Descriptor,
        ValidateRequiredTokens.Descriptor,
        ValidateClientId.Descriptor,
        ValidateClientType.Descriptor,
        ValidateClientSecret.Descriptor,
        ValidateClientAssertion.Descriptor,
        ValidateClientAssertionWellknownClaims.Descriptor,
        ValidateClientAssertionIssuer.Descriptor,
        ValidateClientAssertionAudience.Descriptor,
        ValidateRequestToken.Descriptor,
        ValidateRequestTokenType.Descriptor,
        ValidateAccessToken.Descriptor,
        ValidateAuthorizationCode.Descriptor,
        ValidateDeviceCode.Descriptor,
        ValidateGenericToken.Descriptor,
        ValidateIdentityToken.Descriptor,
        ValidateRefreshToken.Descriptor,
        ValidateUserCode.Descriptor,

        ResolveHostAuthenticationProperties.Descriptor,
        ReformatValidatedTokens.Descriptor,

        /*
         * Challenge processing:
         */
        ValidateChallengeDemand.Descriptor,
        AttachDefaultChallengeError.Descriptor,
        RejectDeviceCodeEntry.Descriptor,
        RejectUserCodeEntry.Descriptor,
        AttachCustomChallengeParameters.Descriptor,

        /*
         * Sign-in processing:
         */
        ValidateSignInDemand.Descriptor,
        RedeemTokenEntry.Descriptor,
        RestoreInternalClaims.Descriptor,
        AttachHostProperties.Descriptor,
        AttachDefaultScopes.Descriptor,
        AttachDefaultPresenters.Descriptor,
        InferResources.Descriptor,
        EvaluateGeneratedTokens.Descriptor,
        AttachAuthorization.Descriptor,

        PrepareAccessTokenPrincipal.Descriptor,
        PrepareAuthorizationCodePrincipal.Descriptor,
        PrepareDeviceCodePrincipal.Descriptor,
        PrepareRequestTokenPrincipal.Descriptor,
        PrepareRefreshTokenPrincipal.Descriptor,
        PrepareIdentityTokenPrincipal.Descriptor,
        PrepareUserCodePrincipal.Descriptor,

        GenerateAccessToken.Descriptor,
        GenerateAuthorizationCode.Descriptor,
        GenerateDeviceCode.Descriptor,
        GenerateRequestToken.Descriptor,
        GenerateRefreshToken.Descriptor,

        AttachDeviceCodeIdentifier.Descriptor,
        UpdateReferenceDeviceCodeEntry.Descriptor,
        AttachTokenDigests.Descriptor,

        GenerateUserCode.Descriptor,
        GenerateIdentityToken.Descriptor,

        BeautifyGeneratedTokens.Descriptor,

        AttachSignInParameters.Descriptor,
        AttachCustomSignInParameters.Descriptor,

        /*
         * Sign-out processing:
         */
        ValidateSignOutDemand.Descriptor,
        RedeemLogoutTokenEntry.Descriptor,
        AttachCustomSignOutParameters.Descriptor,

        /*
         * Error processing:
         */
        AttachErrorParameters.Descriptor,
        AttachCustomErrorParameters.Descriptor,

        .. Authentication.DefaultHandlers,
        .. Device.DefaultHandlers,
        .. Discovery.DefaultHandlers,
        .. Exchange.DefaultHandlers,
        .. Introspection.DefaultHandlers,
        .. Protection.DefaultHandlers,
        .. Revocation.DefaultHandlers,
        .. Session.DefaultHandlers,
        .. UserInfo.DefaultHandlers
    ]);

    /// <summary>
    /// Contains the logic responsible for inferring the endpoint type from the request URI.
    /// </summary>
    public sealed class InferEndpointType : IOpenIddictServerHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .UseSingletonHandler<InferEndpointType>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context is not { BaseUri.IsAbsoluteUri: true, RequestUri.IsAbsoluteUri: true })
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0127));
            }

            context.EndpointType =
                Matches(context.Options.AuthorizationEndpointUris)       ? OpenIddictServerEndpointType.Authorization       :
                Matches(context.Options.ConfigurationEndpointUris)       ? OpenIddictServerEndpointType.Configuration       :
                Matches(context.Options.DeviceAuthorizationEndpointUris) ? OpenIddictServerEndpointType.DeviceAuthorization :
                Matches(context.Options.EndSessionEndpointUris)          ? OpenIddictServerEndpointType.EndSession          :
                Matches(context.Options.EndUserVerificationEndpointUris) ? OpenIddictServerEndpointType.EndUserVerification :
                Matches(context.Options.IntrospectionEndpointUris)       ? OpenIddictServerEndpointType.Introspection       :
                Matches(context.Options.JsonWebKeySetEndpointUris)       ? OpenIddictServerEndpointType.JsonWebKeySet       :
                Matches(context.Options.PushedAuthorizationEndpointUris) ? OpenIddictServerEndpointType.PushedAuthorization :
                Matches(context.Options.RevocationEndpointUris)          ? OpenIddictServerEndpointType.Revocation          :
                Matches(context.Options.TokenEndpointUris)               ? OpenIddictServerEndpointType.Token               :
                Matches(context.Options.UserInfoEndpointUris)            ? OpenIddictServerEndpointType.UserInfo            :
                                                                           OpenIddictServerEndpointType.Unknown;

            if (context.EndpointType is not OpenIddictServerEndpointType.Unknown)
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6053), context.EndpointType);
            }

            return default;

            bool Matches(IReadOnlyList<Uri> candidates)
            {
                for (var index = 0; index < candidates.Count; index++)
                {
                    var candidate = candidates[index];
                    if (candidate.IsAbsoluteUri)
                    {
                        if (Equals(candidate, context.RequestUri))
                        {
                            return true;
                        }
                    }

                    else
                    {
                        var uri = OpenIddictHelpers.CreateAbsoluteUri(context.BaseUri, candidate);
                        if (!OpenIddictHelpers.IsImplicitFileUri(uri) &&
                             OpenIddictHelpers.IsBaseOf(context.BaseUri, uri) && Equals(uri, context.RequestUri))
                        {
                            return true;
                        }
                    }
                }

                return false;
            }

            static bool Equals(Uri left, Uri right) =>
                string.Equals(left.Scheme, right.Scheme, StringComparison.OrdinalIgnoreCase) &&
                string.Equals(left.Host, right.Host, StringComparison.OrdinalIgnoreCase) &&
                left.Port == right.Port &&
                // Note: paths are considered equivalent even if the casing isn't identical or if one of the two
                // paths only differs by a trailing slash, which matches the classical behavior seen on ASP.NET,
                // Microsoft.Owin/Katana and ASP.NET Core. Developers who prefer a different behavior can remove
                // this handler and replace it by a custom version implementing a more strict comparison logic.
                (string.Equals(left.AbsolutePath, right.AbsolutePath, StringComparison.OrdinalIgnoreCase) ||
                 (left.AbsolutePath.Length == right.AbsolutePath.Length + 1 &&
                  left.AbsolutePath.StartsWith(right.AbsolutePath, StringComparison.OrdinalIgnoreCase) &&
                  left.AbsolutePath[^1] is '/') ||
                 (right.AbsolutePath.Length == left.AbsolutePath.Length + 1 &&
                  right.AbsolutePath.StartsWith(left.AbsolutePath, StringComparison.OrdinalIgnoreCase) &&
                  right.AbsolutePath[^1] is '/'));
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands made from unsupported endpoints.
    /// </summary>
    public sealed class ValidateAuthenticationDemand : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ValidateAuthenticationDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            return context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or OpenIddictServerEndpointType.DeviceAuthorization or
                OpenIddictServerEndpointType.EndSession    or OpenIddictServerEndpointType.EndUserVerification or
                OpenIddictServerEndpointType.Introspection or OpenIddictServerEndpointType.PushedAuthorization or
                OpenIddictServerEndpointType.Revocation    or OpenIddictServerEndpointType.Token               or
                OpenIddictServerEndpointType.UserInfo
                    => default,

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0002)),
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for selecting the token types that should be validated.
    /// </summary>
    public sealed class EvaluateValidatedTokens : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<EvaluateValidatedTokens>()
                .SetOrder(ValidateAuthenticationDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.ExtractAccessToken,
             context.RequireAccessToken,
             context.ValidateAccessToken,
             context.RejectAccessToken) = context.EndpointType switch
            {
                // The userinfo endpoint requires sending a valid access token.
                OpenIddictServerEndpointType.UserInfo => (true, true, true, true),

                _ => (false, false, false, false)
            };

            (context.ExtractAuthorizationCode,
             context.RequireAuthorizationCode,
             context.ValidateAuthorizationCode,
             context.RejectAuthorizationCode) = context.EndpointType switch
            {
                // The authorization code grant requires sending a valid authorization code.
                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => (true, true, true, true),

                _ => (false, false, false, false)
            };

            (context.ExtractClientAssertion,
             context.RequireClientAssertion,
             context.ValidateClientAssertion,
             context.RejectClientAssertion) = context.EndpointType switch
            {
                // Client assertions can be used with all the endpoints that support client authentication.
                // By default, client assertions are not required, but they are extracted and validated if
                // present and invalid client assertions are always automatically rejected by OpenIddict.
                OpenIddictServerEndpointType.DeviceAuthorization or OpenIddictServerEndpointType.Introspection or
                OpenIddictServerEndpointType.Revocation          or OpenIddictServerEndpointType.Token
                    => (true, false, true, true),

                _ => (false, false, false, false)
            };

            (context.ExtractDeviceCode,
             context.RequireDeviceCode,
             context.ValidateDeviceCode,
             context.RejectDeviceCode) = context.EndpointType switch
            {
                // The device code grant requires sending a valid device code.
                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => (true, true, true, true),

                _ => (false, false, false, false)
            };

            (context.ExtractGenericToken,
             context.RequireGenericToken,
             context.ValidateGenericToken,
             context.RejectGenericToken) = context.EndpointType switch
            {
                // Tokens received by the introspection and revocation endpoints can be of any supported type.
                // Additional token type filtering is typically performed by the endpoint themselves when needed.
                OpenIddictServerEndpointType.Introspection or OpenIddictServerEndpointType.Revocation
                    => (true, true, true, true),

                _ => (false, false, false, false)
            };

            (context.ExtractIdentityToken,
             context.RequireIdentityToken,
             context.ValidateIdentityToken,
             context.RejectIdentityToken) = context.EndpointType switch
            {
                // The identity token received by the authorization, end session and pushed
                // authorization endpoints are not required and serve as optional hints.
                //
                // As such, identity token hints are extracted and validated, but
                // the authentication demand is not rejected if they are not valid.
                OpenIddictServerEndpointType.Authorization or
                OpenIddictServerEndpointType.EndSession    or
                OpenIddictServerEndpointType.PushedAuthorization
                    => (true, false, true, false),

                _ => (false, false, false, false)
            };

            (context.ExtractRequestToken,
             context.RequireRequestToken,
             context.ValidateRequestToken,
             context.RejectRequestToken) = context.EndpointType switch
            {
                // Always validate request tokens received by the authorization or end session endpoints.
                OpenIddictServerEndpointType.Authorization or
                OpenIddictServerEndpointType.EndSession => (true, false, true, true),

                _ => (false, false, false, false)
            };

            (context.ExtractRefreshToken,
             context.RequireRefreshToken,
             context.ValidateRefreshToken,
             context.RejectRefreshToken) = context.EndpointType switch
            {
                // The refresh token grant requires sending a valid refresh token.
                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => (true, true, true, true),

                _ => (false, false, false, false)
            };

            (context.ExtractUserCode,
             context.RequireUserCode,
             context.ValidateUserCode,
             context.RejectUserCode) = context.EndpointType switch
            {
                // Note: the end-user verification endpoint can be accessed without specifying a
                // user code (that can be later set by the user using a form, for instance).
                OpenIddictServerEndpointType.EndUserVerification => (true, false, true, false),

                _ => (false, false, false, false)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the tokens from the incoming request.
    /// </summary>
    public sealed class ResolveValidatedTokens : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveValidatedTokens>()
                .SetOrder(EvaluateValidatedTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.AccessToken = context.EndpointType switch
            {
                OpenIddictServerEndpointType.UserInfo when context.ExtractAccessToken
                    => context.Request.AccessToken,

                _ => null
            };

            context.AuthorizationCode = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.ExtractAuthorizationCode
                    => context.Request.Code,

                _ => null
            };

            (context.ClientAssertion, context.ClientAssertionType) = context.EndpointType switch
            {
                OpenIddictServerEndpointType.DeviceAuthorization or OpenIddictServerEndpointType.Introspection or
                OpenIddictServerEndpointType.Revocation          or OpenIddictServerEndpointType.Token
                    when context.ExtractClientAssertion
                    => (context.Request.ClientAssertion, context.Request.ClientAssertionType),

                _ => (null, null)
            };

            context.DeviceCode = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.ExtractDeviceCode
                    => context.Request.DeviceCode,

                _ => null
            };

            (context.GenericToken, context.GenericTokenTypeHint) = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Introspection or
                OpenIddictServerEndpointType.Revocation when context.ExtractGenericToken
                    => (context.Request.Token, context.Request.TokenTypeHint),

                _ => (null, null)
            };

            context.IdentityToken = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or
                OpenIddictServerEndpointType.EndSession    or
                OpenIddictServerEndpointType.PushedAuthorization when context.ExtractIdentityToken
                    => context.Request.IdTokenHint,

                _ => null
            };

            context.RequestToken = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization when
                    context.ExtractRequestToken &&
                    context.Request.RequestUri is { Length: > 0 } uri &&
                    uri.StartsWith(RequestUris.Prefixes.Generic, StringComparison.OrdinalIgnoreCase)
                    => uri[RequestUris.Prefixes.Generic.Length..],

                OpenIddictServerEndpointType.EndSession when
                    context.ExtractRequestToken &&
                    context.Request.RequestUri is { Length: > 0 } uri &&
                    uri.StartsWith(RequestUris.Prefixes.Generic, StringComparison.OrdinalIgnoreCase)
                    => uri[RequestUris.Prefixes.Generic.Length..],

                _ => null
            };

            context.RefreshToken = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.ExtractRefreshToken
                    => context.Request.RefreshToken,

                _ => null
            };

            context.UserCode = context.EndpointType switch
            {
                OpenIddictServerEndpointType.EndUserVerification when context.ExtractUserCode
                    => context.Request.UserCode,

                _ => null
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands that lack required tokens.
    /// </summary>
    public sealed class ValidateRequiredTokens : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ValidateRequiredTokens>()
                // Note: this handler is registered with a high gap to allow handlers
                // that do token extraction to be executed before this handler runs.
                .SetOrder(ResolveValidatedTokens.Descriptor.Order + 50_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if ((context.RequireAccessToken       && string.IsNullOrEmpty(context.AccessToken))       ||
                (context.RequireAuthorizationCode && string.IsNullOrEmpty(context.AuthorizationCode)) ||
                (context.RequireClientAssertion   && string.IsNullOrEmpty(context.ClientAssertion))   ||
                (context.RequireDeviceCode        && string.IsNullOrEmpty(context.DeviceCode))        ||
                (context.RequireGenericToken      && string.IsNullOrEmpty(context.GenericToken))      ||
                (context.RequireIdentityToken     && string.IsNullOrEmpty(context.IdentityToken))     ||
                (context.RequireRefreshToken      && string.IsNullOrEmpty(context.RefreshToken))      ||
                (context.RequireRequestToken      && string.IsNullOrEmpty(context.RequestToken))      ||
                (context.RequireUserCode          && string.IsNullOrEmpty(context.UserCode)))
            {
                context.Reject(
                    error: Errors.MissingToken,
                    description: SR.GetResourceString(SR.ID2000),
                    uri: SR.FormatID8000(SR.ID2000));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the client assertion resolved from the context.
    /// </summary>
    public sealed class ValidateClientAssertion : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateClientAssertion(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionValidated>()
                .UseScopedHandler<ValidateClientAssertion>()
                .SetOrder(ValidateRequiredTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.ClientAssertion))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.ClientAssertion,
                TokenFormat = context.ClientAssertionType switch
                {
                    ClientAssertionTypes.JwtBearer => TokenFormats.Jwt,
                    _ => null
                },
                ValidTokenTypes = { TokenTypeHints.ClientAssertion }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectClientAssertion)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidClient,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.ClientAssertionPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the well-known claims contained in the client assertion principal.
    /// </summary>
    public sealed class ValidateClientAssertionWellknownClaims : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionPrincipal>()
                .UseSingletonHandler<ValidateClientAssertionWellknownClaims>()
                .SetOrder(ValidateClientAssertion.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.ClientAssertionPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            foreach (var group in context.ClientAssertionPrincipal.Claims
                .GroupBy(static claim => claim.Type)
                .ToDictionary(static group => group.Key, group => group.ToList())
                .Where(static group => !ValidateClaimGroup(group.Key, group.Value)))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2171(group.Key),
                    uri: SR.FormatID8000(SR.ID2171));

                return default;
            }

            // Client assertions MUST contain an "iss" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            // and https://datatracker.ietf.org/doc/html/rfc7523#section-3.
            if (!context.ClientAssertionPrincipal.HasClaim(Claims.Issuer))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2172(Claims.Issuer),
                    uri: SR.FormatID8000(SR.ID2172));

                return default;
            }

            // Client assertions MUST contain a "sub" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            // and https://datatracker.ietf.org/doc/html/rfc7523#section-3.
            if (!context.ClientAssertionPrincipal.HasClaim(Claims.Subject))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2172(Claims.Subject),
                    uri: SR.FormatID8000(SR.ID2172));

                return default;
            }

            // Client assertions MUST contain at least one "aud" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            // and https://datatracker.ietf.org/doc/html/rfc7523#section-3.
            if (!context.ClientAssertionPrincipal.HasClaim(Claims.Audience))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2172(Claims.Audience),
                    uri: SR.FormatID8000(SR.ID2172));

                return default;
            }

            // Client assertions MUST contain contain a "exp" claim. For more information,
            // see https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
            // and https://datatracker.ietf.org/doc/html/rfc7523#section-3.
            if (!context.ClientAssertionPrincipal.HasClaim(Claims.ExpiresAt))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2172(Claims.ExpiresAt),
                    uri: SR.FormatID8000(SR.ID2172));

                return default;
            }

            return default;

            static bool ValidateClaimGroup(string name, List<Claim> values) => name switch
            {
                // The following claims MUST be represented as unique strings.
                Claims.AuthorizedParty or Claims.Issuer or Claims.JwtId or Claims.Subject
                    => values is [{ ValueType: ClaimValueTypes.String }],

                // The following claims MUST be represented as unique strings or array of strings.
                Claims.Audience
                    => values.TrueForAll(static value => value.ValueType is ClaimValueTypes.String) ||
                       // Note: a unique claim using the special JSON_ARRAY claim value type is allowed
                       // if the individual elements of the parsed JSON array are all string values.
                       (values is [{ ValueType: JsonClaimValueTypes.JsonArray, Value: string value }] &&
                        JsonSerializer.Deserialize<JsonElement>(value) is { ValueKind: JsonValueKind.Array } element &&
                        OpenIddictHelpers.ValidateArrayElements(element, JsonValueKind.String)),

                // The following claims MUST be represented as unique numeric dates.
                Claims.ExpiresAt or Claims.IssuedAt or Claims.NotBefore
                    => values is [{ ValueType: ClaimValueTypes.Integer    or ClaimValueTypes.Integer32 or
                                               ClaimValueTypes.Integer64  or ClaimValueTypes.Double    or
                                               ClaimValueTypes.UInteger32 or ClaimValueTypes.UInteger64 }],

                // Claims that are not in the well-known list can be of any type.
                _ => true
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the issuer contained in the client assertion principal.
    /// </summary>
    public sealed class ValidateClientAssertionIssuer : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionPrincipal>()
                .UseSingletonHandler<ValidateClientAssertionIssuer>()
                .SetOrder(ValidateClientAssertionWellknownClaims.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.ClientAssertionPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Ensure the subject represented by the client assertion matches its issuer.
            var (issuer, subject) = (
                context.ClientAssertionPrincipal.GetClaim(Claims.Issuer),
                context.ClientAssertionPrincipal.GetClaim(Claims.Subject));

            if (!string.Equals(issuer, subject, StringComparison.Ordinal))
            {
                context.Reject(
                    error: Errors.InvalidGrant,
                    description: SR.FormatID2173(Claims.Subject),
                    uri: SR.FormatID8000(SR.ID2173));

                return default;
            }

            // If a client identifier was also specified in the request, ensure the
            // value matches the application represented by the client assertion.
            if (!string.IsNullOrEmpty(context.ClientId))
            {
                if (!string.Equals(context.ClientId, issuer, StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: SR.FormatID2173(Claims.Issuer),
                        uri: SR.FormatID8000(SR.ID2173));

                    return default;
                }

                if (!string.Equals(context.ClientId, subject, StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.InvalidGrant,
                        description: SR.FormatID2173(Claims.Subject),
                        uri: SR.FormatID8000(SR.ID2173));

                    return default;
                }
            }

            // Otherwise, use the issuer resolved from the client assertion principal as the client identifier.
            else if (context.Request is OpenIddictRequest request)
            {
                request.ClientId = context.ClientAssertionPrincipal.GetClaim(Claims.Issuer);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the audience contained in the client assertion principal.
    /// </summary>
    public sealed class ValidateClientAssertionAudience : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionPrincipal>()
                .UseSingletonHandler<ValidateClientAssertionAudience>()
                .SetOrder(ValidateClientAssertionIssuer.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.ClientAssertionPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Ensure at least one non-empty audience was specified (note: in
            // the most common case, a single audience is generally specified).
            var audiences = context.ClientAssertionPrincipal.GetClaims(Claims.Audience);
            if (!audiences.Any(static audience => !string.IsNullOrEmpty(audience)))
            {
                context.Reject(
                    error: Errors.InvalidGrant,
                    description: SR.FormatID2172(Claims.Audience),
                    uri: SR.FormatID8000(SR.ID2172));

                return default;
            }

            // Ensure at least one of the audiences points to the current authorization server.
            if (!ValidateAudiences(audiences))
            {
                context.Reject(
                    error: Errors.InvalidGrant,
                    description: SR.FormatID2173(Claims.Audience),
                    uri: SR.FormatID8000(SR.ID2173));

                return default;
            }

            return default;

            bool ValidateAudiences(ImmutableArray<string> audiences)
            {
                foreach (var audience in audiences)
                {
                    // Ignore the iterated audience if it's not a valid absolute URI.
                    if (!Uri.TryCreate(audience, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        continue;
                    }

                    // Consider the audience valid if it matches the issuer value assigned to the current instance.
                    //
                    // See https://datatracker.ietf.org/doc/html/rfc7523#section-3 for more information.
                    if (context.Options.Issuer is not null && UriEquals(uri, context.Options.Issuer))
                    {
                        return true;
                    }

                    // At this point, ignore the rest of the validation logic if the current base URI is not known.
                    if (context.BaseUri is null)
                    {
                        continue;
                    }

                    // Consider the audience valid if it matches the current base URI, unless an explicit issuer was set.
                    if (context.Options.Issuer is null && UriEquals(uri, context.BaseUri))
                    {
                        return true;
                    }

                    // Consider the audience valid if it matches one of the URIs assigned to the token
                    // endpoint, independently of whether the request is a token request or not.
                    if (MatchesAnyUri(uri, context.Options.TokenEndpointUris))
                    {
                        return true;
                    }

                    // If the current request is a device request, consider the audience valid
                    // if the address matches one of the URIs assigned to the device authorization endpoint.
                    if (context.EndpointType is OpenIddictServerEndpointType.DeviceAuthorization &&
                        MatchesAnyUri(uri, context.Options.DeviceAuthorizationEndpointUris))
                    {
                        return true;
                    }

                    // If the current request is an introspection request, consider the audience valid
                    // if the address matches one of the URIs assigned to the introspection endpoint.
                    else if (context.EndpointType is OpenIddictServerEndpointType.Introspection &&
                        MatchesAnyUri(uri, context.Options.IntrospectionEndpointUris))
                    {
                        return true;
                    }

                    // If the current request is a pushed authorization request, consider the audience valid
                    // if the address matches one of the URIs assigned to the pushed authorization endpoint.
                    else if (context.EndpointType is OpenIddictServerEndpointType.PushedAuthorization &&
                        MatchesAnyUri(uri, context.Options.PushedAuthorizationEndpointUris))
                    {
                        return true;
                    }

                    // If the current request is a revocation request, consider the audience valid
                    // if the address matches one of the URIs assigned to the revocation endpoint.
                    else if (context.EndpointType is OpenIddictServerEndpointType.Revocation &&
                        MatchesAnyUri(uri, context.Options.RevocationEndpointUris))
                    {
                        return true;
                    }
                }

                return false;
            }

            bool MatchesAnyUri(Uri uri, List<Uri> uris)
            {
                for (var index = 0; index < uris.Count; index++)
                {
                    if (UriEquals(uri, OpenIddictHelpers.CreateAbsoluteUri(context.BaseUri, uris[index])))
                    {
                        return true;
                    }
                }

                return false;
            }

            static bool UriEquals(Uri left, Uri right)
            {
                if (string.Equals(left.AbsolutePath, right.AbsolutePath, StringComparison.Ordinal))
                {
                    return true;
                }

                // Consider the two URIs identical if they only differ by the trailing slash.

                if (left.AbsolutePath.Length == right.AbsolutePath.Length + 1 &&
                    left.AbsolutePath.StartsWith(right.AbsolutePath, StringComparison.Ordinal) &&
                    left.AbsolutePath[^1] is '/')
                {
                    return true;
                }

                return right.AbsolutePath.Length == left.AbsolutePath.Length + 1 &&
                       right.AbsolutePath.StartsWith(left.AbsolutePath, StringComparison.Ordinal) &&
                       right.AbsolutePath[^1] is '/';
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands that use an invalid client_id.
    /// </summary>
    public sealed class ValidateClientId : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictApplicationManager? _applicationManager;

        public ValidateClientId(IOpenIddictApplicationManager? applicationManager = null)
            => _applicationManager = applicationManager;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseScopedHandler<ValidateClientId>(static provider =>
                {
                    // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                    // invalid core configuration exceptions are not thrown even if the managers were registered.
                    var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    return options.EnableDegradedMode ?
                        new ValidateClientId() :
                        new ValidateClientId(provider.GetService<IOpenIddictApplicationManager>() ??
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                })
                .SetOrder(ValidateClientAssertionAudience.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Don't validate the client identifier on endpoints that don't support client identification.
            if (context.EndpointType is OpenIddictServerEndpointType.EndUserVerification or
                                        OpenIddictServerEndpointType.UserInfo)
            {
                return;
            }

            if (string.IsNullOrEmpty(context.ClientId))
            {
                switch (context.EndpointType)
                {
                    // Note: support for the client_id parameter was only added in the second draft of the
                    // https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout specification
                    // and is optional. As such, the client identifier is only validated if it was specified.
                    case OpenIddictServerEndpointType.EndSession:
                        return;

                    case OpenIddictServerEndpointType.Introspection when context.Options.AcceptAnonymousClients:
                    case OpenIddictServerEndpointType.Revocation    when context.Options.AcceptAnonymousClients:
                    case OpenIddictServerEndpointType.Token         when context.Options.AcceptAnonymousClients:
                        return;
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6220), Parameters.ClientId);

                context.Reject(
                    error: Errors.InvalidClient,
                    description: SR.FormatID2029(Parameters.ClientId),
                    uri: SR.FormatID8000(SR.ID2029));

                return;
            }

            if (!context.Options.EnableDegradedMode)
            {
                if (_applicationManager is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                }

                // Retrieve the application details corresponding to the requested client_id.
                // If no entity can be found, this likely indicates that the client_id is invalid.
                var application = await _applicationManager.FindByClientIdAsync(context.ClientId);
                if (application is null)
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6221), context.ClientId);

                    context.Reject(
                        error: context.EndpointType switch
                        {
                            // For non-interactive endpoints, return "invalid_client" instead of "invalid_request".
                            OpenIddictServerEndpointType.DeviceAuthorization or OpenIddictServerEndpointType.Introspection or
                            OpenIddictServerEndpointType.Revocation          or OpenIddictServerEndpointType.Token
                                => Errors.InvalidClient,

                            _ => Errors.InvalidRequest
                        },
                        description: SR.FormatID2052(Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands made by applications
    /// whose client type is not compatible with the presence of client credentials.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class ValidateClientType : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictApplicationManager _applicationManager;

        public ValidateClientType() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public ValidateClientType(IOpenIddictApplicationManager applicationManager)
            => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientIdParameter>()
                .AddFilter<RequireDegradedModeDisabled>()
                .UseScopedHandler<ValidateClientType>()
                .SetOrder(ValidateClientId.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

            // Don't validate the client type on endpoints that don't support client authentication.
            if (context.EndpointType is OpenIddictServerEndpointType.Authorization       or
                                        OpenIddictServerEndpointType.EndSession          or
                                        OpenIddictServerEndpointType.EndUserVerification or
                                        OpenIddictServerEndpointType.PushedAuthorization or
                                        OpenIddictServerEndpointType.UserInfo)
            {
                return;
            }

            var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

            if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
            {
                // Reject grant_type=client_credentials token requests if the application is a public client.
                if (context.EndpointType is OpenIddictServerEndpointType.Token &&
                    context.Request.IsClientCredentialsGrantType())
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6222), context.Request.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.FormatID2043(Parameters.GrantType),
                        uri: SR.FormatID8000(SR.ID2043));

                    return;
                }

                // Reject requests containing a client_assertion when the client is a public application.
                if (!string.IsNullOrEmpty(context.ClientAssertion))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6226), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2053(Parameters.ClientAssertion),
                        uri: SR.FormatID8000(SR.ID2053));

                    return;
                }

                // Reject requests containing a client_secret when the client is a public application.
                if (!string.IsNullOrEmpty(context.ClientSecret))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6223), context.ClientId);

                    context.Reject(
                        error: Errors.InvalidClient,
                        description: SR.FormatID2053(Parameters.ClientSecret),
                        uri: SR.FormatID8000(SR.ID2053));

                    return;
                }

                return;
            }

            // Confidential and hybrid applications MUST authenticate to protect them from impersonation attacks.
            if (context.ClientAssertionPrincipal is null && string.IsNullOrEmpty(context.ClientSecret))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6224), context.ClientId);

                context.Reject(
                    error: Errors.InvalidClient,
                    description: SR.FormatID2054(Parameters.ClientSecret),
                    uri: SR.FormatID8000(SR.ID2054));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting authentication demands specifying an invalid client secret.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class ValidateClientSecret : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictApplicationManager _applicationManager;

        public ValidateClientSecret() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public ValidateClientSecret(IOpenIddictApplicationManager applicationManager)
            => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientIdParameter>()
                .AddFilter<RequireClientSecretParameter>()
                .AddFilter<RequireDegradedModeDisabled>()
                .UseScopedHandler<ValidateClientSecret>()
                .SetOrder(ValidateClientType.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));
            Debug.Assert(!string.IsNullOrEmpty(context.ClientSecret), SR.FormatID4000(Parameters.ClientSecret));

            // Don't validate the client secret on endpoints that don't support client authentication.
            if (context.EndpointType is OpenIddictServerEndpointType.Authorization       or
                                        OpenIddictServerEndpointType.EndSession          or
                                        OpenIddictServerEndpointType.EndUserVerification or
                                        OpenIddictServerEndpointType.PushedAuthorization or
                                        OpenIddictServerEndpointType.UserInfo)
            {
                return;
            }

            var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

            // If the application is a public client, don't validate the client secret.
            if (await _applicationManager.HasClientTypeAsync(application, ClientTypes.Public))
            {
                return;
            }

            if (!await _applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6225), context.ClientId);

                context.Reject(
                    error: Errors.InvalidClient,
                    description: SR.GetResourceString(SR.ID2055),
                    uri: SR.FormatID8000(SR.ID2055));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the request token resolved from the context.
    /// </summary>
    public sealed class ValidateRequestToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateRequestToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRequestTokenValidated>()
                .UseScopedHandler<ValidateRequestToken>()
                .SetOrder(ValidateClientSecret.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.RequestToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.RequestToken,
                ValidTokenTypes = { TokenTypeHints.Private.RequestToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectRequestToken)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.RequestTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring the resolved request
    /// token is suitable for the requested authentication demand.
    /// </summary>
    public sealed class ValidateRequestTokenType : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRequestTokenPrincipal>()
                .AddFilter<RequireRequestTokenValidated>()
                .UseSingletonHandler<ValidateRequestTokenType>()
                .SetOrder(ValidateRequestToken.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.RequestTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Reject the authentication demand if the request token is not expected to be
            // received by the current endpoint as it may indicate a mix-up attack (e.g a request
            // token created for an end session request was used for an authorization request).
            switch ((context.EndpointType, context.RequestTokenPrincipal.GetClaim(Claims.Private.RequestTokenType)))
            {
                case (OpenIddictServerEndpointType.Authorization, not (
                    RequestTokenTypes.Private.CachedAuthorizationRequest or
                    RequestTokenTypes.Private.PushedAuthorizationRequest)):

                case (OpenIddictServerEndpointType.EndSession, not RequestTokenTypes.Private.CachedEndSessionRequest):
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2182(Parameters.RequestUri),
                        uri: SR.FormatID8000(SR.ID2182));

                    return default;

                // For other endpoints that don't natively support request tokens, don't return an error
                // to allow custom implementations to use request tokens with other types of endpoints.
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the access token resolved from the context.
    /// </summary>
    public sealed class ValidateAccessToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateAccessToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAccessTokenValidated>()
                .UseScopedHandler<ValidateAccessToken>()
                .SetOrder(ValidateRequestTokenType.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.AccessToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.AccessToken,
                ValidTokenTypes = { TokenTypeHints.AccessToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectAccessToken)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.AccessTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the authorization code resolved from the context.
    /// </summary>
    public sealed class ValidateAuthorizationCode : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateAuthorizationCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireAuthorizationCodeValidated>()
                .UseScopedHandler<ValidateAuthorizationCode>()
                .SetOrder(ValidateAccessToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.AuthorizationCode))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.AuthorizationCode,
                ValidTokenTypes = { TokenTypeHints.AuthorizationCode }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectAuthorizationCode)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.AuthorizationCodePrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the device code resolved from the context.
    /// </summary>
    public sealed class ValidateDeviceCode : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateDeviceCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireDeviceCodeValidated>()
                .UseScopedHandler<ValidateDeviceCode>()
                .SetOrder(ValidateAuthorizationCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.DeviceCode))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.DeviceCode,
                ValidTokenTypes = { TokenTypeHints.DeviceCode }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectDeviceCode)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.DeviceCodePrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating tokens of unknown types resolved from the context.
    /// </summary>
    public sealed class ValidateGenericToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateGenericToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireGenericTokenValidated>()
                .UseScopedHandler<ValidateGenericToken>()
                .SetOrder(ValidateDeviceCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.GenericToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.GenericToken,
                TokenTypeHint = context.GenericTokenTypeHint,

                // By default, only access tokens and refresh tokens can be introspected/revoked but
                // tokens received by the introspection and revocation endpoints can be of any type.
                //
                // Additional token type filtering is made by the endpoint themselves, if needed.
                // As such, the valid token types list is deliberately left empty in this case.
                //
                // Note: tokens not created by the server stack (e.g client assertions)
                // are deliberately excluded and not present in the following list:
                ValidTokenTypes =
                {
                    TokenTypeHints.AccessToken,
                    TokenTypeHints.AuthorizationCode,
                    TokenTypeHints.DeviceCode,
                    TokenTypeHints.IdToken,
                    TokenTypeHints.RefreshToken,
                    TokenTypeHints.UserCode
                }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectGenericToken)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.GenericTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the identity token resolved from the context.
    /// </summary>
    public sealed class ValidateIdentityToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateIdentityToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireIdentityTokenValidated>()
                .UseScopedHandler<ValidateIdentityToken>()
                .SetOrder(ValidateGenericToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.IdentityToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                // Don't validate the lifetime of id_tokens used as id_token_hints.
                DisableLifetimeValidation = context.EndpointType is OpenIddictServerEndpointType.Authorization or
                                                                    OpenIddictServerEndpointType.EndSession    or
                                                                    OpenIddictServerEndpointType.PushedAuthorization,
                Token = context.IdentityToken,
                ValidTokenTypes = { TokenTypeHints.IdToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectIdentityToken)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.IdentityTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the refresh token resolved from the context.
    /// </summary>
    public sealed class ValidateRefreshToken : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateRefreshToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRefreshTokenValidated>()
                .UseScopedHandler<ValidateRefreshToken>()
                .SetOrder(ValidateIdentityToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.RefreshToken))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.RefreshToken,
                ValidTokenTypes = { TokenTypeHints.RefreshToken }
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectRefreshToken)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.RefreshTokenPrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the user code resolved from the context.
    /// </summary>
    public sealed class ValidateUserCode : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public ValidateUserCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserCodeValidated>()
                .UseScopedHandler<ValidateUserCode>()
                .SetOrder(ValidateRefreshToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (string.IsNullOrEmpty(context.UserCode))
            {
                return;
            }

            var notification = new ValidateTokenContext(context.Transaction)
            {
                Token = context.UserCode,
                ValidTokenTypes = { TokenTypeHints.UserCode }
            };

            // Note: restrict the allowed characters to the user code charset set in the options.
            notification.AllowedCharset.UnionWith(context.Options.UserCodeCharset);

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                if (context.RejectUserCode)
                {
                    context.Reject(
                        error: notification.Error ?? Errors.InvalidRequest,
                        description: notification.ErrorDescription,
                        uri: notification.ErrorUri);
                    return;
                }

                return;
            }

            context.UserCodePrincipal = notification.Principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the host authentication properties from the principal, if applicable.
    /// </summary>
    public sealed class ResolveHostAuthenticationProperties : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<ResolveHostAuthenticationProperties>()
                .SetOrder(ValidateUserCode.Descriptor.Order + 1_000)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var principal = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => context.AuthorizationCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => context.DeviceCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => context.RefreshTokenPrincipal,

                OpenIddictServerEndpointType.EndUserVerification => context.UserCodePrincipal,

                _ => null
            };

            if (principal?.GetClaim(Claims.Private.HostProperties) is string value && !string.IsNullOrEmpty(value))
            {
                using var document = JsonDocument.Parse(value);

                foreach (var property in document.RootElement.EnumerateObject())
                {
                    context.Properties[property.Name] = property.Value.GetString();
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for reformating validated tokens if necessary.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class ReformatValidatedTokens : IOpenIddictServerHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseScopedHandler<ReformatValidatedTokens>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: unlike other tokens, user codes may be potentially entered manually by users in a web form.
            // To make that easier, characters that are not part of the allowed charset are generally ignored.
            // Since user codes entered by the user or flowed as a query string parameter can be re-rendered
            // (e.g for user confirmation), they are automatically reformatted here to make sure that characters
            // that were not part of the allowed charset and ignored when validating them are not included in the
            // token string that will be attached to the authentication context and resolved by the application.
            if (!string.IsNullOrEmpty(context.UserCode) && !string.IsNullOrEmpty(context.Options.UserCodeDisplayFormat))
            {
                List<string> arguments = [];

                var enumerator = StringInfo.GetTextElementEnumerator(context.UserCode);
                while (enumerator.MoveNext())
                {
                    var element = enumerator.GetTextElement();
                    if (context.Options.UserCodeCharset.Contains(element))
                    {
                        arguments.Add(enumerator.GetTextElement());
                    }
                }

                if (arguments.Count is 0)
                {
                    context.UserCode = null;
                }

                else if (arguments.Count == context.Options.UserCodeLength)
                {
                    try
                    {
                        context.UserCode = string.Format(CultureInfo.InvariantCulture,
                            context.Options.UserCodeDisplayFormat, [.. arguments]);
                    }

                    catch (FormatException)
                    {
                        context.UserCode = string.Join(string.Empty, arguments);
                    }
                }

                else
                {
                    context.UserCode = string.Join(string.Empty, arguments);
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting challenge demands made from unsupported endpoints.
    /// </summary>
    public sealed class ValidateChallengeDemand : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<ValidateChallengeDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not (OpenIddictServerEndpointType.Authorization       or
                                             OpenIddictServerEndpointType.EndUserVerification or
                                             OpenIddictServerEndpointType.PushedAuthorization or
                                             OpenIddictServerEndpointType.Token               or
                                             OpenIddictServerEndpointType.UserInfo))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0006));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring that the challenge response contains an appropriate error.
    /// </summary>
    public sealed class AttachDefaultChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachDefaultChallengeError>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Response.Error ??= context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization       or
                OpenIddictServerEndpointType.EndUserVerification or
                OpenIddictServerEndpointType.PushedAuthorization
                    => Errors.AccessDenied,

                OpenIddictServerEndpointType.Token    => Errors.InvalidGrant,
                OpenIddictServerEndpointType.UserInfo => Errors.InsufficientAccess,

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0006))
            };

            context.Response.ErrorDescription ??= context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization       or
                OpenIddictServerEndpointType.EndUserVerification or
                OpenIddictServerEndpointType.PushedAuthorization
                    => SR.GetResourceString(SR.ID2015),

                OpenIddictServerEndpointType.Token    => SR.GetResourceString(SR.ID2024),
                OpenIddictServerEndpointType.UserInfo => SR.GetResourceString(SR.ID2025),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0006))
            };

            context.Response.ErrorUri ??= context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization       or
                OpenIddictServerEndpointType.EndUserVerification or
                OpenIddictServerEndpointType.PushedAuthorization
                    => SR.FormatID8000(SR.ID2015),

                OpenIddictServerEndpointType.Token    => SR.FormatID8000(SR.ID2024),
                OpenIddictServerEndpointType.UserInfo => SR.FormatID8000(SR.ID2025),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0006))
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting the device code entry associated with the user code.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class RejectDeviceCodeEntry : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public RejectDeviceCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public RejectDeviceCodeEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .UseScopedHandler<RejectDeviceCodeEntry>()
                .SetOrder(AttachDefaultChallengeError.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictServerEndpointType.EndUserVerification)
            {
                return;
            }

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            Debug.Assert(notification.UserCodePrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Extract the device code identifier from the user code principal.
            var identifier = notification.UserCodePrincipal.GetClaim(Claims.Private.DeviceCodeId);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0008));
            }

            var token = await _tokenManager.FindByIdAsync(identifier);
            if (token is not null)
            {
                await _tokenManager.TryRejectAsync(token);
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting the user code entry, if applicable.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class RejectUserCodeEntry : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public RejectUserCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public RejectUserCodeEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .UseScopedHandler<RejectUserCodeEntry>()
                .SetOrder(RejectDeviceCodeEntry.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictServerEndpointType.EndUserVerification)
            {
                return;
            }

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            Debug.Assert(notification.UserCodePrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Extract the device code identifier from the authentication principal.
            var identifier = notification.UserCodePrincipal.GetTokenId();
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0009));
            }

            var token = await _tokenManager.FindByIdAsync(identifier);
            if (token is not null)
            {
                await _tokenManager.TryRejectAsync(token);
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the challenge response.
    /// </summary>
    public sealed class AttachCustomChallengeParameters : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<AttachCustomChallengeParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring that the sign-in demand
    /// is compatible with the type of the endpoint that handled the request.
    /// </summary>
    public sealed class ValidateSignInDemand : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<ValidateSignInDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            switch (context.EndpointType)
            {
                // Note: sign-in operations triggered from the device authorization or pushed authorization endpoints
                // can't be associated to specific users as users' identity is not known until they reach the end-user
                // verification endpoint and validate the user code (for the device authorization flow) or are redirected
                // to the authorization endpoint and approve the demand (for an interactive flow like the code flow).
                //
                // As such, the principal used in this case cannot contain an authenticated identity or a subject claim.
                case OpenIddictServerEndpointType.DeviceAuthorization:
                case OpenIddictServerEndpointType.PushedAuthorization:

                // Similarly, sign-in operations triggered from the authorization or end session endpoints
                // when the built-in request caching (that stores requests as request tokens in the database)
                // is enabled cannot be associated to a specific user or contain an authenticated identity.
                case OpenIddictServerEndpointType.Authorization
                    when context.Options.EnableAuthorizationRequestCaching &&
                         string.IsNullOrEmpty(context.Request.RequestUri):
                case OpenIddictServerEndpointType.EndSession
                    when context.Options.EnableEndSessionRequestCaching &&
                         string.IsNullOrEmpty(context.Request.RequestUri):
                    if (context.Principal is not { Identity: ClaimsIdentity })
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0011));
                    }

                    if (context.Principal.Identity.IsAuthenticated)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0012));
                    }

                    if (context.Principal.HasClaim(Claims.Subject))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0013));
                    }
                    break;

                case OpenIddictServerEndpointType.Authorization:
                case OpenIddictServerEndpointType.EndUserVerification:
                case OpenIddictServerEndpointType.Token:
                    if (context.Principal is not { Identity: ClaimsIdentity })
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0011));
                    }

                    if (!context.Principal.Identity.IsAuthenticated)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0014));
                    }

                    if (string.IsNullOrEmpty(context.Principal.GetClaim(Claims.Subject)))
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0015));
                    }
                    break;

                default: throw new InvalidOperationException(SR.GetResourceString(SR.ID0010));
            }

            foreach (var group in context.Principal.Claims
                .GroupBy(static claim => claim.Type)
                .ToDictionary(static group => group.Key, static group => group.ToList())
                .Where(static group => !ValidateClaimGroup(group.Key, group.Value)))
            {
                throw new InvalidOperationException(SR.FormatID0424(group.Key));
            }

            return default;

            static bool ValidateClaimGroup(string name, List<Claim> values) => name switch
            {
                // The following claims MUST be represented as unique strings.
                Claims.AuthenticationContextReference or Claims.Subject                or
                Claims.Private.AuthorizationId        or Claims.Private.CreationDate   or
                Claims.Private.DeviceCodeId           or Claims.Private.ExpirationDate or
                Claims.Private.TokenId
                    => values is [{ ValueType: ClaimValueTypes.String }],

                // The following claims MUST be represented as unique strings or array of strings.
                Claims.Private.Audience or Claims.Private.Presenter or Claims.Private.Resource
                    => values.TrueForAll(static value => value.ValueType is ClaimValueTypes.String) ||
                       // Note: a unique claim using the special JSON_ARRAY claim value type is allowed
                       // if the individual elements of the parsed JSON array are all string values.
                       (values is [{ ValueType: JsonClaimValueTypes.JsonArray, Value: string value }] &&
                        JsonSerializer.Deserialize<JsonElement>(value) is { ValueKind: JsonValueKind.Array } element &&
                        OpenIddictHelpers.ValidateArrayElements(element, JsonValueKind.String)),

                // Note: unlike other claims (e.g "aud"), the "amr" claim MUST be represented as a unique
                // claim representing a JSON array, even if a single authentication method reference
                // is present in the collection. To avoid forcing users to use the special JSON_ARRAY
                // value type, string values are also allowed here and normalized to JSON arrays
                // by OpenIddict when generating an identity token based on the specified principal.
                Claims.AuthenticationMethodReference
                    => values.TrueForAll(static value => value.ValueType is ClaimValueTypes.String) ||
                       (values is [{ ValueType: JsonClaimValueTypes.JsonArray, Value: string value }] &&
                        JsonSerializer.Deserialize<JsonElement>(value) is { ValueKind: JsonValueKind.Array } element &&
                        OpenIddictHelpers.ValidateArrayElements(element, JsonValueKind.String)),

                // The following claims MUST be represented as unique integers.
                Claims.Private.AccessTokenLifetime  or Claims.Private.AuthorizationCodeLifetime or
                Claims.Private.DeviceCodeLifetime   or Claims.Private.IdentityTokenLifetime     or
                Claims.Private.RefreshTokenLifetime or Claims.Private.RefreshTokenLifetime      or
                Claims.Private.RequestTokenLifetime
                    => values is [{ ValueType: ClaimValueTypes.Integer   or ClaimValueTypes.Integer32  or
                                               ClaimValueTypes.Integer64 or ClaimValueTypes.UInteger32 or
                                               ClaimValueTypes.UInteger64 }],

                // The following claims MUST be represented as unique numeric dates.
                Claims.AuthenticationTime
                    => values is [{ ValueType: ClaimValueTypes.Integer    or ClaimValueTypes.Integer32 or
                                               ClaimValueTypes.Integer64  or ClaimValueTypes.Double    or
                                               ClaimValueTypes.UInteger32 or ClaimValueTypes.UInteger64 }],

                // Claims that are not in the well-known list can be of any type.
                _ => true
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for redeeming the token entry corresponding to the received token.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class RedeemTokenEntry : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public RedeemTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public RedeemTokenEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .UseScopedHandler<RedeemTokenEntry>()
                // Note: this handler is deliberately executed early in the pipeline to ensure
                // that the token database entry is always marked as redeemed even if the sign-in
                // demand is rejected later in the pipeline (e.g because an error was returned).
                .SetOrder(ValidateSignInDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            switch (context.EndpointType)
            {
                case OpenIddictServerEndpointType.Authorization:
                case OpenIddictServerEndpointType.EndUserVerification:
                case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType() &&
                                                            !context.Options.DisableRollingRefreshTokens:
                    break;

                default: return;
            }

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            var principal = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization => notification.RequestTokenPrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => notification.AuthorizationCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => notification.DeviceCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => notification.RefreshTokenPrincipal,

                OpenIddictServerEndpointType.EndUserVerification => notification.UserCodePrincipal,

                _ => null
            };

            if (principal is null)
            {
                return;
            }

            // Extract the token identifier from the authentication principal.
            // If no token identifier can be found, this indicates that the token has no backing database entry.
            var identifier = principal.GetTokenId();
            if (string.IsNullOrEmpty(identifier))
            {
                return;
            }

            var token = await _tokenManager.FindByIdAsync(identifier);
            if (token is null)
            {
                return;
            }

            // Mark the token as redeemed to prevent future reuses. If the request is a refresh token request, ignore
            // errors returned while trying to mark the entry as redeemed (that may be caused by concurrent requests).
            if (context.EndpointType is OpenIddictServerEndpointType.Token && context.Request.IsRefreshTokenGrantType())
            {
                await _tokenManager.TryRedeemAsync(token);
            }

            else if (!await _tokenManager.TryRedeemAsync(token))
            {
                context.Reject(
                    error: Errors.InvalidToken,
                    description: principal.GetTokenType() switch
                    {
                        TokenTypeHints.AuthorizationCode => SR.GetResourceString(SR.ID2010),
                        TokenTypeHints.DeviceCode        => SR.GetResourceString(SR.ID2011),
                        TokenTypeHints.RefreshToken      => SR.GetResourceString(SR.ID2012),

                        _ => SR.GetResourceString(SR.ID2013)
                    },
                    uri: principal.GetTokenType() switch
                    {
                        TokenTypeHints.AuthorizationCode => SR.FormatID8000(SR.ID2010),
                        TokenTypeHints.DeviceCode        => SR.FormatID8000(SR.ID2011),
                        TokenTypeHints.RefreshToken      => SR.FormatID8000(SR.ID2012),

                        _ => SR.FormatID8000(SR.ID2013)
                    });

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for re-attaching internal claims to the authentication principal.
    /// </summary>
    public sealed class RestoreInternalClaims : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<RestoreInternalClaims>()
                .SetOrder(RedeemTokenEntry.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            switch (context.EndpointType)
            {
                case OpenIddictServerEndpointType.EndUserVerification:
                case OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType():
                case OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType():
                    break;

                default: return default;
            }

            var identity = (ClaimsIdentity) context.Principal.Identity;

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            var principal = context.EndpointType switch
            {
                OpenIddictServerEndpointType.EndUserVerification => notification.UserCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => notification.AuthorizationCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => notification.DeviceCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => notification.RefreshTokenPrincipal,

                _ => null
            };

            if (principal is null)
            {
                return default;
            }

            // Restore the internal claims resolved from the token.
            foreach (var claims in principal.Claims
                .Where(claim => claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                .GroupBy(claim => claim.Type))
            {
                // If the specified principal already contains one claim of the iterated type, ignore them.
                if (context.Principal.Claims.Any(claim => claim.Type == claims.Key))
                {
                    continue;
                }

                // When the request is a end-user verification request, don't flow the scopes from the user code.
                if (context.EndpointType is OpenIddictServerEndpointType.EndUserVerification &&
                    string.Equals(claims.Key, Claims.Private.Scope, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                identity.AddClaims(claims);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the user-defined properties to the authentication principal.
    /// </summary>
    public sealed class AttachHostProperties : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachHostProperties>()
                .SetOrder(RestoreInternalClaims.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            context.Principal.SetClaim(Claims.Private.HostProperties, context.Properties);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching default scopes to the authentication principal.
    /// </summary>
    public sealed class AttachDefaultScopes : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachDefaultScopes>()
                .SetOrder(AttachHostProperties.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Always include the "openid" scope when the developer doesn't explicitly call SetScopes.
            // Note: the application is allowed to specify a different "scopes": in this case,
            // don't replace the "scopes" property stored in the authentication ticket.
            if (!context.Principal.HasClaim(Claims.Private.Scope) && context.Request.HasScope(Scopes.OpenId))
            {
                context.Principal.SetScopes(Scopes.OpenId);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching default presenters to the authentication principal.
    /// </summary>
    public sealed class AttachDefaultPresenters : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachDefaultPresenters>()
                .SetOrder(AttachDefaultScopes.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Add the validated client_id to the list of authorized presenters,
            // unless the presenters were explicitly set by the developer.
            if (!context.Principal.HasClaim(Claims.Private.Presenter) && !string.IsNullOrEmpty(context.ClientId))
            {
                context.Principal.SetPresenters(context.ClientId);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for inferring resources from the audience claims if necessary.
    /// </summary>
    public sealed class InferResources : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<InferResources>()
                .SetOrder(AttachDefaultPresenters.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // When a "resources" property cannot be found in the ticket, infer it from the "audiences" property.
            if (context.Principal.HasClaim(Claims.Private.Audience) &&
               !context.Principal.HasClaim(Claims.Private.Resource))
            {
                context.Principal.SetResources(context.Principal.GetAudiences());
            }

            // Reset the audiences collection, as it's later set, based on the token type.
            context.Principal.SetAudiences(ImmutableArray<string>.Empty);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for selecting the token types that
    /// should be generated and optionally returned in the response.
    /// </summary>
    public sealed class EvaluateGeneratedTokens : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<EvaluateGeneratedTokens>()
                .SetOrder(InferResources.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            (context.GenerateAccessToken, context.IncludeAccessToken) = context.EndpointType switch
            {
                // Never generate an access token if request caching was enabled and the authorization
                // request doesn't already contain a request_uri parameter, as the user agent will be
                // redirected to the authorization endpoint after generating a request token.
                OpenIddictServerEndpointType.Authorization when
                    context.Options.EnableAuthorizationRequestCaching &&
                    string.IsNullOrEmpty(context.Request.RequestUri) => (false, false),

                // For authorization requests, generate and return an access token
                // if a response type containing the "token" value was specified.
                OpenIddictServerEndpointType.Authorization when context.Request.HasResponseType(ResponseTypes.Token)
                    => (true, true),

                // For token requests, always generate and return an access token.
                OpenIddictServerEndpointType.Token => (true, true),

                _ => (false, false)
            };

            (context.GenerateAuthorizationCode, context.IncludeAuthorizationCode) = context.EndpointType switch
            {
                // Never generate an authorization code if request caching was enabled and the authorization
                // request doesn't already contain a request_uri parameter, as the user agent will be
                // redirected to the authorization endpoint after generating a request token.
                OpenIddictServerEndpointType.Authorization when
                    context.Options.EnableAuthorizationRequestCaching &&
                    string.IsNullOrEmpty(context.Request.RequestUri) => (false, false),

                // For authorization requests, generate and return an authorization code
                // if a response type containing the "code" value was specified.
                OpenIddictServerEndpointType.Authorization when context.Request.HasResponseType(ResponseTypes.Code)
                    => (true, true),

                _ => (false, false)
            };

            (context.GenerateDeviceCode, context.IncludeDeviceCode) = context.EndpointType switch
            {
                // For device requests, always generate and return a device code.
                OpenIddictServerEndpointType.DeviceAuthorization => (true, true),

                // Note: a device code is not directly returned by the end-user verification endpoint (that generally
                // returns an empty response or redirects the user agent to another page), but a device code
                // must be generated to replace the payload of the device code initially returned to the client.
                // In this case, the device code is not returned as part of the response but persisted in the DB.
                OpenIddictServerEndpointType.EndUserVerification => (true, false),

                _ => (false, false)
            };

            (context.GenerateIdentityToken, context.IncludeIdentityToken) = context.EndpointType switch
            {
                // Never generate an identity token if request caching was enabled and the authorization
                // request doesn't contain a request_uri parameter, as the user agent will be
                // redirected to the authorization endpoint after generating a request token.
                OpenIddictServerEndpointType.Authorization when
                    context.Options.EnableAuthorizationRequestCaching &&
                    string.IsNullOrEmpty(context.Request.RequestUri) => (false, false),

                // For authorization requests, generate and return an identity token if a response type
                // containing code was specified and if the openid scope was explicitly or implicitly granted.
                OpenIddictServerEndpointType.Authorization when
                    context.Principal.HasScope(Scopes.OpenId) &&
                    context.Request.HasResponseType(ResponseTypes.IdToken) => (true, true),

                // For token requests, only generate and return an identity token if the openid scope was granted.
                OpenIddictServerEndpointType.Token when context.Principal.HasScope(Scopes.OpenId) => (true, true),

                _ => (false, false)
            };

            (context.GenerateRequestToken, context.IncludeRequestToken) = context.EndpointType switch
            {
                // Always generate a request token if request caching was enabled and the
                // authorization request doesn't already contain a request_uri parameter.
                OpenIddictServerEndpointType.Authorization when
                    context.Options.EnableAuthorizationRequestCaching &&
                    string.IsNullOrEmpty(context.Request.RequestUri) => (true, true),

                // Always generate a request token if request caching was enabled and the
                // end session request doesn't already contain a request_uri parameter.
                OpenIddictServerEndpointType.EndSession when
                    context.Options.EnableEndSessionRequestCaching &&
                    string.IsNullOrEmpty(context.Request.RequestUri) => (true, true),

                // Always generate and return a request token if the request is a PAR request.
                OpenIddictServerEndpointType.PushedAuthorization => (true, true),

                _ => (false, false)
            };

            (context.GenerateRefreshToken, context.IncludeRefreshToken) = context.EndpointType switch
            {
                // For token requests, allow a refresh token to be returned
                // if the special offline_access protocol scope was granted.
                OpenIddictServerEndpointType.Token when context.Principal.HasScope(Scopes.OfflineAccess)
                    => (true, true),

                _ => (false, false)
            };

            (context.GenerateUserCode, context.IncludeUserCode) = context.EndpointType switch
            {
                // Only generate and return a user code if the request is a device authorization request.
                OpenIddictServerEndpointType.DeviceAuthorization => (true, true),

                _ => (false, false)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating an ad-hoc authorization, if necessary.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class AttachAuthorization : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager _applicationManager;
        private readonly IOpenIddictAuthorizationManager _authorizationManager;

        public AttachAuthorization() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public AttachAuthorization(
            IOpenIddictApplicationManager applicationManager,
            IOpenIddictAuthorizationManager authorizationManager)
        {
            _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));
            _authorizationManager = authorizationManager ?? throw new ArgumentNullException(nameof(authorizationManager));
        }

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireAuthorizationStorageEnabled>()
                .UseScopedHandler<AttachAuthorization>()
                .SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // If no authorization code, device code or refresh token is returned, don't create an authorization.
            if (!context.GenerateAuthorizationCode && !context.GenerateDeviceCode && !context.GenerateRefreshToken)
            {
                return;
            }

            // If an authorization identifier was explicitly specified, don't create an ad-hoc authorization.
            if (!string.IsNullOrEmpty(context.Principal.GetAuthorizationId()))
            {
                return;
            }

            var descriptor = new OpenIddictAuthorizationDescriptor
            {
                CreationDate =
#if SUPPORTS_TIME_PROVIDER
                    context.Options.TimeProvider?.GetUtcNow() ??
#endif
                    DateTimeOffset.UtcNow,
                Principal = context.Principal,
                Status = Statuses.Valid,
                Subject = context.Principal.GetClaim(Claims.Subject),
                Type = AuthorizationTypes.AdHoc
            };

            descriptor.Scopes.UnionWith(context.Principal.GetScopes());

            // If the client application is known, associate it to the authorization.
            if (!string.IsNullOrEmpty(context.Request.ClientId))
            {
                var application = await _applicationManager.FindByClientIdAsync(context.Request.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                descriptor.ApplicationId = await _applicationManager.GetIdAsync(application);
            }

            var authorization = await _authorizationManager.CreateAsync(descriptor) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0018));

            var identifier = await _authorizationManager.GetIdAsync(authorization);

            if (string.IsNullOrEmpty(context.Request.ClientId))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6007), identifier);
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6008), context.Request.ClientId, identifier);
            }

            // Attach the unique identifier of the ad hoc authorization to the authentication principal
            // so that it is attached to all the derived tokens, allowing batched revocations support.
            context.Principal.SetAuthorizationId(identifier);
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the access token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareAccessTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager? _applicationManager;

        public PrepareAccessTokenPrincipal(IOpenIddictApplicationManager? applicationManager = null)
            => _applicationManager = applicationManager;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireAccessTokenGenerated>()
                .UseScopedHandler<PrepareAccessTokenPrincipal>(static provider =>
                {
                    // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                    // invalid core configuration exceptions are not thrown even if the managers were registered.
                    var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    return options.EnableDegradedMode ?
                        new PrepareAccessTokenPrincipal() :
                        new PrepareAccessTokenPrincipal(provider.GetService<IOpenIddictApplicationManager>() ??
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                })
                .SetOrder(AttachAuthorization.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never exclude the subject and authorization identifier claims.
                if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.AuthorizationId, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Never exclude the presenters and scope private claims.
                if (string.Equals(claim.Type, Claims.Private.Presenter, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.Scope, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Always exclude private claims, whose values must generally be kept secret.
                if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "access_token" are not included in the access token.
                if (!claim.HasDestination(Destinations.AccessToken))
                {
                    context.Logger.LogDebug(SR.GetResourceString(SR.ID6009), claim.Type);

                    return false;
                }

                return true;
            });

            // Remove the destinations from the claim properties.
            foreach (var claim in principal.Claims)
            {
                claim.Properties.Remove(Properties.Destinations);
            }

            principal.SetCreationDate(
#if SUPPORTS_TIME_PROVIDER
                context.Options.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow);

            // If a specific token lifetime was attached to the principal, prefer it over any other value.
            var lifetime = context.Principal.GetAccessTokenLifetime();

            // If the client to which the token is returned is known, use the attached setting if available.
            if (lifetime is null && !context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.ClientId))
            {
                if (_applicationManager is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                var settings = await _applicationManager.GetSettingsAsync(application);
                if (settings.TryGetValue(Settings.TokenLifetimes.AccessToken, out string? setting) &&
                    TimeSpan.TryParse(setting, CultureInfo.InvariantCulture, out var value))
                {
                    lifetime = value;
                }
            }

            // Otherwise, fall back to the global value.
            lifetime ??= context.Options.AccessTokenLifetime;

            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri)?.AbsoluteUri);

            // Set the audiences based on the resource claims stored in the principal.
            principal.SetAudiences(context.Principal.GetResources());

            // Store the client identifier in the public client_id claim, if available.
            // See https://datatracker.ietf.org/doc/html/rfc9068 for more information.
            principal.SetClaim(Claims.ClientId, context.ClientId);

            // When receiving a grant_type=refresh_token request, determine whether the client application
            // requests a limited set of scopes and immediately replace the scopes collection if necessary.
            if (context.EndpointType is OpenIddictServerEndpointType.Token &&
                context.Request.IsRefreshTokenGrantType() && !string.IsNullOrEmpty(context.Request.Scope))
            {
                var scopes = context.Request.GetScopes();
                principal.SetScopes(scopes.Intersect(context.Principal.GetScopes()));

                context.Logger.LogDebug(SR.GetResourceString(SR.ID6010), scopes);
            }

            context.AccessTokenPrincipal = principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the authorization code, if one is going to be returned.
    /// </summary>
    public sealed class PrepareAuthorizationCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager? _applicationManager;

        public PrepareAuthorizationCodePrincipal(IOpenIddictApplicationManager? applicationManager = null)
            => _applicationManager = applicationManager;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireAuthorizationCodeGenerated>()
                .UseScopedHandler<PrepareAuthorizationCodePrincipal>(static provider =>
                {
                    // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                    // invalid core configuration exceptions are not thrown even if the managers were registered.
                    var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    return options.EnableDegradedMode ?
                        new PrepareAuthorizationCodePrincipal() :
                        new PrepareAuthorizationCodePrincipal(provider.GetService<IOpenIddictApplicationManager>() ??
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                })
                .SetOrder(PrepareAccessTokenPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the authorization code, even private claims.
                return true;
            });

            principal.SetCreationDate(
#if SUPPORTS_TIME_PROVIDER
                context.Options.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow);

            // If a specific token lifetime was attached to the principal, prefer it over any other value.
            var lifetime = context.Principal.GetAuthorizationCodeLifetime();

            // If the client to which the token is returned is known, use the attached setting if available.
            if (lifetime is null && !context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.ClientId))
            {
                if (_applicationManager is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                var settings = await _applicationManager.GetSettingsAsync(application);
                if (settings.TryGetValue(Settings.TokenLifetimes.AuthorizationCode, out string? setting) &&
                    TimeSpan.TryParse(setting, CultureInfo.InvariantCulture, out var value))
                {
                    lifetime = value;
                }
            }

            // Otherwise, fall back to the global value.
            lifetime ??= context.Options.AuthorizationCodeLifetime;

            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri)?.AbsoluteUri);

            // Attach the redirect_uri to allow for later comparison when
            // receiving a grant_type=authorization_code token request.
            principal.SetClaim(Claims.Private.RedirectUri, context.Request.RedirectUri);

            // Attach the code challenge and the code challenge methods to allow the ValidateCodeVerifier
            // handler to validate the code verifier sent by the client as part of the token request.
            if (!string.IsNullOrEmpty(context.Request.CodeChallenge))
            {
                principal.SetClaim(Claims.Private.CodeChallenge, context.Request.CodeChallenge);

                // Default to plain if no explicit code challenge method was specified.
                principal.SetClaim(Claims.Private.CodeChallengeMethod,
                    !string.IsNullOrEmpty(context.Request.CodeChallengeMethod) ?
                    context.Request.CodeChallengeMethod : CodeChallengeMethods.Plain);
            }

            // Attach the nonce so that it can be later returned by
            // the token endpoint as part of the JWT identity token.
            principal.SetClaim(Claims.Private.Nonce, context.Request.Nonce);

            context.AuthorizationCodePrincipal = principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the device code, if one is going to be returned.
    /// </summary>
    public sealed class PrepareDeviceCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager? _applicationManager;

        public PrepareDeviceCodePrincipal(IOpenIddictApplicationManager? applicationManager = null)
            => _applicationManager = applicationManager;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDeviceCodeGenerated>()
                .UseScopedHandler<PrepareDeviceCodePrincipal>(static provider =>
                {
                    // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                    // invalid core configuration exceptions are not thrown even if the managers were registered.
                    var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    return options.EnableDegradedMode ?
                        new PrepareDeviceCodePrincipal() :
                        new PrepareDeviceCodePrincipal(provider.GetService<IOpenIddictApplicationManager>() ??
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                })
                .SetOrder(PrepareAuthorizationCodePrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the device code, even private claims.
                return true;
            });

            principal.SetCreationDate(
#if SUPPORTS_TIME_PROVIDER
                context.Options.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow);

            // If a specific token lifetime was attached to the principal, prefer it over any other value.
            var lifetime = context.Principal.GetDeviceCodeLifetime();

            // If the client to which the token is returned is known, use the attached setting if available.
            if (lifetime is null && !context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.ClientId))
            {
                if (_applicationManager is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                var settings = await _applicationManager.GetSettingsAsync(application);
                if (settings.TryGetValue(Settings.TokenLifetimes.DeviceCode, out string? setting) &&
                    TimeSpan.TryParse(setting, CultureInfo.InvariantCulture, out var value))
                {
                    lifetime = value;
                }
            }

            // Otherwise, fall back to the global value.
            lifetime ??= context.Options.DeviceCodeLifetime;

            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri)?.AbsoluteUri);

            // Restore the device code internal token identifier from the principal
            // resolved from the user code used in the end-user verification request.
            if (context.EndpointType is OpenIddictServerEndpointType.EndUserVerification)
            {
                principal.SetClaim(Claims.Private.TokenId, context.Principal.GetClaim(Claims.Private.DeviceCodeId));
            }

            context.DeviceCodePrincipal = principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal used
    /// to generate the request token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareRequestTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager? _applicationManager;

        public PrepareRequestTokenPrincipal(IOpenIddictApplicationManager? applicationManager = null)
            => _applicationManager = applicationManager;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireRequestTokenGenerated>()
                .UseScopedHandler<PrepareRequestTokenPrincipal>(static provider =>
                {
                    // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                    // invalid core configuration exceptions are not thrown even if the managers were registered.
                    var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    return options.EnableDegradedMode ?
                        new PrepareRequestTokenPrincipal() :
                        new PrepareRequestTokenPrincipal(provider.GetService<IOpenIddictApplicationManager>() ??
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                })
                .SetOrder(PrepareDeviceCodePrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the device code, even private claims.
                return true;
            });

            principal.SetCreationDate(
#if SUPPORTS_TIME_PROVIDER
                context.Options.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow);

            // If a specific token lifetime was attached to the principal, prefer it over any other value.
            var lifetime = context.Principal.GetRequestTokenLifetime();

            // If the client to which the token is returned is known, use the attached setting if available.
            if (lifetime is null && !context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.ClientId))
            {
                if (_applicationManager is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                var settings = await _applicationManager.GetSettingsAsync(application);
                if (settings.TryGetValue(Settings.TokenLifetimes.RequestToken, out string? setting) &&
                    TimeSpan.TryParse(setting, CultureInfo.InvariantCulture, out var value))
                {
                    lifetime = value;
                }
            }

            // Otherwise, fall back to the global value.
            lifetime ??= context.Options.RequestTokenLifetime;

            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri)?.AbsoluteUri);

            // Store the type of the request token.
            principal.SetClaim(Claims.Private.RequestTokenType, context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization       => RequestTokenTypes.Private.CachedAuthorizationRequest,
                OpenIddictServerEndpointType.EndSession          => RequestTokenTypes.Private.CachedEndSessionRequest,
                OpenIddictServerEndpointType.PushedAuthorization => RequestTokenTypes.Private.PushedAuthorizationRequest,

                _ => null
            });

            // Store the request parameters as a special JSON object claim.
            //
            // Note: parameters used for client authentication are deliberately filtered out.
            var parameters = from parameter in context.Request.GetParameters()
                             where parameter.Key is not (Parameters.ClientAssertion or
                                                         Parameters.ClientAssertionType or
                                                         Parameters.ClientSecret)
                             select parameter;

            principal.SetClaim(Claims.Private.RequestParameters, JsonSerializer.Deserialize<JsonElement>(
                JsonSerializer.Serialize(new OpenIddictRequest(parameters))));

            context.RequestTokenPrincipal = principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the refresh token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareRefreshTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager? _applicationManager;

        public PrepareRefreshTokenPrincipal(IOpenIddictApplicationManager? applicationManager = null)
            => _applicationManager = applicationManager;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireRefreshTokenGenerated>()
                .UseScopedHandler<PrepareRefreshTokenPrincipal>(static provider =>
                {
                    // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                    // invalid core configuration exceptions are not thrown even if the managers were registered.
                    var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    return options.EnableDegradedMode ?
                        new PrepareRefreshTokenPrincipal() :
                        new PrepareRefreshTokenPrincipal(provider.GetService<IOpenIddictApplicationManager>() ??
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                })
                .SetOrder(PrepareRequestTokenPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the refresh token, even private claims.
                return true;
            });

            principal.SetCreationDate(
#if SUPPORTS_TIME_PROVIDER
                context.Options.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow);

            // When sliding expiration is disabled, the expiration date of generated refresh tokens is fixed
            // and must exactly match the expiration date of the refresh token used in the token request.
            if (context.EndpointType is OpenIddictServerEndpointType.Token &&
                context.Request.IsRefreshTokenGrantType() &&
                context.Options.DisableSlidingRefreshTokenExpiration)
            {
                var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                    typeof(ProcessAuthenticationContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                Debug.Assert(notification.RefreshTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

                principal.SetExpirationDate(notification.RefreshTokenPrincipal.GetExpirationDate());
            }

            else
            {
                // If a specific token lifetime was attached to the principal, prefer it over any other value.
                var lifetime = context.Principal.GetRefreshTokenLifetime();

                // If the client to which the token is returned is known, use the attached setting if available.
                if (lifetime is null && !context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.ClientId))
                {
                    if (_applicationManager is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                    }

                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                    var settings = await _applicationManager.GetSettingsAsync(application);
                    if (settings.TryGetValue(Settings.TokenLifetimes.RefreshToken, out string? setting) &&
                        TimeSpan.TryParse(setting, CultureInfo.InvariantCulture, out var value))
                    {
                        lifetime = value;
                    }
                }

                // Otherwise, fall back to the global value.
                lifetime ??= context.Options.RefreshTokenLifetime;

                if (lifetime.HasValue)
                {
                    principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
                }
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri)?.AbsoluteUri);

            context.RefreshTokenPrincipal = principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the identity token, if one is going to be returned.
    /// </summary>
    public sealed class PrepareIdentityTokenPrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager? _applicationManager;

        public PrepareIdentityTokenPrincipal(IOpenIddictApplicationManager? applicationManager = null)
            => _applicationManager = applicationManager;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireIdentityTokenGenerated>()
                .UseScopedHandler<PrepareIdentityTokenPrincipal>(static provider =>
                {
                    // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                    // invalid core configuration exceptions are not thrown even if the managers were registered.
                    var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    return options.EnableDegradedMode ?
                        new PrepareIdentityTokenPrincipal() :
                        new PrepareIdentityTokenPrincipal(provider.GetService<IOpenIddictApplicationManager>() ??
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                })
                .SetOrder(PrepareRefreshTokenPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Replace the principal by a new one containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never exclude the subject and authorization identifier claims.
                if (string.Equals(claim.Type, Claims.Subject, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.AuthorizationId, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }

                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Always exclude private claims by default, whose values must generally be kept secret.
                if (claim.Type.StartsWith(Claims.Prefixes.Private, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Claims whose destination is not explicitly referenced or doesn't
                // contain "id_token" are not included in the identity token.
                if (!claim.HasDestination(Destinations.IdentityToken))
                {
                    context.Logger.LogDebug(SR.GetResourceString(SR.ID6011), claim.Type);

                    return false;
                }

                return true;
            });

            // Remove the destinations from the claim properties.
            foreach (var claim in principal.Claims)
            {
                claim.Properties.Remove(Properties.Destinations);
            }

            principal.SetCreationDate(
#if SUPPORTS_TIME_PROVIDER
                context.Options.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow);

            // If a specific token lifetime was attached to the principal, prefer it over any other value.
            var lifetime = context.Principal.GetIdentityTokenLifetime();

            // If the client to which the token is returned is known, use the attached setting if available.
            if (lifetime is null && !context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.ClientId))
            {
                if (_applicationManager is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                var settings = await _applicationManager.GetSettingsAsync(application);
                if (settings.TryGetValue(Settings.TokenLifetimes.IdentityToken, out string? setting) &&
                    TimeSpan.TryParse(setting, CultureInfo.InvariantCulture, out var value))
                {
                    lifetime = value;
                }
            }

            // Otherwise, fall back to the global value.
            lifetime ??= context.Options.IdentityTokenLifetime;

            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri)?.AbsoluteUri);

            // If available, use the client_id as both the audience and the authorized party.
            // See https://openid.net/specs/openid-connect-core-1_0.html#IDToken for more information.
            if (!string.IsNullOrEmpty(context.ClientId))
            {
                principal.SetAudiences(context.ClientId);
                principal.SetClaim(Claims.AuthorizedParty, context.ClientId);
            }

            // If a nonce was present in the authorization request, it MUST be included in the id_token generated
            // by the token endpoint. For that, OpenIddict simply flows the nonce as an authorization code claim.
            // See http://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation for more information.
            principal.SetClaim(Claims.Nonce, context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or
                OpenIddictServerEndpointType.PushedAuthorization => context.Request.Nonce,

                OpenIddictServerEndpointType.Token => context.Principal.GetClaim(Claims.Private.Nonce),

                _ => null
            });

            context.IdentityTokenPrincipal = principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for preparing and attaching the claims principal
    /// used to generate the user code, if one is going to be returned.
    /// </summary>
    public sealed class PrepareUserCodePrincipal : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictApplicationManager? _applicationManager;

        public PrepareUserCodePrincipal(IOpenIddictApplicationManager? applicationManager = null)
            => _applicationManager = applicationManager;

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireUserCodeGenerated>()
                .UseScopedHandler<PrepareUserCodePrincipal>(static provider =>
                {
                    // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                    // invalid core configuration exceptions are not thrown even if the managers were registered.
                    var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                    return options.EnableDegradedMode ?
                        new PrepareUserCodePrincipal() :
                        new PrepareUserCodePrincipal(provider.GetService<IOpenIddictApplicationManager>() ??
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                })
                .SetOrder(PrepareIdentityTokenPrincipal.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // Create a new principal containing only the filtered claims.
            // Actors identities are also filtered (delegation scenarios).
            var principal = context.Principal.Clone(claim =>
            {
                // Never include the public or internal token identifiers to ensure the identifiers
                // that are automatically inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.JwtId, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.Private.TokenId, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Never include the creation and expiration dates that are automatically
                // inherited from the parent token are not reused for the new token.
                if (string.Equals(claim.Type, Claims.ExpiresAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.IssuedAt, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(claim.Type, Claims.NotBefore, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                // Other claims are always included in the authorization code, even private claims.
                return true;
            });

            principal.SetCreationDate(
#if SUPPORTS_TIME_PROVIDER
                context.Options.TimeProvider?.GetUtcNow() ??
#endif
                DateTimeOffset.UtcNow);

            // If a specific token lifetime was attached to the principal, prefer it over any other value.
            var lifetime = context.Principal.GetUserCodeLifetime();

            // If the client to which the token is returned is known, use the attached setting if available.
            if (lifetime is null && !context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.ClientId))
            {
                if (_applicationManager is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                }

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0017));

                var settings = await _applicationManager.GetSettingsAsync(application);
                if (settings.TryGetValue(Settings.TokenLifetimes.UserCode, out string? setting) &&
                    TimeSpan.TryParse(setting, CultureInfo.InvariantCulture, out var value))
                {
                    lifetime = value;
                }
            }

            // Otherwise, fall back to the global value.
            lifetime ??= context.Options.UserCodeLifetime;

            if (lifetime.HasValue)
            {
                principal.SetExpirationDate(principal.GetCreationDate() + lifetime.Value);
            }

            // Use the server identity as the token issuer.
            principal.SetClaim(Claims.Private.Issuer, (context.Options.Issuer ?? context.BaseUri)?.AbsoluteUri);

            // Store the client_id as a public client_id claim.
            principal.SetClaim(Claims.ClientId, context.Request.ClientId);

            context.UserCodePrincipal = principal;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating an access token for the current sign-in operation.
    /// </summary>
    public sealed class GenerateAccessToken : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateAccessToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireAccessTokenGenerated>()
                .UseScopedHandler<GenerateAccessToken>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                // Access tokens can be converted to reference tokens if the
                // corresponding option was enabled in the server options.
                IsReferenceToken = context.Options.UseReferenceAccessTokens,
                PersistTokenPayload = context.Options.UseReferenceAccessTokens,
                Principal = context.AccessTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.AccessToken
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.AccessToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating an authorization code for the current sign-in operation.
    /// </summary>
    public sealed class GenerateAuthorizationCode : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateAuthorizationCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireAuthorizationCodeGenerated>()
                .UseScopedHandler<GenerateAuthorizationCode>()
                .SetOrder(GenerateAccessToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                IsReferenceToken = !context.Options.DisableTokenStorage,
                PersistTokenPayload = !context.Options.DisableTokenStorage,
                Principal = context.AuthorizationCodePrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.AuthorizationCode
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.AuthorizationCode = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a device code for the current sign-in operation.
    /// </summary>
    public sealed class GenerateDeviceCode : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateDeviceCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDeviceCodeGenerated>()
                .UseScopedHandler<GenerateDeviceCode>()
                .SetOrder(GenerateAuthorizationCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                // Don't create a new entry if the device code is generated as part
                // of a device code swap made by the end-user verification endpoint.
                CreateTokenEntry = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.EndUserVerification => false,

                    _ => !context.Options.DisableTokenStorage
                },
                IsReferenceToken = !context.Options.DisableTokenStorage,
                // Device codes are not persisted using the generic logic if they are generated
                // as part of a device code swap made by the end-user verification endpoint.
                PersistTokenPayload = context.EndpointType switch
                {
                    OpenIddictServerEndpointType.EndUserVerification => false,

                    _ => !context.Options.DisableTokenStorage
                },
                Principal = context.DeviceCodePrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.DeviceCode
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.DeviceCode = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a request token for the current sign-in operation.
    /// </summary>
    public sealed class GenerateRequestToken : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateRequestToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireRequestTokenGenerated>()
                .UseScopedHandler<GenerateRequestToken>()
                .SetOrder(GenerateDeviceCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                PersistTokenPayload = !context.Options.DisableTokenStorage,
                IsReferenceToken = !context.Options.DisableTokenStorage,
                Principal = context.RequestTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.Private.RequestToken
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.RequestToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a refresh token for the current sign-in operation.
    /// </summary>
    public sealed class GenerateRefreshToken : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateRefreshToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireRefreshTokenGenerated>()
                .UseScopedHandler<GenerateRefreshToken>()
                .SetOrder(GenerateRequestToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                // Refresh tokens can be converted to reference tokens if the
                // corresponding option was enabled in the server options.
                IsReferenceToken = context.Options.UseReferenceRefreshTokens,
                PersistTokenPayload = context.Options.UseReferenceRefreshTokens,
                Principal = context.RefreshTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.RefreshToken
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.RefreshToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating and attaching the device code identifier to the user code principal.
    /// </summary>
    public sealed class AttachDeviceCodeIdentifier : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDeviceCodeGenerated>()
                .AddFilter<RequireUserCodeGenerated>()
                .UseSingletonHandler<AttachDeviceCodeIdentifier>()
                .SetOrder(GenerateRefreshToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.UserCodePrincipal is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0020));
            }

            var identifier = context.DeviceCodePrincipal?.GetTokenId();
            if (!string.IsNullOrEmpty(identifier))
            {
                context.UserCodePrincipal.SetClaim(Claims.Private.DeviceCodeId, identifier);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for updating the existing reference device code entry.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class UpdateReferenceDeviceCodeEntry : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public UpdateReferenceDeviceCodeEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public UpdateReferenceDeviceCodeEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .AddFilter<RequireDeviceCodeGenerated>()
                .UseScopedHandler<UpdateReferenceDeviceCodeEntry>()
                .SetOrder(AttachDeviceCodeIdentifier.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictServerEndpointType.EndUserVerification ||
                string.IsNullOrEmpty(context.DeviceCode))
            {
                return;
            }

            Debug.Assert(context.Principal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            if (context.DeviceCodePrincipal is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0020));
            }

            // Extract the device code identifier from the user code principal.
            var identifier = context.Principal.GetClaim(Claims.Private.DeviceCodeId);
            if (string.IsNullOrEmpty(identifier))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0008));
            }

            var token = await _tokenManager.FindByIdAsync(identifier) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0265));

            // Replace the device code details by the payload derived from the new device code principal,
            // that includes all the user claims populated by the application after authenticating the user.
            var descriptor = new OpenIddictTokenDescriptor();
            await _tokenManager.PopulateAsync(descriptor, token);

            // Note: the lifetime is deliberately extended to give more time to the client to redeem the code.
            descriptor.ExpirationDate = context.DeviceCodePrincipal.GetExpirationDate();
            descriptor.Payload = context.DeviceCode;
            descriptor.Principal = context.DeviceCodePrincipal;
            descriptor.Status = Statuses.Valid;
            descriptor.Subject = context.DeviceCodePrincipal.GetClaim(Claims.Subject);

            await _tokenManager.UpdateAsync(token, descriptor);

            context.Logger.LogTrace(SR.GetResourceString(SR.ID6021), await _tokenManager.GetIdAsync(token));
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating and attaching the hashes of
    /// the access token and authorization code to the identity token principal.
    /// </summary>
    public sealed class AttachTokenDigests : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireIdentityTokenGenerated>()
                .UseSingletonHandler<AttachTokenDigests>()
                .SetOrder(UpdateReferenceDeviceCodeEntry.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.IdentityTokenPrincipal is null)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0022));
            }

            if (string.IsNullOrEmpty(context.AccessToken) && string.IsNullOrEmpty(context.AuthorizationCode))
            {
                return default;
            }

            var credentials = context.Options.SigningCredentials.Find(
                credentials => credentials.Key is AsymmetricSecurityKey) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0266));

            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                var digest = ComputeTokenHash(credentials, context.AccessToken);

                // Note: only the left-most half of the hash is used.
                // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
                context.IdentityTokenPrincipal.SetClaim(Claims.AccessTokenHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
            }

            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                var digest = ComputeTokenHash(credentials, context.AuthorizationCode);

                // Note: only the left-most half of the hash is used.
                // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                context.IdentityTokenPrincipal.SetClaim(Claims.CodeHash, Base64UrlEncoder.Encode(digest, 0, digest.Length / 2));
            }

            return default;

            static byte[] ComputeTokenHash(SigningCredentials credentials, string token) => credentials switch
            {
                // Note: ASCII is deliberately used here, as it's the encoding required by the specification.
                // For more information, see https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken.

                { Digest:    SecurityAlgorithms.Sha256          or SecurityAlgorithms.Sha256Digest             } or
                { Algorithm: SecurityAlgorithms.EcdsaSha256     or SecurityAlgorithms.EcdsaSha256Signature     } or
                { Algorithm: SecurityAlgorithms.HmacSha256      or SecurityAlgorithms.HmacSha256Signature      } or
                { Algorithm: SecurityAlgorithms.RsaSha256       or SecurityAlgorithms.RsaSha256Signature       } or
                { Algorithm: SecurityAlgorithms.RsaSsaPssSha256 or SecurityAlgorithms.RsaSsaPssSha256Signature }
                    => OpenIddictHelpers.ComputeSha256Hash(Encoding.ASCII.GetBytes(token)),

                { Digest:    SecurityAlgorithms.Sha384          or SecurityAlgorithms.Sha384Digest             } or
                { Algorithm: SecurityAlgorithms.EcdsaSha384     or SecurityAlgorithms.EcdsaSha384Signature     } or
                { Algorithm: SecurityAlgorithms.HmacSha384      or SecurityAlgorithms.HmacSha384Signature      } or
                { Algorithm: SecurityAlgorithms.RsaSha384       or SecurityAlgorithms.RsaSha384Signature       } or
                { Algorithm: SecurityAlgorithms.RsaSsaPssSha384 or SecurityAlgorithms.RsaSsaPssSha384Signature }
                    => OpenIddictHelpers.ComputeSha384Hash(Encoding.ASCII.GetBytes(token)),

                { Digest:    SecurityAlgorithms.Sha512          or SecurityAlgorithms.Sha512Digest             } or
                { Algorithm: SecurityAlgorithms.EcdsaSha512     or SecurityAlgorithms.EcdsaSha512Signature     } or
                { Algorithm: SecurityAlgorithms.HmacSha512      or SecurityAlgorithms.HmacSha512Signature      } or
                { Algorithm: SecurityAlgorithms.RsaSha512       or SecurityAlgorithms.RsaSha512Signature       } or
                { Algorithm: SecurityAlgorithms.RsaSsaPssSha512 or SecurityAlgorithms.RsaSsaPssSha512Signature }
                    => OpenIddictHelpers.ComputeSha512Hash(Encoding.ASCII.GetBytes(token)),

                _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0267))
            };
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating a user code for the current sign-in operation.
    /// </summary>
    public sealed class GenerateUserCode : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateUserCode(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireUserCodeGenerated>()
                .UseScopedHandler<GenerateUserCode>()
                .SetOrder(AttachTokenDigests.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                PersistTokenPayload = !context.Options.DisableTokenStorage,
                IsReferenceToken = !context.Options.DisableTokenStorage,
                Principal = context.UserCodePrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.UserCode
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.UserCode = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for generating an identity token for the current sign-in operation.
    /// </summary>
    public sealed class GenerateIdentityToken : IOpenIddictServerHandler<ProcessSignInContext>
    {
        private readonly IOpenIddictServerDispatcher _dispatcher;

        public GenerateIdentityToken(IOpenIddictServerDispatcher dispatcher)
            => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireIdentityTokenGenerated>()
                .UseScopedHandler<GenerateIdentityToken>()
                .SetOrder(GenerateUserCode.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = new GenerateTokenContext(context.Transaction)
            {
                ClientId = context.ClientId,
                CreateTokenEntry = !context.Options.DisableTokenStorage,
                // Identity tokens cannot be reference tokens.
                IsReferenceToken = false,
                PersistTokenPayload = false,
                Principal = context.IdentityTokenPrincipal!,
                TokenFormat = TokenFormats.Jwt,
                TokenType = TokenTypeHints.IdToken
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                context.HandleRequest();
                return;
            }

            else if (notification.IsRequestSkipped)
            {
                context.SkipRequest();
                return;
            }

            else if (notification.IsRejected)
            {
                context.Reject(
                    error: notification.Error ?? Errors.InvalidRequest,
                    description: notification.ErrorDescription,
                    uri: notification.ErrorUri);
                return;
            }

            context.IdentityToken = notification.Token;
        }
    }

    /// <summary>
    /// Contains the logic responsible for beautifying user-typed tokens.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class BeautifyGeneratedTokens : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<BeautifyGeneratedTokens>()
                .SetOrder(GenerateIdentityToken.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // To make user codes easier to read and type by humans, the user is formatted
            // using a display format string specified by the user or created by OpenIddict
            // (by default, grouping the user code characters and separating them by dashes).
            if (!string.IsNullOrEmpty(context.UserCode) &&
                !string.IsNullOrEmpty(context.Options.UserCodeDisplayFormat))
            {
                List<string> arguments = [];

                var enumerator = StringInfo.GetTextElementEnumerator(context.UserCode);
                while (enumerator.MoveNext())
                {
                    arguments.Add(enumerator.GetTextElement());
                }

                if (arguments.Count == context.Options.UserCodeLength)
                {
                    try
                    {
                        context.UserCode = string.Format(CultureInfo.InvariantCulture,
                            context.Options.UserCodeDisplayFormat, [.. arguments]);
                    }

                    catch (FormatException)
                    {
                        context.UserCode = string.Join(string.Empty, arguments);
                    }
                }

                else
                {
                    context.UserCode = string.Join(string.Empty, arguments);
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate parameters to the sign-in response.
    /// </summary>
    public sealed class AttachSignInParameters : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachSignInParameters>()
                .SetOrder(BeautifyGeneratedTokens.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.IncludeAccessToken)
            {
                context.Response.AccessToken = context.AccessToken;
                context.Response.TokenType = TokenTypes.Bearer;

                // If the principal is available, attach additional metadata.
                if (context.AccessTokenPrincipal is not null)
                {
                    // If an expiration date was set on the access token principal, return it to the client application.
                    if (context.AccessTokenPrincipal.GetExpirationDate()
                        is DateTimeOffset date && date > (
#if SUPPORTS_TIME_PROVIDER
                        context.Options.TimeProvider?.GetUtcNow() ??
#endif
                        DateTimeOffset.UtcNow))
                    {
                        context.Response.ExpiresIn = (long) ((date - (
#if SUPPORTS_TIME_PROVIDER
                        context.Options.TimeProvider?.GetUtcNow() ??
#endif
                        DateTimeOffset.UtcNow)).TotalSeconds + .5);
                    }

                    // If the granted access token scopes differ from the requested scopes, return the granted scopes
                    // list as a parameter to inform the client application of the fact the scopes set will be reduced.
                    var scopes = context.AccessTokenPrincipal.GetScopes().ToHashSet(StringComparer.Ordinal);
                    if ((context.EndpointType is OpenIddictServerEndpointType.Token &&
                         context.Request.IsAuthorizationCodeGrantType()) ||
                        !scopes.SetEquals(context.Request.GetScopes()))
                    {
                        context.Response.Scope = string.Join(" ", scopes);
                    }
                }
            }

            if (context.IncludeAuthorizationCode)
            {
                context.Response.Code = context.AuthorizationCode;
            }

            if (context.IncludeDeviceCode)
            {
                context.Response.DeviceCode = context.DeviceCode;
            }

            if (context.IncludeIdentityToken)
            {
                context.Response.IdToken = context.IdentityToken;
            }

            if (context.IncludeRequestToken)
            {
                if (context.EndpointType is OpenIddictServerEndpointType.Authorization or
                                            OpenIddictServerEndpointType.EndSession)
                {
                    context.Response[Parameters.ClientId] = context.Request.ClientId;
                }

                context.Response.RequestUri = RequestUris.Prefixes.Generic + context.RequestToken;
            }

            if (context.IncludeRefreshToken)
            {
                context.Response.RefreshToken = context.RefreshToken;
            }

            if (context.IncludeUserCode)
            {
                context.Response.UserCode = context.UserCode;
            }

            if (context.EndpointType is OpenIddictServerEndpointType.DeviceAuthorization)
            {
                var uri = OpenIddictHelpers.CreateAbsoluteUri(
                    left : context.BaseUri ?? throw new InvalidOperationException(SR.GetResourceString(SR.ID0127)),
                    right: context.Options.EndUserVerificationEndpointUris.First());

                context.Response.VerificationUri = uri.AbsoluteUri;

                if (!string.IsNullOrEmpty(context.UserCode))
                {
                    // Build the "verification_uri_complete" parameter using the end-user verification endpoint URI
                    // with the generated user code appended to the query string as a unique parameter.
                    context.Response.VerificationUriComplete = OpenIddictHelpers.AddQueryStringParameter(
                        uri, Parameters.UserCode, context.UserCode).AbsoluteUri;
                }

                context.Response.ExpiresIn = (
                    context.DeviceCodePrincipal?.GetExpirationDate() ??
                    context.UserCodePrincipal?.GetExpirationDate()) switch
                {
                    // If an expiration date was set on the device code or user
                    // code principal, return it to the client application.
                    DateTimeOffset date when date > (
#if SUPPORTS_TIME_PROVIDER
                        context.Options.TimeProvider?.GetUtcNow() ??
#endif
                        DateTimeOffset.UtcNow)
                        => (long) ((date - (
#if SUPPORTS_TIME_PROVIDER
                        context.Options.TimeProvider?.GetUtcNow() ??
#endif
                        DateTimeOffset.UtcNow)).TotalSeconds + .5),

                    // Otherwise, return an arbitrary value, as the "expires_in"
                    // parameter is required in device authorization responses.
                    _ => 5 * 60 // 5 minutes, in seconds.
                };
            }

            else if (context.EndpointType is OpenIddictServerEndpointType.PushedAuthorization)
            {
                context.Response.ExpiresIn = context.RequestTokenPrincipal?.GetExpirationDate() switch
                {
                    // If an expiration date was set on the pushed authorization
                    // request token principal, return it to the client application.
                    DateTimeOffset date when date > (
#if SUPPORTS_TIME_PROVIDER
                        context.Options.TimeProvider?.GetUtcNow() ??
#endif
                        DateTimeOffset.UtcNow)
                        => (long) ((date - (
#if SUPPORTS_TIME_PROVIDER
                        context.Options.TimeProvider?.GetUtcNow() ??
#endif
                        DateTimeOffset.UtcNow)).TotalSeconds + .5),

                    // Otherwise, return an arbitrary value, as the "expires_in"
                    // parameter is required in pushed authorization responses.
                    _ => 5 * 60 // 5 minutes, in seconds.
                };
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the sign-in response.
    /// </summary>
    public sealed class AttachCustomSignInParameters : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .UseSingletonHandler<AttachCustomSignInParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for ensuring that the sign-out demand
    /// is compatible with the type of the endpoint that handled the request.
    /// </summary>
    public sealed class ValidateSignOutDemand : IOpenIddictServerHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<ValidateSignOutDemand>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.EndpointType is not OpenIddictServerEndpointType.EndSession)
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0024));
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for redeeming the token entry corresponding to the received token.
    /// Note: this handler is not used when the degraded mode is enabled.
    /// </summary>
    public sealed class RedeemLogoutTokenEntry : IOpenIddictServerHandler<ProcessSignOutContext>
    {
        private readonly IOpenIddictTokenManager _tokenManager;

        public RedeemLogoutTokenEntry() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

        public RedeemLogoutTokenEntry(IOpenIddictTokenManager tokenManager)
            => _tokenManager = tokenManager ?? throw new ArgumentNullException(nameof(tokenManager));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireEndSessionRequest>()
                .AddFilter<RequireDegradedModeDisabled>()
                .AddFilter<RequireTokenStorageEnabled>()
                .UseScopedHandler<RedeemLogoutTokenEntry>()
                // Note: this handler is deliberately executed early in the pipeline to ensure
                // that the token database entry is always marked as redeemed even if the sign-out
                // demand is rejected later in the pipeline (e.g because an error was returned).
                .SetOrder(ValidateSignOutDemand.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var notification = context.Transaction.GetProperty<ProcessAuthenticationContext>(
                typeof(ProcessAuthenticationContext).FullName!) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

            var principal = notification.RequestTokenPrincipal;
            if (principal is null)
            {
                return;
            }

            // Extract the token identifier from the authentication principal.
            // If no token identifier can be found, this indicates that the token has no backing database entry.
            var identifier = principal.GetTokenId();
            if (string.IsNullOrEmpty(identifier))
            {
                return;
            }

            var token = await _tokenManager.FindByIdAsync(identifier);
            if (token is null)
            {
                return;
            }

            // Mark the token as redeemed to prevent future reuses.
            await _tokenManager.TryRedeemAsync(token);
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the sign-out response.
    /// </summary>
    public sealed class AttachCustomSignOutParameters : IOpenIddictServerHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .UseSingletonHandler<AttachCustomSignOutParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate parameters to the error response.
    /// </summary>
    public sealed class AttachErrorParameters : IOpenIddictServerHandler<ProcessErrorContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .UseSingletonHandler<AttachErrorParameters>()
                .SetOrder(int.MinValue + 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessErrorContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Response.Error = context.Error;
            context.Response.ErrorDescription = context.ErrorDescription;
            context.Response.ErrorUri = context.ErrorUri;

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the parameters
    /// populated from user-defined handlers to the error response.
    /// </summary>
    public sealed class AttachCustomErrorParameters : IOpenIddictServerHandler<ProcessErrorContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessErrorContext>()
                .UseSingletonHandler<AttachCustomErrorParameters>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessErrorContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.Parameters.Count > 0)
            {
                foreach (var parameter in context.Parameters)
                {
                    context.Response.SetParameter(parameter.Key, parameter.Value);
                }
            }

            return default;
        }
    }
}

﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using OpenIddict.Extensions;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = [
        /*
         * Authentication processing:
         */
        ValidateRedirectionRequestSignature.Descriptor,
        HandleNonStandardFrontchannelErrorResponse.Descriptor,
        ValidateNonStandardParameters.Descriptor,
        OverrideTokenEndpoint.Descriptor,
        AttachNonStandardClientAssertionClaims.Descriptor,
        AttachTokenRequestNonStandardClientCredentials.Descriptor,
        AdjustRedirectUriInTokenRequest.Descriptor,
        OverrideValidatedBackchannelTokens.Descriptor,
        DisableBackchannelIdentityTokenNonceValidation.Descriptor,
        OverrideUserinfoEndpoint.Descriptor,
        DisableUserinfoRetrieval.Descriptor,
        DisableUserinfoValidation.Descriptor,
        AttachAdditionalUserinfoRequestParameters.Descriptor,
        PopulateUserinfoTokenPrincipalFromTokenResponse.Descriptor,
        MapCustomWebServicesFederationClaims.Descriptor,

        /*
         * Challenge processing:
         */
        ValidateChallengeProperties.Descriptor,
        OverrideAuthorizationEndpoint.Descriptor,
        OverrideResponseMode.Descriptor,
        FormatNonStandardScopeParameter.Descriptor,
        IncludeStateParameterInRedirectUri.Descriptor,
        AttachAdditionalChallengeParameters.Descriptor,

        ..Authentication.DefaultHandlers,
        ..Device.DefaultHandlers,
        ..Discovery.DefaultHandlers,
        ..Exchange.DefaultHandlers,
        ..Protection.DefaultHandlers,
        ..Userinfo.DefaultHandlers
    ];

    /// <summary>
    /// Contains the logic responsible for validating the signature or message authentication
    /// code attached to the redirection request for the providers that require it.
    /// </summary>
    public sealed class ValidateRedirectionRequestSignature : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .UseSingletonHandler<ValidateRedirectionRequestSignature>()
                .SetOrder(ValidateIssuerParameter.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Shopify returns custom/non-standard parameters like the name of the shop for which the
            // installation request was initiated. To prevent these parameters from being tampered with,
            // a "hmac" parameter is added by Shopify alongside a "timestamp" parameter containing the
            // UNIX-formatted date at which the authorization response was generated. While this doesn't
            // by itself protect against replayed HMACs, the HMAC always includes the "state" parameter,
            // which is itself protected against replay attacks as state tokens are automatically marked
            // as redeemed by OpenIddict when they are returned to the redirection endpoint.
            //
            // For more information, see
            // https://shopify.dev/docs/apps/auth/oauth/getting-started#step-2-verify-the-installation-request.
            if (context.Registration.ProviderType is ProviderTypes.Shopify &&
                !string.IsNullOrEmpty(context.Registration.ClientSecret))
            {
                var signature = (string?) context.Request["hmac"];
                if (string.IsNullOrEmpty(signature))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029("hmac"),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                var builder = new StringBuilder();

                // Note: the "hmac" parameter MUST be ignored and the remaining parameters MUST be sorted alphabetically.
                //
                // See https://shopify.dev/docs/apps/auth/oauth/getting-started#remove-the-hmac-parameter-from-the-query-string
                // for more information.
                foreach (var (name, value) in
                    from parameter in OpenIddictHelpers.ParseQuery(context.RequestUri!.Query)
                    where !string.IsNullOrEmpty(parameter.Key)
                    where !string.Equals(parameter.Key, "hmac", StringComparison.Ordinal)
                    orderby parameter.Key ascending
                    from value in parameter.Value
                    select (Name: parameter.Key, Value: value))
                {
                    if (builder.Length > 0)
                    {
                        builder.Append('&');
                    }

                    builder.Append(Uri.EscapeDataString(name));

                    if (!string.IsNullOrEmpty(value))
                    {
                        builder.Append('=');
                        builder.Append(Uri.EscapeDataString(value));
                    }
                }

                // Compare the received HMAC (represented as an hexadecimal string) and the HMAC computed
                // locally from the concatenated query string: if the two don't match, return an error.
                //
                // Note: to prevent timing attacks, a time-constant comparer is always used.
                try
                {
                    if (!OpenIddictHelpers.FixedTimeEquals(
                        left : OpenIddictHelpers.ConvertFromHexadecimalString(signature),
                        right: OpenIddictHelpers.ComputeSha256MessageAuthenticationCode(
                            key : Encoding.UTF8.GetBytes(context.Registration.ClientSecret),
                            data: Encoding.UTF8.GetBytes(builder.ToString()))))
                    {
                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2052("hmac"),
                            uri: SR.FormatID8000(SR.ID2052));

                        return default;
                    }
                }

                catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2052("hmac"),
                        uri: SR.FormatID8000(SR.ID2052));

                    return default;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for handling non-standard
    /// authorization errors for the providers that require it.
    /// </summary>
    public sealed class HandleNonStandardFrontchannelErrorResponse : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .UseSingletonHandler<HandleNonStandardFrontchannelErrorResponse>()
                .SetOrder(HandleFrontchannelErrorResponse.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: some providers are known to return non-standard errors.
            // To normalize the set of errors handled by the OpenIddict client,
            // the non-standard errors are mapped to their standard equivalent.
            //
            // Errors that are not handled here will be automatically handled
            // by the standard handler present in the core OpenIddict client.

            if (context.Registration.ProviderType is ProviderTypes.Deezer)
            {
                // Note: Deezer uses a custom "error_reason" parameter instead of the
                // standard "error" parameter defined by the OAuth 2.0 specification.
                //
                // See https://developers.deezer.com/api/oauth for more information.
                var error = (string?) context.Request["error_reason"];
                if (string.Equals(error, "user_denied", StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.AccessDenied,
                        description: SR.GetResourceString(SR.ID2149),
                        uri: SR.FormatID8000(SR.ID2149));

                    return default;
                }
            }

            else if (context.Registration.ProviderType is ProviderTypes.LinkedIn)
            {
                var error = (string?) context.Request[Parameters.Error];
                if (string.Equals(error, "user_cancelled_authorize", StringComparison.Ordinal) ||
                    string.Equals(error, "user_cancelled_login", StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.AccessDenied,
                        description: SR.GetResourceString(SR.ID2149),
                        uri: SR.FormatID8000(SR.ID2149));

                    return default;
                }
            }

            else if (context.Registration.ProviderType is ProviderTypes.Mixcloud)
            {
                var error = (string?) context.Request[Parameters.Error];
                if (string.Equals(error, "user_denied", StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.AccessDenied,
                        description: SR.GetResourceString(SR.ID2149),
                        uri: SR.FormatID8000(SR.ID2149));

                    return default;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating custom parameters for the providers that require it.
    /// </summary>
    public sealed class ValidateNonStandardParameters : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireRedirectionRequest>()
                .AddFilter<RequireStateTokenPrincipal>()
                .AddFilter<RequireStateTokenValidated>()
                .UseSingletonHandler<ValidateNonStandardParameters>()
                .SetOrder(ResolveGrantTypeAndResponseTypeFromStateToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.StateTokenPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            if (context.Registration.ProviderType is ProviderTypes.Shopify)
            {
                var domain = (string?) context.Request["shop"];
                if (string.IsNullOrEmpty(domain))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2029("shop"),
                        uri: SR.FormatID8000(SR.ID2029));

                    return default;
                }

                // Resolve the shop name from the authentication properties stored in the state token principal.
                if (context.StateTokenPrincipal.FindFirst(Claims.Private.HostProperties)?.Value is not string value ||
                    JsonSerializer.Deserialize<JsonElement>(value) is not { ValueKind: JsonValueKind.Object } properties ||
                    !properties.TryGetProperty(Shopify.Properties.ShopName, out JsonElement name))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0412));
                }

                // Note: the shop domain extracted from the redirection request is not used by OpenIddict (that stores
                // the shop name in the state token, but it can be resolved and used by the developers in their own code.
                //
                // To ensure the value is correct, it is compared to the shop name stored in the state token: if
                // the two don't match, the request is automatically rejected to prevent a potential mixup attack.
                if (!string.Equals(domain, $"{name}.myshopify.com", StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2052("shop"),
                        uri: SR.FormatID8000(SR.ID2052));

                    return default;
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the address
    /// of the token endpoint for the providers that require it.
    /// </summary>
    public sealed class OverrideTokenEndpoint : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<OverrideTokenEndpoint>()
                .SetOrder(ResolveTokenEndpoint.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.TokenEndpoint = context.Registration.ProviderType switch
            {
                // Shopify is a multitenant provider that requires setting the token endpoint dynamically
                // based on the shop name stored in the authentication properties set during the challenge.
                //
                // For more information, see
                // https://shopify.dev/docs/apps/auth/oauth/getting-started#step-5-get-an-access-token.
                ProviderTypes.Shopify when context.GrantType is GrantTypes.AuthorizationCode =>
                    context.StateTokenPrincipal is ClaimsPrincipal principal &&
                    principal.FindFirst(Claims.Private.HostProperties)?.Value is string value &&
                    JsonSerializer.Deserialize<JsonElement>(value) is { ValueKind: JsonValueKind.Object } properties &&
                    properties.TryGetProperty(Shopify.Properties.ShopName, out JsonElement name) ?
                    new Uri($"https://{name}.myshopify.com/admin/oauth/access_token", UriKind.Absolute) :
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0412)),

                // Trovo uses a different token endpoint for the refresh token grant.
                //
                // For more information, see
                // https://developer.trovo.live/docs/APIs.html#_4-3-refresh-access-token.
                ProviderTypes.Trovo when context.GrantType is GrantTypes.RefreshToken
                    => new Uri("https://open-api.trovo.live/openplatform/refreshtoken", UriKind.Absolute),

                _ => context.TokenEndpoint
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for amending the client
    /// assertion methods for the providers that require it.
    /// </summary>
    public sealed class AttachNonStandardClientAssertionClaims : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireClientAssertionGenerated>()
                .UseSingletonHandler<AttachNonStandardClientAssertionClaims>()
                .SetOrder(PrepareClientAssertionPrincipal.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.ClientAssertionPrincipal is { Identity: ClaimsIdentity }, SR.GetResourceString(SR.ID4006));

            // For client assertions to be considered valid by the Apple ID authentication service,
            // the team identifier associated with the developer account MUST be used as the issuer
            // and the static "https://appleid.apple.com" URL MUST be used as the token audience.
            //
            // For more information about the custom client authentication method implemented by Apple,
            // see https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens.
            if (context.Registration.ProviderType is ProviderTypes.Apple)
            {
                var settings = context.Registration.GetAppleSettings();

                context.ClientAssertionPrincipal.SetClaim(Claims.Private.Issuer, settings.TeamId);
                context.ClientAssertionPrincipal.SetAudiences("https://appleid.apple.com");
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching custom client credentials
    /// parameters to the token request for the providers that require it.
    /// </summary>
    public sealed class AttachTokenRequestNonStandardClientCredentials : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<AttachTokenRequestNonStandardClientCredentials>()
                .SetOrder(AttachTokenRequestClientCredentials.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.TokenRequest is not null, SR.GetResourceString(SR.ID4008));

            // Apple implements a non-standard client authentication method for the token endpoint
            // that is inspired by the standard private_key_jwt method but doesn't use the standard
            // client_assertion/client_assertion_type parameters. Instead, the client assertion
            // must be sent as a "dynamic" client secret using client_secret_post. Since the logic
            // is the same as private_key_jwt, the configuration is amended to assume Apple supports
            // private_key_jwt and an event handler is responsible for populating the client_secret
            // parameter using the client assertion once it has been generated by OpenIddict.
            if (context.Registration.ProviderType is ProviderTypes.Apple)
            {
                context.TokenRequest.ClientSecret = context.TokenRequest.ClientAssertion;
                context.TokenRequest.ClientAssertion = null;
                context.TokenRequest.ClientAssertionType = null;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching custom client credentials
    /// parameters to the token request for the providers that require it.
    /// </summary>
    public sealed class AdjustRedirectUriInTokenRequest : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<AdjustRedirectUriInTokenRequest>()
                .SetOrder(AttachTokenRequestClientCredentials.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.TokenRequest is not null, SR.GetResourceString(SR.ID4008));

            if (context.TokenRequest.RedirectUri is null)
            {
                return default;
            }

            // Note: some providers don't support the "state" parameter, don't flow
            // it correctly or don't include it in errored authorization responses.
            //
            // Since OpenIddict requires flowing the state token in every circumstance
            // (for security reasons), the state token is appended to the "redirect_uri"
            // instead of being sent as a standard OAuth 2.0 authorization request parameter.
            //
            // Note: for token requests to use the actual redirect_uri that was sent as part
            // of the authorization requests, the value persisted in the state token principal
            // MUST be replaced to include the state token received by the redirection endpoint.

            context.TokenRequest.RedirectUri = context.Registration.ProviderType switch
            {
                ProviderTypes.Deezer or
                ProviderTypes.Mixcloud => OpenIddictHelpers.AddQueryStringParameter(
                    uri  : new Uri(context.TokenRequest.RedirectUri, UriKind.Absolute),
                    name : Parameters.State,
                    value: context.StateToken).AbsoluteUri,

                _ => context.TokenRequest.RedirectUri
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the set
    /// of required tokens for the providers that require it.
    /// </summary>
    public sealed class OverrideValidatedBackchannelTokens : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<OverrideValidatedBackchannelTokens>()
                .SetOrder(EvaluateValidatedBackchannelTokens.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            (context.ExtractBackchannelIdentityToken,
             context.RequireBackchannelIdentityToken,
             context.ValidateBackchannelIdentityToken) = context.Registration.ProviderType switch
            {
                // While PayPal claims the OpenID Connect flavor of the code flow is supported,
                // their implementation doesn't return an id_token from the token endpoint.
                ProviderTypes.PayPal => (false, false, false),

                _ => (context.ExtractBackchannelIdentityToken,
                      context.RequireBackchannelIdentityToken,
                      context.ValidateBackchannelIdentityToken)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for disabling the backchannel
    /// identity token nonce validation for the providers that require it.
    /// </summary>
    public sealed class DisableBackchannelIdentityTokenNonceValidation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<DisableBackchannelIdentityTokenNonceValidation>()
                .SetOrder(ValidateBackchannelIdentityTokenNonce.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: despite implementing OpenID Connect, some providers are known to implement the
            // specification incorrectly and either don't support the "nonce" authorization request
            // parameter, don't include it in the issued identity tokens or flow an unexpected value.
            //
            // Despite being an important security feature, nonce validation is explicitly disabled
            // for the providers that are known to cause errors when nonce validation is enforced.

            context.DisableBackchannelIdentityTokenNonceValidation = context.Registration.ProviderType switch
            {
                // These providers don't include the nonce in their identity tokens:
                ProviderTypes.Asana    or ProviderTypes.Dropbox or
                ProviderTypes.LinkedIn or ProviderTypes.QuickBooksOnline => true,

                _ => context.DisableBackchannelIdentityTokenNonceValidation
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the address
    /// of the userinfo endpoint for the providers that require it.
    /// </summary>
    public sealed class OverrideUserinfoEndpoint : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<OverrideUserinfoEndpoint>()
                .SetOrder(ResolveUserinfoEndpoint.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.UserinfoEndpoint = context.Registration.ProviderType switch
            {
                // HubSpot doesn't have a static userinfo endpoint but allows retrieving basic information
                // by using an access token info endpoint that requires sending the token in the URI path.
                ProviderTypes.HubSpot when
                    (context.BackchannelAccessToken ?? context.FrontchannelAccessToken) is { Length: > 0 } token
                    => OpenIddictHelpers.CreateAbsoluteUri(
                        left : new Uri("https://api.hubapi.com/oauth/v1/access-tokens", UriKind.Absolute),
                        right: new Uri(token, UriKind.Relative)),

                // SuperOffice doesn't expose a static OpenID Connect userinfo endpoint but offers an API whose
                // absolute URI needs to be computed based on a special claim returned in the identity token.
                ProviderTypes.SuperOffice when
                    (context.BackchannelIdentityTokenPrincipal ?? // Always prefer the backchannel identity token when available.
                     context.FrontchannelIdentityTokenPrincipal) is ClaimsPrincipal principal &&
                    Uri.TryCreate(principal.GetClaim("http://schemes.superoffice.net/identity/webapi_url"), UriKind.Absolute, out Uri? uri)
                    => OpenIddictHelpers.CreateAbsoluteUri(uri, new Uri("v1/user/currentPrincipal", UriKind.Relative)),

                _ => context.UserinfoEndpoint
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for disabling the userinfo retrieval for the providers that require it.
    /// </summary>
    public sealed class DisableUserinfoRetrieval : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<DisableUserinfoRetrieval>()
                .SetOrder(EvaluateUserinfoRequest.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.SendUserinfoRequest = context.Registration.ProviderType switch
            {
                // Note: ADFS has severe restrictions affecting the ability to access the userinfo endpoint
                // (e.g the "resource" parameter MUST be null or the "urn:microsoft:userinfo" value MUST be
                // used, which prevents specifying any other resource as only one value is allowed by ADFS).
                //
                // Since the userinfo endpoint returns very limited information anyway,
                // userinfo retrieval is always disabled for the ADFS provider.
                ProviderTypes.ActiveDirectoryFederationServices => false,

                // Note: the frontchannel or backchannel access tokens returned by Azure AD when a
                // Xbox scope is requested cannot be used with the userinfo endpoint as they use a
                // legacy format that is not supported by the Azure AD userinfo implementation.
                //
                // To work around this limitation, userinfo retrieval is disabled when a Xbox scope is requested.
                ProviderTypes.Microsoft => context.GrantType switch
                {
                    GrantTypes.AuthorizationCode or GrantTypes.Implicit when
                        context.StateTokenPrincipal is ClaimsPrincipal principal &&
                        principal.HasClaim(static claim =>
                            claim.Type is Claims.Private.Scope &&
                            claim.Value.StartsWith("XboxLive.", StringComparison.OrdinalIgnoreCase))
                        => false,

                    GrantTypes.DeviceCode or GrantTypes.RefreshToken when
                        context.Scopes.Any(static scope => scope.StartsWith("XboxLive.", StringComparison.OrdinalIgnoreCase))
                        => false,

                    _ => context.SendUserinfoRequest
                },

                _ => context.SendUserinfoRequest
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for disabling the userinfo validation for the providers that require it.
    /// </summary>
    public sealed class DisableUserinfoValidation : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .UseSingletonHandler<DisableUserinfoValidation>()
                .SetOrder(DisableUserinfoRetrieval.Descriptor.Order + 250)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Note: despite implementing OpenID Connect, some providers are known to implement completely custom
            // userinfo endpoints or semi-standard endpoints that don't fully conform to the core specification.
            //
            // To ensure OpenIddict can be used with these providers, validation is disabled when necessary.

            context.DisableUserinfoValidation = context.Registration.ProviderType switch
            {
                // SuperOffice doesn't offer a standard OpenID Connect userinfo endpoint.
                ProviderTypes.SuperOffice => true,

                _ => context.DisableUserinfoValidation
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching additional parameters
    /// to the userinfo request for the providers that require it.
    /// </summary>
    public sealed class AttachAdditionalUserinfoRequestParameters : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireUserinfoRequest>()
                .UseSingletonHandler<AttachAdditionalUserinfoRequestParameters>()
                .SetOrder(AttachUserinfoRequestParameters.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.UserinfoRequest is not null, SR.GetResourceString(SR.ID4008));

            // Facebook limits the number of fields returned by the userinfo endpoint
            // but allows returning additional information using special parameters that
            // determine what fields will be returned as part of the userinfo response.
            if (context.Registration.ProviderType is ProviderTypes.Facebook)
            {
                var settings = context.Registration.GetFacebookSettings();

                context.UserinfoRequest["fields"] = string.Join(",", settings.Fields);
            }

            // Patreon limits the number of fields returned by the userinfo endpoint
            // but allows returning additional information using special parameters that
            // determine what fields will be returned as part of the userinfo response.
            else if (context.Registration.ProviderType is ProviderTypes.Patreon)
            {
                var settings = context.Registration.GetPatreonSettings();

                context.UserinfoRequest["fields[user]"] = string.Join(",", settings.UserFields);
            }

            // StackOverflow requires sending an application key and a site parameter
            // containing the name of the site from which the user profile is retrieved.
            else if (context.Registration.ProviderType is ProviderTypes.StackExchange)
            {
                var settings = context.Registration.GetStackExchangeSettings();

                context.UserinfoRequest["key"] = settings.ApplicationKey;
                context.UserinfoRequest["site"] = settings.Site;
            }

            // SubscribeStar's userinfo endpoint is a GraphQL implementation that requires
            // sending a proper "query" parameter containing the requested user details.
            else if (context.Registration.ProviderType is ProviderTypes.SubscribeStar)
            {
                var settings = context.Registration.GetSubscribeStarSettings();

                context.UserinfoRequest["query"] = $"{{ user {{ {string.Join(", ", settings.UserFields)} }} }}";
            }

            // Trakt allows retrieving additional user details via the "extended" parameter.
            else if (context.Registration.ProviderType is ProviderTypes.Trakt)
            {
                context.UserinfoRequest["extended"] = "full";
            }

            // Twitter limits the number of fields returned by the userinfo endpoint
            // but allows returning additional information using special parameters that
            // determine what fields will be returned as part of the userinfo response.
            else if (context.Registration.ProviderType is ProviderTypes.Twitter)
            {
                var settings = context.Registration.GetTwitterSettings();

                context.UserinfoRequest["expansions"] = string.Join(",", settings.Expansions);
                context.UserinfoRequest["tweet.fields"] = string.Join(",", settings.TweetFields);
                context.UserinfoRequest["user.fields"] = string.Join(",", settings.UserFields);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for creating a userinfo token principal from the custom
    /// parameters returned in the token response for the providers that require it.
    /// </summary>
    public sealed class PopulateUserinfoTokenPrincipalFromTokenResponse : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireTokenRequest>()
                .UseSingletonHandler<PopulateUserinfoTokenPrincipalFromTokenResponse>()
                .SetOrder(ValidateUserinfoToken.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Registration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));
            Debug.Assert(context.TokenResponse is not null, SR.GetResourceString(SR.ID4007));

            // Don't overwrite the userinfo token principal if one was already set.
            if (context.UserinfoTokenPrincipal is not null)
            {
                return default;
            }

            // Some providers don't provide an OAuth 2.0/OpenID Connect userinfo endpoint but
            // return the user information using custom/non-standard token response parameters.
            // To work around that, this handler is responsible for extracting these parameters
            // from the token response and creating a userinfo token principal containing them.

            var parameters = context.Registration.ProviderType switch
            {
                // For Shopify, include all the parameters contained in the "associated_user" object.
                //
                // Note: the "associated_user" node is only available when using the online access mode.
                ProviderTypes.Shopify => context.TokenResponse["associated_user"]?.GetNamedParameters(),

                // For Strava, include all the parameters contained in the "athlete" object.
                //
                // Note: the "athlete" node is not returned for grant_type=refresh_token requests.
                ProviderTypes.Strava => context.TokenResponse["athlete"]?.GetNamedParameters(),

                // For Stripe, only include "livemode" and the parameters that are prefixed with "stripe_":
                ProviderTypes.StripeConnect =>
                    from parameter in context.TokenResponse.GetParameters()
                    where string.Equals(parameter.Key, "livemode", StringComparison.OrdinalIgnoreCase) ||
                        parameter.Key.StartsWith("stripe_", StringComparison.OrdinalIgnoreCase)
                    select parameter,

                _ => null
            };

            if (parameters is null)
            {
                return default;
            }

            var identity = new ClaimsIdentity(
                context.Registration.TokenValidationParameters.AuthenticationType,
                context.Registration.TokenValidationParameters.NameClaimType,
                context.Registration.TokenValidationParameters.RoleClaimType);

            foreach (var parameter in parameters)
            {
                // Note: in the typical case, the response parameters should be deserialized from a
                // JSON response and thus natively stored as System.Text.Json.JsonElement instances.
                //
                // In the rare cases where the underlying value wouldn't be a JsonElement instance
                // (e.g when custom parameters are manually added to the response), the static
                // conversion operator would take care of converting the underlying value to a
                // JsonElement instance using the same value type as the original parameter value.
                switch ((JsonElement) parameter.Value)
                {
                    // Top-level claims represented as arrays are split and mapped to multiple CLR claims
                    // to match the logic implemented by IdentityModel for JWT token deserialization.
                    case { ValueKind: JsonValueKind.Array } value:
                        identity.AddClaims(parameter.Key, value, context.Registration.Issuer.AbsoluteUri);
                        break;

                    case { ValueKind: _ } value:
                        identity.AddClaim(parameter.Key, value, context.Registration.Issuer.AbsoluteUri);
                        break;
                }
            }

            context.UserinfoTokenPrincipal = new ClaimsPrincipal(identity);

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for mapping select custom claims to
    /// their WS-Federation equivalent for the providers that require it.
    /// </summary>
    public sealed class MapCustomWebServicesFederationClaims : IOpenIddictClientHandler<ProcessAuthenticationContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessAuthenticationContext>()
                .AddFilter<RequireWebServicesFederationClaimMappingEnabled>()
                .UseSingletonHandler<MapCustomWebServicesFederationClaims>()
                .SetOrder(MapStandardWebServicesFederationClaims.Descriptor.Order + 1_000)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessAuthenticationContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Registration.Issuer is { IsAbsoluteUri: true }, SR.GetResourceString(SR.ID4013));

            // As an OpenID Connect framework, the OpenIddict client mostly uses the claim set defined by the OpenID
            // Connect core specification (https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
            // While these claims can be easily accessed using their standard OIDC name, many components still use
            // the Web Services Federation claims exposed by the BCL ClaimTypes class, sometimes without allowing
            // to use different claim types (e.g ASP.NET Core Identity hardcodes ClaimTypes.NameIdentifier in a few
            // places, like the GetUserId() extension). To reduce the difficulty of using the OpenIddict client with
            // these components relying on WS-Federation-style claims, these claims are mapped from the custom,
            // provider-specific parameters (either from the userinfo response or from the token rensponse).
            //
            // Note: a similar event handler exists in OpenIddict.Client to map these claims from
            // the standard OpenID Connect claim types (see MapStandardWebServicesFederationClaims).

            var issuer = context.Registration.Issuer.AbsoluteUri;

            context.MergedPrincipal.SetClaim(ClaimTypes.Email, issuer: issuer, value: context.Registration.ProviderType switch
            {
                // Basecamp returns the email address as a custom "email_address" node:
                ProviderTypes.Basecamp => (string?) context.UserinfoResponse?["email_address"],

                // HubSpot returns the email address as a custom "user" node:
                ProviderTypes.HubSpot => (string?) context.UserinfoResponse?["user"],

                // Mailchimp returns the email address as a custom "login/login_email" node:
                ProviderTypes.Mailchimp => (string?) context.UserinfoResponse?["login"]?["login_email"],

                // Notion returns the email address as a custom "bot/owner/user/person/email" node
                // but requires a special capability to access this node, that may not be present:
                ProviderTypes.Notion => (string?) context.UserinfoResponse?["bot"]?["owner"]?["user"]?["person"]?["email"],

                // Patreon returns the email address as a custom "attributes/email" node:
                ProviderTypes.Patreon => (string?) context.UserinfoResponse?["attributes"]?["email"],

                // ServiceChannel returns the email address as a custom "Email" node:
                ProviderTypes.ServiceChannel => (string?) context.UserinfoResponse?["Email"],

                // Shopify returns the email address as a custom "associated_user/email" node in token responses:
                ProviderTypes.Shopify => (string?) context.TokenResponse?["associated_user"]?["email"],

                _ => context.MergedPrincipal.GetClaim(ClaimTypes.Email)
            });

            context.MergedPrincipal.SetClaim(ClaimTypes.Name, issuer: issuer, value: context.Registration.ProviderType switch
            {
                // These providers return the username as a custom "username" node:
                ProviderTypes.ArcGisOnline or ProviderTypes.Discord  or ProviderTypes.DeviantArt or
                ProviderTypes.Lichess      or ProviderTypes.Mixcloud or ProviderTypes.Trakt      or
                ProviderTypes.WordPress
                    => (string?) context.UserinfoResponse?["username"],

                // Basecamp and Harvest don't return a username so one is created using the "first_name" and "last_name" nodes:
                ProviderTypes.Basecamp or ProviderTypes.Harvest
                    when context.UserinfoResponse?.HasParameter("first_name") is true &&
                         context.UserinfoResponse?.HasParameter("last_name")  is true
                    => $"{(string?) context.UserinfoResponse?["first_name"]} {(string?) context.UserinfoResponse?["last_name"]}",

                // These providers return the username as a custom "name" node:
                ProviderTypes.Deezer or ProviderTypes.Facebook      or ProviderTypes.GitHub or
                ProviderTypes.Reddit or ProviderTypes.SubscribeStar or ProviderTypes.Vimeo
                    => (string?) context.UserinfoResponse?["name"],

                // FitBit returns the username as a custom "displayName" node:
                ProviderTypes.Fitbit => (string?) context.UserinfoResponse?["displayName"],

                // HubSpot returns the username as a custom "user" node:
                ProviderTypes.HubSpot => (string?) context.UserinfoResponse?["user"],

                // Mailchimp returns the username as a custom "accountname" node:
                ProviderTypes.Mailchimp => (string?) context.UserinfoResponse?["accountname"],

                // Nextcloud returns the username as a custom "displayname" or "display-name" node:
                ProviderTypes.Nextcloud => (string?) context.UserinfoResponse?["displayname"] ??
                                           (string?) context.UserinfoResponse?["display-name"],

                // Notion returns the username as a custom "bot/owner/user/name" node but
                // requires a special capability to access this node, that may not be present:
                ProviderTypes.Notion => (string?) context.UserinfoResponse?["bot"]?["owner"]?["user"]?["name"],

                // Patreon doesn't return a username and require using the complete user name as the username:
                ProviderTypes.Patreon => (string?) context.UserinfoResponse?["attributes"]?["full_name"],

                // ServiceChannel returns the username as a custom "UserName" node:
                ProviderTypes.ServiceChannel => (string?) context.UserinfoResponse?["UserName"],

                // Shopify doesn't return a username so one is created using the "first_name" and "last_name" nodes:
                ProviderTypes.Shopify
                    when context.TokenResponse?["associated_user"]?["first_name"] is not null &&
                         context.TokenResponse?["associated_user"]?["last_name"]  is not null
                    => $"{(string?) context.TokenResponse?["associated_user"]?["first_name"]} {(string?) context.TokenResponse?["associated_user"]?["last_name"]}",

                // Smartsheet doesn't return a username so one is created using the "firstName" and "lastName" nodes:
                ProviderTypes.Smartsheet
                    when context.UserinfoResponse?.HasParameter("firstName") is true &&
                         context.UserinfoResponse?.HasParameter("lastName")  is true
                    => $"{(string?) context.UserinfoResponse?["firstName"]} {(string?) context.UserinfoResponse?["lastName"]}",

                // These providers return return the username as a custom "display_name" node:
                ProviderTypes.Spotify or ProviderTypes.StackExchange or ProviderTypes.Zoom
                    => (string?) context.UserinfoResponse?["display_name"],

                // Strava returns the username as a custom "athlete/username" node in token responses:
                ProviderTypes.Strava => (string?) context.TokenResponse?["athlete"]?["username"],

                // Streamlabs returns the username as a custom "streamlabs/display_name" node:
                ProviderTypes.Streamlabs => (string?) context.UserinfoResponse?["streamlabs"]?["display_name"],

                // Trovo returns the username as a custom "userName" node:
                ProviderTypes.Trovo => (string?) context.UserinfoResponse?["userName"],

                // Tumblr returns the username as a custom "name" node:
                ProviderTypes.Tumblr => (string?) context.UserinfoResponse?["name"],

                _ => context.MergedPrincipal.GetClaim(ClaimTypes.Name)
            });

            context.MergedPrincipal.SetClaim(ClaimTypes.NameIdentifier, issuer: issuer, value: context.Registration.ProviderType switch
            {
                // ArcGIS and Trakt don't return a user identifier and require using the username as the identifier:
                ProviderTypes.ArcGisOnline or ProviderTypes.Trakt
                    => (string?) context.UserinfoResponse?["username"],

                // These providers return the user identifier as a custom "id" node:
                ProviderTypes.Basecamp or ProviderTypes.Deezer        or ProviderTypes.Discord    or
                ProviderTypes.Facebook or ProviderTypes.GitHub        or ProviderTypes.Harvest    or
                ProviderTypes.Kroger   or ProviderTypes.Lichess       or ProviderTypes.Nextcloud  or
                ProviderTypes.Patreon  or ProviderTypes.Reddit        or ProviderTypes.Smartsheet or
                ProviderTypes.Spotify  or ProviderTypes.SubscribeStar or ProviderTypes.Twitter    or
                ProviderTypes.Zoom
                    => (string?) context.UserinfoResponse?["id"],

                // Bitbucket returns the user identifier as a custom "uuid" node:
                ProviderTypes.Bitbucket => (string?) context.UserinfoResponse?["uuid"],

                // DeviantArt returns the user identifier as a custom "userid" node:
                ProviderTypes.DeviantArt => (string?) context.UserinfoResponse?["userid"],

                // Fitbit returns the user identifier as a custom "encodedId" node:
                ProviderTypes.Fitbit => (string?) context.UserinfoResponse?["encodedId"],

                // HubSpot and StackExchange return the user identifier as a custom "user_id" node:
                ProviderTypes.HubSpot or ProviderTypes.StackExchange
                    => (string?) context.UserinfoResponse?["user_id"],

                // Mailchimp returns the user identifier as a custom "login/login_id" node:
                ProviderTypes.Mailchimp => (string?) context.UserinfoResponse?["login"]?["login_id"],

                // Mixcloud returns the user identifier as a custom "key" node:
                ProviderTypes.Mixcloud => (string?) context.UserinfoResponse?["key"],

                // Notion returns the user identifier as a custom "bot/owner/user/id" node but
                // requires a special capability to access this node, that may not be present:
                ProviderTypes.Notion => (string?) context.UserinfoResponse?["bot"]?["owner"]?["user"]?["id"],

                // ServiceChannel returns the user identifier as a custom "UserId" node:
                ProviderTypes.ServiceChannel => (string?) context.UserinfoResponse?["UserId"],

                // Shopify returns the user identifier as a custom "associated_user/id" node in token responses:
                ProviderTypes.Shopify => (string?) context.TokenResponse?["associated_user"]?["id"],

                // Strava returns the user identifier as a custom "athlete/id" node in token responses:
                ProviderTypes.Strava => (string?) context.TokenResponse?["athlete"]?["id"],

                // Stripe returns the user identifier as a custom "stripe_user_id" node in token responses:
                ProviderTypes.StripeConnect => (string?) context.TokenResponse?["stripe_user_id"],

                // Streamlabs returns the user identifier as a custom "streamlabs/id" node:
                ProviderTypes.Streamlabs => (string?) context.UserinfoResponse?["streamlabs"]?["id"],

                // Trovo returns the user identifier as a custom "userId" node:
                ProviderTypes.Trovo => (string?) context.UserinfoResponse?["userId"],

                // Tumblr doesn't return a user identifier and requires using the username as the identifier:
                ProviderTypes.Tumblr => (string?) context.UserinfoResponse?["name"],

                // Vimeo returns the user identifier as a custom "uri" node, prefixed with "/users/":
                ProviderTypes.Vimeo => (string?) context.UserinfoResponse?["uri"] is string uri &&
                    uri.StartsWith("/users/", StringComparison.Ordinal) ? uri["/users/".Length..] : null,

                // WordPress returns the user identifier as a custom "ID" node:
                ProviderTypes.WordPress => (string?) context.UserinfoResponse?["ID"],

                _ => context.MergedPrincipal.GetClaim(ClaimTypes.NameIdentifier)
            });

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the user-defined authentication properties.
    /// </summary>
    public sealed class ValidateChallengeProperties : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<ValidateChallengeProperties>()
                .SetOrder(ResolveClientRegistrationFromChallengeContext.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // If no explicit shop name was attached to the challenge properties, use the
            // shop name set in the provider settings, if set. Otherwise, throw an exception.
            if (context.Registration.ProviderType is ProviderTypes.Shopify &&
              (!context.Properties.TryGetValue(Shopify.Properties.ShopName, out string? name) ||
                string.IsNullOrEmpty(name)))
            {
                var settings = context.Registration.GetShopifySettings();
                if (string.IsNullOrEmpty(settings.ShopName))
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0412));
                }

                context.Properties[Shopify.Properties.ShopName] = settings.ShopName;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the address of
    /// the authorization endpoint for the providers that require it.
    /// </summary>
    public sealed class OverrideAuthorizationEndpoint : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .UseSingletonHandler<OverrideAuthorizationEndpoint>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order - 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.AuthorizationEndpoint = context.Registration.ProviderType switch
            {
                // Shopify is a multitenant provider that requires setting the authorization endpoint
                // dynamically based on the shop name stored in the authentication properties.
                //
                // For more information, see
                // https://shopify.dev/docs/apps/auth/oauth/getting-started#step-3-ask-for-permission.
                ProviderTypes.Shopify => context.Properties.TryGetValue(Shopify.Properties.ShopName, out string? name) ?
                    new Uri($"https://{name}.myshopify.com/admin/oauth/authorize", UriKind.Absolute) :
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0412)),

                // Stripe uses a different authorization endpoint for express accounts.
                //
                // The type of account can be defined globally (via the Stripe options) or
                // per authentication demand by adding a specific authentication property.
                //
                // For more information, see
                // https://stripe.com/docs/connect/oauth-reference?locale=en-us#get-authorize.
                ProviderTypes.StripeConnect when context.Properties.TryGetValue(
                    StripeConnect.Properties.AccountType, out string? type) =>
                    string.Equals(type, "express", StringComparison.OrdinalIgnoreCase) ?
                        new Uri("https://connect.stripe.com/express/oauth/authorize", UriKind.Absolute) :
                        new Uri("https://connect.stripe.com/oauth/authorize", UriKind.Absolute),

                _ => context.AuthorizationEndpoint
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the response mode for the providers that require it.
    /// </summary>
    public sealed class OverrideResponseMode : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<OverrideResponseMode>()
                // Note: this handler MUST be invoked after the scopes have been attached to the
                // context to support overriding the response mode based on the requested scopes.
                .SetOrder(AttachScopes.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.ResponseMode = context.Registration.ProviderType switch
            {
                // Note: Apple requires using form_post when the "email" or "name" scopes are requested.
                ProviderTypes.Apple when context.Scopes.Contains(Scopes.Email) || context.Scopes.Contains("name")
                    => ResponseModes.FormPost,

                _ => context.ResponseMode
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for overriding the standard "scope"
    /// parameter for providers that are known to use a non-standard format.
    /// </summary>
    public sealed class FormatNonStandardScopeParameter : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<FormatNonStandardScopeParameter>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Request.Scope = context.Registration.ProviderType switch
            {
                // The following providers are known to use comma-separated scopes instead of
                // the standard format (that requires using a space as the scope separator):
                ProviderTypes.Deezer or ProviderTypes.Shopify or ProviderTypes.Strava
                    => string.Join(",", context.Scopes),

                // The following providers are known to use plus-separated scopes instead of
                // the standard format (that requires using a space as the scope separator):
                ProviderTypes.Trovo => string.Join("+", context.Scopes),

                _ => context.Request.Scope
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for persisting the state parameter in the redirect URI for
    /// providers that don't support it but allow arbitrary dynamic parameters in redirect_uri.
    /// </summary>
    public sealed class IncludeStateParameterInRedirectUri : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<IncludeStateParameterInRedirectUri>()
                .SetOrder(FormatNonStandardScopeParameter.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (context.RedirectUri is null)
            {
                return default;
            }

            // Note: some providers don't support the "state" parameter, don't flow
            // it correctly or don't include it in errored authorization responses.
            //
            // Since OpenIddict requires flowing the state token in every circumstance
            // (for security reasons), the state token is appended to the "redirect_uri"
            // instead of being sent as a standard OAuth 2.0 authorization request parameter.
            //
            // Note: this workaround only works for providers that allow dynamic
            // redirection URIs and implement a relaxed validation policy logic.

            if (context.Registration.ProviderType is ProviderTypes.Deezer or ProviderTypes.Mixcloud)
            {
                context.Request.RedirectUri = OpenIddictHelpers.AddQueryStringParameter(
                    uri  : new Uri(context.RedirectUri, UriKind.Absolute),
                    name : Parameters.State,
                    value: context.Request.State).AbsoluteUri;

                context.Request.State = null;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching additional parameters
    /// to the authorization request for the providers that require it.
    /// </summary>
    public sealed class AttachAdditionalChallengeParameters : IOpenIddictClientHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictClientHandlerDescriptor Descriptor { get; }
            = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireInteractiveGrantType>()
                .UseSingletonHandler<AttachAdditionalChallengeParameters>()
                .SetOrder(AttachChallengeParameters.Descriptor.Order + 500)
                .SetType(OpenIddictClientHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // Active Directory Federation Services allows sending a custom "resource"
            // parameter to define what API resources the access token will give access to.
            if (context.Registration.ProviderType is ProviderTypes.ActiveDirectoryFederationServices)
            {
                var settings = context.Registration.GetActiveDirectoryFederationServicesSettings();

                context.Request["resource"] = settings.Resource;
            }

            // By default, Google doesn't return a refresh token but allows sending an "access_type"
            // parameter to retrieve one (but it is only returned during the first authorization dance).
            else if (context.Registration.ProviderType is ProviderTypes.Google)
            {
                var settings = context.Registration.GetGoogleSettings();

                context.Request["access_type"] = settings.AccessType;
            }

            // Pro Santé Connect's specification requires sending an acr_values parameter containing
            // the desired level of authentication (currently, only "eidas1" is supported). For more
            // information, see https://www.legifrance.gouv.fr/jorf/id/JORFTEXT000045551195.
            else if (context.Registration.ProviderType is ProviderTypes.ProSantéConnect)
            {
                var settings = context.Registration.GetProSantéConnectSettings();

                context.Request.AcrValues = settings.AuthenticationLevel;
            }

            // By default, Reddit doesn't return a refresh token but
            // allows sending a "duration" parameter to retrieve one.
            else if (context.Registration.ProviderType is ProviderTypes.Reddit)
            {
                var settings = context.Registration.GetRedditSettings();

                context.Request["duration"] = settings.Duration;
            }

            // Shopify allows setting an optional access mode to enable per-user authorization.
            else if (context.Registration.ProviderType is ProviderTypes.Shopify)
            {
                var settings = context.Registration.GetShopifySettings();
                if (string.Equals(settings.AccessMode, "online", StringComparison.OrdinalIgnoreCase))
                {
                    context.Request["grant_options[]"] = "per-user";
                }
            }

            // Slack allows sending an optional "team" parameter to simplify the login process.
            else if (context.Registration.ProviderType is ProviderTypes.Slack)
            {
                var settings = context.Registration.GetSlackSettings();

                context.Request["team"] = settings.Team;
            }

            return default;
        }
    }
}

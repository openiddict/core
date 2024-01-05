﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using OpenIddict.Extensions;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers.Exchange;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class Exchange
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = [
            /*
             * Token request preparation:
             */
            MapNonStandardRequestParameters.Descriptor,
            AttachNonStandardBasicAuthenticationCredentials.Descriptor,
            AttachNonStandardRequestHeaders.Descriptor,
            AttachNonStandardQueryStringParameters.Descriptor,
            AttachNonStandardRequestPayload.Descriptor,

            /*
             * Token response extraction:
             */
            MapNonStandardResponseParameters.Descriptor
        ];

        /// <summary>
        /// Contains the logic responsible for mapping non-standard request parameters
        /// to their standard equivalent for the providers that require it.
        /// </summary>
        public sealed class MapNonStandardRequestParameters : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .UseSingletonHandler<MapNonStandardRequestParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Some providers implement old drafts of the OAuth 2.0 specification that
                // didn't support the "response_type" parameter but relied on a "type"
                // parameter to determine the type of request (web server or refresh).
                //
                // To support these providers, the "grant_type" parameter must be manually mapped
                // to its equivalent "type" (e.g "web_server") before sending the token request.
                if (context.Registration.ProviderType is ProviderTypes.Basecamp)
                {
                    context.Request["type"] = context.Request.GrantType switch
                    {
                        GrantTypes.AuthorizationCode => "web_server",
                        GrantTypes.RefreshToken      => "refresh",

                        _ => null
                    };

                    context.Request.GrantType = null;
                }

                // World ID doesn't support the standard and mandatory redirect_uri parameter and returns
                // a HTTP 500 response when specifying it in a grant_type=authorization_code token request.
                //
                // To prevent that, the redirect_uri parameter must be removed from the token request.
                else if (context.GrantType is GrantTypes.AuthorizationCode &&
                         context.Registration.ProviderType is ProviderTypes.WorldId)
                {
                    context.Request.RedirectUri = null;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the client credentials to the HTTP Authorization
        /// header using a non-standard construction logic for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardBasicAuthenticationCredentials : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachNonStandardBasicAuthenticationCredentials>()
                    .SetOrder(AttachBasicAuthenticationCredentials.Descriptor.Order - 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Some providers are known to incorrectly implement basic authentication support, either because
                // an incorrect encoding scheme is used (e.g the credentials are not formURL-encoded as required
                // by the OAuth 2.0 specification) or because basic authentication is required even for public
                // clients, even though these clients don't have a secret (which requires using an empty password).

                Debug.Assert(context.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // These providers require using basic authentication to flow the client_id
                // for all types of client applications, even when there's no client_secret.
                if (context.Registration.ProviderType is ProviderTypes.Reddit &&
                    !string.IsNullOrEmpty(context.Request.ClientId))
                {
                    // Important: the credentials MUST be formURL-encoded before being base64-encoded.
                    var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(new StringBuilder()
                        .Append(EscapeDataString(context.Request.ClientId))
                        .Append(':')
                        .Append(EscapeDataString(context.Request.ClientSecret))
                        .ToString()));

                    // Attach the authorization header containing the client identifier to the HTTP request.
                    request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Basic, credentials);

                    // Remove the client credentials from the request payload to ensure they are not sent twice.
                    context.Request.ClientId = context.Request.ClientSecret = null;
                }

                // These providers don't implement the standard version of the client_secret_basic
                // authentication method as they don't support formURL-encoding the client credentials.
                else if (context.Registration.ProviderType is ProviderTypes.EpicGames &&
                    !string.IsNullOrEmpty(context.Request.ClientId) &&
                    !string.IsNullOrEmpty(context.Request.ClientSecret))
                {
                    var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes(new StringBuilder()
                        .Append(context.Request.ClientId)
                        .Append(':')
                        .Append(context.Request.ClientSecret)
                        .ToString()));

                    // Attach the authorization header containing the client identifier to the HTTP request.
                    request.Headers.Authorization = new AuthenticationHeaderValue(Schemes.Basic, credentials);

                    // Remove the client credentials from the request payload to ensure they are not sent twice.
                    context.Request.ClientId = context.Request.ClientSecret = null;
                }

                return default;

                static string? EscapeDataString(string? value)
                    => value is not null ? Uri.EscapeDataString(value).Replace("%20", "+") : null;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching additional
        /// headers to the request for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardRequestHeaders : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachNonStandardRequestHeaders>()
                    .SetOrder(AttachUserAgentHeader<PrepareTokenRequestContext>.Descriptor.Order + 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // Trovo requires sending the client identifier in a non-standard "client-id" header and
                // the client secret in the payload (formatted using JSON instead of the standard format).
                if (context.Registration.ProviderType is ProviderTypes.Trovo)
                {
                    request.Headers.Add("Client-ID", context.Request.ClientId);

                    // Remove the client identifier from the request payload to ensure it's not sent twice.
                    context.Request.ClientId = null;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching non-standard query string
        /// parameters to the token request for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardQueryStringParameters : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachNonStandardQueryStringParameters>()
                    .SetOrder(AttachHttpParameters<PrepareTokenRequestContext>.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                if (request.RequestUri is null)
                {
                    return default;
                }

                // By default, Deezer returns non-standard token responses formatted as formurl-encoded
                // payloads and declared as "text/html" content but allows sending an "output" query string
                // parameter containing "json" to get a response conforming to the OAuth 2.0 specification.
                if (context.Registration.ProviderType is ProviderTypes.Deezer)
                {
                    request.RequestUri = OpenIddictHelpers.AddQueryStringParameter(
                        request.RequestUri, name: "output", value: "json");
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching a non-standard payload for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardRequestPayload : IOpenIddictClientHandler<PrepareTokenRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareTokenRequestContext>()
                    .AddFilter<RequireHttpMetadataUri>()
                    .UseSingletonHandler<AttachNonStandardRequestPayload>()
                    .SetOrder(AttachHttpParameters<PrepareTokenRequestContext>.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareTokenRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                request.Content = context.Registration.ProviderType switch
                {
                    // Trovo returns a 500 internal server error when using the standard
                    // "application/x-www-form-urlencoded" format and requires using JSON.
                    ProviderTypes.Trovo => JsonContent.Create(context.Transaction.Request,
                        new MediaTypeHeaderValue(MediaTypes.Json)
                        {
                            CharSet = Charsets.Utf8
                        }),

                    _ => request.Content
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for mapping non-standard response parameters
        /// to their standard equivalent for the providers that require it.
        /// </summary>
        public sealed class MapNonStandardResponseParameters : IOpenIddictClientHandler<ExtractTokenResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractTokenResponseContext>()
                    .UseSingletonHandler<MapNonStandardResponseParameters>()
                    .SetOrder(int.MaxValue - 50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractTokenResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.Response is null)
                {
                    return default;
                }

                // Note: Deezer doesn't return a standard "expires_in" parameter
                // but returns an equivalent "expires" integer parameter instead.
                if (context.Registration.ProviderType is ProviderTypes.Deezer)
                {
                    context.Response[Parameters.ExpiresIn] = context.Response["expires"];
                    context.Response["expires"] = null;
                }

                // Note: Tumblr returns a non-standard "id_token: false" node that collides
                // with the standard id_token parameter used in OpenID Connect. To ensure
                // the response is not rejected, the "id_token" node is manually removed.
                else if (context.Registration.ProviderType is ProviderTypes.Tumblr)
                {
                    context.Response["id_token"] = null;
                }

                return default;
            }
        }
    }
}

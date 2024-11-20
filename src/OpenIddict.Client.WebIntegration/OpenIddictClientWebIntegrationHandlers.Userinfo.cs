/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpConstants;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlerFilters;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers;
using static OpenIddict.Client.SystemNetHttp.OpenIddictClientSystemNetHttpHandlers.UserInfo;
using static OpenIddict.Client.WebIntegration.OpenIddictClientWebIntegrationConstants;

namespace OpenIddict.Client.WebIntegration;

public static partial class OpenIddictClientWebIntegrationHandlers
{
    public static class UserInfo
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * UserInfo request preparation:
             */
            OverrideHttpMethod.Descriptor,
            AttachRequestHeaders.Descriptor,
            AttachAccessTokenParameter.Descriptor,
            AttachNonStandardParameters.Descriptor,
            AttachNonStandardRequestPayload.Descriptor,

            /*
             * UserInfo response extraction:
             */
            NormalizeContentType.Descriptor,
            UnwrapUserInfoResponse.Descriptor,
            MapNonStandardResponseParameters.Descriptor,
        ]);

        /// <summary>
        /// Contains the logic responsible for overriding the HTTP method for the providers that require it.
        /// </summary>
        public sealed class OverrideHttpMethod : IOpenIddictClientHandler<PrepareUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserInfoRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<OverrideHttpMethod>()
                    .SetOrder(PreparePostHttpRequest<PrepareUserInfoRequestContext>.Descriptor.Order + 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                request.Method = context.Registration.ProviderType switch
                {
                    // The userinfo endpoints exposed by these providers
                    // are based on GraphQL, which requires using POST:
                    ProviderTypes.Meetup or ProviderTypes.SubscribeStar => HttpMethod.Post,

                    // The userinfo endpoints exposed by these providers
                    // use custom protocols that require using POST:
                    ProviderTypes.Todoist => HttpMethod.Post,

                    _ => request.Method
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching additional
        /// headers to the request for the providers that require it.
        /// </summary>
        public sealed class AttachRequestHeaders : IOpenIddictClientHandler<PrepareUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserInfoRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachRequestHeaders>()
                    .SetOrder(AttachUserAgentHeader<PrepareUserInfoRequestContext>.Descriptor.Order + 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // Notion requires sending an explicit API version (which is statically set
                // to the last version known to be supported by the OpenIddict integration).
                if (context.Registration.ProviderType is ProviderTypes.Notion)
                {
                    request.Headers.Add("Notion-Version", "2022-06-28");
                }

                // Trakt requires sending both an API key (which is always the client identifier) and an API version
                // (which is statically set to the last version known to be supported by the OpenIddict integration).
                else if (context.Registration.ProviderType is ProviderTypes.Trakt)
                {
                    request.Headers.Add("trakt-api-key", context.Registration.ClientId);
                    request.Headers.Add("trakt-api-version", "2");
                }

                // Trovo requires sending the client identifier as a separate, non-standard header.
                else if (context.Registration.ProviderType is ProviderTypes.Trovo)
                {
                    request.Headers.Add("Client-ID", context.Registration.ClientId);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the access token
        /// parameter to the request for the providers that require it.
        /// </summary>
        public sealed class AttachAccessTokenParameter : IOpenIddictClientHandler<PrepareUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserInfoRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachAccessTokenParameter>()
                    .SetOrder(AttachBearerAccessToken.Descriptor.Order + 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var request = context.Transaction.GetHttpRequestMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                // By default, OpenIddict sends the access token as part of the Authorization header
                // using the Bearer authentication scheme. Some providers don't support this method
                // and require sending the access token as part of the userinfo request payload
                // or using a non-standard authentication scheme (e.g OAuth instead of Bearer).

                // These providers require sending the access token as part of the request payload.
                if (context.Registration.ProviderType is
                    ProviderTypes.Deezer or ProviderTypes.Mixcloud or ProviderTypes.StackExchange or ProviderTypes.Weibo)
                {
                    context.Request.AccessToken = request.Headers.Authorization?.Parameter;

                    // Remove the access token from the request headers to ensure it's not sent twice.
                    request.Headers.Authorization = null;
                }

                // Shopify requires using the non-standard "X-Shopify-Access-Token" header.
                else if (context.Registration.ProviderType is ProviderTypes.Shopify)
                {
                    request.Headers.Add("X-Shopify-Access-Token", request.Headers.Authorization?.Parameter);

                    // Remove the access token from the request headers to ensure it's not sent twice.
                    request.Headers.Authorization = null;
                }

                // Trovo requires using the "OAuth" scheme instead of the standard "Bearer" value.
                else if (context.Registration.ProviderType is ProviderTypes.Trovo)
                {
                    request.Headers.Authorization = new AuthenticationHeaderValue("OAuth",
                        request.Headers.Authorization?.Parameter);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching non-standard
        /// parameters to the request for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardParameters : IOpenIddictClientHandler<PrepareUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserInfoRequestContext>()
                    .UseSingletonHandler<AttachNonStandardParameters>()
                    .SetOrder(AttachHttpParameters<PrepareUserInfoRequestContext>.Descriptor.Order - 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserInfoRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // ArcGIS Online doesn't support header-based content negotiation and requires using
                // the non-standard "f" parameter to get back JSON responses instead of HTML pages.
                if (context.Registration.ProviderType is ProviderTypes.ArcGisOnline)
                {
                    context.Request["f"] = "json";
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching a non-standard payload for the providers that require it.
        /// </summary>
        public sealed class AttachNonStandardRequestPayload : IOpenIddictClientHandler<PrepareUserInfoRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareUserInfoRequestContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<AttachNonStandardRequestPayload>()
                    .SetOrder(AttachHttpParameters<PrepareUserInfoRequestContext>.Descriptor.Order + 500)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareUserInfoRequestContext context)
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
                    // The userinfo endpoints exposed by these providers are based on GraphQL,
                    // which requires sending the request parameters as a JSON payload:
                    ProviderTypes.Meetup or ProviderTypes.SubscribeStar
                        => JsonContent.Create(context.Transaction.Request, new MediaTypeHeaderValue(MediaTypes.Json)
                        {
                            CharSet = Charsets.Utf8
                        }),

                    _ => request.Content
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for normalizing the returned content
        /// type of userinfo responses for the providers that require it.
        /// </summary>
        public sealed class NormalizeContentType : IOpenIddictClientHandler<ExtractUserInfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractUserInfoResponseContext>()
                    .AddFilter<RequireHttpUri>()
                    .UseSingletonHandler<NormalizeContentType>()
                    .SetOrder(ExtractUserInfoTokenHttpResponse.Descriptor.Order - 250)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractUserInfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to System.Net.Http requests. If the HTTP response cannot be resolved,
                // this may indicate that the request was incorrectly processed by another client stack.
                var response = context.Transaction.GetHttpResponseMessage() ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0173));

                if (response.Content is null)
                {
                    return default;
                }

                // Some providers are known to return invalid or incorrect media types, which prevents
                // OpenIddict from extracting userinfo responses. To work around that, the declared
                // content type is replaced by the correct value for the providers that require it.

                response.Content.Headers.ContentType = context.Registration.ProviderType switch
                {
                    // Mixcloud returns JSON-formatted contents declared as "text/javascript".
                    ProviderTypes.Mixcloud when string.Equals(
                        response.Content.Headers.ContentType?.MediaType,
                        "text/javascript", StringComparison.OrdinalIgnoreCase)
                        => new MediaTypeHeaderValue(MediaTypes.Json)
                        {
                            CharSet = Charsets.Utf8
                        },

                    // Wikimedia returns JSON-formatted contents declared as "text/html".
                    ProviderTypes.Wikimedia when string.Equals(
                        response.Content.Headers.ContentType?.MediaType,
                        "text/html", StringComparison.OrdinalIgnoreCase)
                        => new MediaTypeHeaderValue(MediaTypes.Json)
                        {
                            CharSet = Charsets.Utf8
                        },

                    _ => response.Content.Headers.ContentType
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the userinfo response
        /// from nested JSON nodes (e.g "data") for the providers that require it.
        /// </summary>
        public sealed class UnwrapUserInfoResponse : IOpenIddictClientHandler<ExtractUserInfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractUserInfoResponseContext>()
                    .UseSingletonHandler<UnwrapUserInfoResponse>()
                    .SetOrder(int.MaxValue - 50_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractUserInfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                // Some providers are known to wrap their userinfo payloads in top-level JSON nodes
                // (generally named "d", "data" or "response"), which prevents the default extraction
                // logic from mapping the parameters to CLR claims. To work around that, this handler
                // is responsible for extracting the nested payload and replacing the userinfo response.

                context.Response = context.Registration.ProviderType switch
                {
                    // Basecamp returns a nested "identity" object and a collection of "accounts".
                    ProviderTypes.Basecamp => new(context.Response["identity"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("identity")))
                    {
                        ["accounts"] = context.Response["accounts"]
                    },

                    // Calendly returns a nested "resource" object.
                    ProviderTypes.Calendly => new(context.Response["resource"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("resource"))),

                    // Disqus returns a nested "response" object.
                    ProviderTypes.Disqus => new(context.Response["response"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("response"))),

                    // Exact Online returns a "results" array nested in a "d" node and containing a single element.
                    ProviderTypes.ExactOnline => new(context.Response["d"]?["results"]?[0]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("d/results/0"))),

                    // Fitbit, Todoist, and Zendesk return a nested "user" object.
                    ProviderTypes.Fitbit or ProviderTypes.Todoist or ProviderTypes.Zendesk
                        => new(context.Response["user"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("user"))),

                    // Harvest returns a nested "user" object and a collection of "accounts".
                    ProviderTypes.Harvest => new(context.Response["user"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("user")))
                    {
                        ["accounts"] = context.Response["accounts"]
                    },

                    // These providers return a nested "data" object.
                    ProviderTypes.Kook    or ProviderTypes.Kroger    or
                    ProviderTypes.Patreon or ProviderTypes.Pipedrive or ProviderTypes.Twitter
                        => new(context.Response["data"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("data"))),

                    // Meetup returns a nested "self" object that is itself nested in a GraphQL "data" node.
                    ProviderTypes.Meetup => new(context.Response["data"]?["self"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("data/self"))),

                    // Nextcloud returns a nested "data" object that is itself nested in a "ocs" node.
                    ProviderTypes.Nextcloud => new(context.Response["ocs"]?["data"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("ocs/data"))),

                    // ServiceChannel returns a nested "UserProfile" object.
                    ProviderTypes.ServiceChannel => new(context.Response["UserProfile"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("UserProfile"))),

                    // StackExchange returns an "items" array containing a single element.
                    ProviderTypes.StackExchange => new(context.Response["items"]?[0]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("items/0"))),

                    // SubscribeStar returns a nested "user" object that is itself nested in a GraphQL "data" node.
                    ProviderTypes.SubscribeStar => new(context.Response["data"]?["user"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("data/user"))),

                    // Tumblr returns a nested "user" object that is itself nested in a "response" node.
                    ProviderTypes.Tumblr => new(context.Response["response"]?["user"]?.GetNamedParameters() ??
                        throw new InvalidOperationException(SR.FormatID0334("response/user"))),

                    _ => context.Response
                };

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for mapping non-standard response parameters
        /// to their standard equivalent for the providers that require it.
        /// </summary>
        public sealed class MapNonStandardResponseParameters : IOpenIddictClientHandler<ExtractUserInfoResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ExtractUserInfoResponseContext>()
                    .UseSingletonHandler<MapNonStandardResponseParameters>()
                    .SetOrder(UnwrapUserInfoResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractUserInfoResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(context.Response is not null, SR.GetResourceString(SR.ID4007));

                // Note: Wikimedia returns a non-standard "sub" claim formatted as an integer instead of a string.
                if (context.Registration.ProviderType is ProviderTypes.Wikimedia)
                {
                    context.Response[Claims.Subject] = (string?) context.Response[Claims.Subject];
                }
                
                // Note: Clever returns a non-standard "name" claim formatted as a JSON object.
                else if (context.Registration.ProviderType is ProviderTypes.Clever)
                {
                    var name = context.Response[Claims.Name]?.GetNamedParameters();
                    if (name is not null)
                    {
                        context.Response[Claims.Name] = $"{name["first"]} {name["last"]}";
                        context.Response[Claims.FamilyName] = name["last"];
                        context.Response[Claims.GivenName] = name["first"];
                    }
                }

                return default;
            }
        }
    }
}

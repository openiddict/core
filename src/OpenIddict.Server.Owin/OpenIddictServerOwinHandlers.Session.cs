/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Owin;

namespace OpenIddict.Server.Owin;

public static partial class OpenIddictServerOwinHandlers
{
    public static class Session
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * End-session request extraction:
             */
            ExtractGetOrPostRequest<ExtractEndSessionRequestContext>.Descriptor,

            /*
             * End-session request handling:
             */
            EnablePassthroughMode<HandleEndSessionRequestContext, RequireEndSessionEndpointPassthroughEnabled>.Descriptor,

            /*
             * End-session response processing:
             */
            AttachHttpResponseCode<ApplyEndSessionResponseContext>.Descriptor,
            AttachOwinResponseChallenge<ApplyEndSessionResponseContext>.Descriptor,
            SuppressFormsAuthenticationRedirect<ApplyEndSessionResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyEndSessionResponseContext>.Descriptor,
            ProcessSelfRedirection.Descriptor,
            ProcessQueryResponse.Descriptor,
            ProcessHostRedirectionResponse.Descriptor,
            ProcessPassthroughErrorResponse<ApplyEndSessionResponseContext, RequireEndSessionEndpointPassthroughEnabled>.Descriptor,
            ProcessLocalErrorResponse<ApplyEndSessionResponseContext>.Descriptor,
            ProcessEmptyResponse<ApplyEndSessionResponseContext>.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for restoring cached requests from the request_id, if specified.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        [Obsolete("This event handler is obsolete and will be removed in a future version.")]
        public sealed class RestoreCachedRequestParameters : IOpenIddictServerHandler<ExtractEndSessionRequestContext>
        {
            public RestoreCachedRequestParameters() => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            public RestoreCachedRequestParameters(IDistributedCache cache)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractEndSessionRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .AddFilter<RequireEndSessionRequestCachingEnabled>()
                    .UseSingletonHandler<RestoreCachedRequestParameters>()
                    .SetOrder(ExtractGetOrPostRequest<ExtractEndSessionRequestContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractEndSessionRequestContext context)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));
        }

        /// <summary>
        /// Contains the logic responsible for caching end session requests, if applicable.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        [Obsolete("This event handler is obsolete and will be removed in a future version.")]
        public sealed class CacheRequestParameters : IOpenIddictServerHandler<ExtractEndSessionRequestContext>
        {
            public CacheRequestParameters() => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            public CacheRequestParameters(
                IDistributedCache cache,
                IOptionsMonitor<OpenIddictServerOwinOptions> options)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractEndSessionRequestContext>()
                    .AddFilter<RequireOwinRequest>()
                    .AddFilter<RequireEndSessionRequestCachingEnabled>()
                    .UseSingletonHandler<CacheRequestParameters>()
                    .SetOrder(RestoreCachedRequestParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractEndSessionRequestContext context)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));
        }

        /// <summary>
        /// Contains the logic responsible for removing cached end session requests from the distributed cache.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        [Obsolete("This event handler is obsolete and will be removed in a future version.")]
        public sealed class RemoveCachedRequest : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
        {
            public RemoveCachedRequest() => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            public RemoveCachedRequest(IDistributedCache cache)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
                    .AddFilter<RequireOwinRequest>()
                    .AddFilter<RequireEndSessionRequestCachingEnabled>()
                    .UseSingletonHandler<RemoveCachedRequest>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyEndSessionResponseContext context)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));
        }

        /// <summary>
        /// Contains the logic responsible for processing end session responses requiring a self-redirection.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public sealed class ProcessSelfRedirection : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessSelfRedirection>()
                    .SetOrder(250_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyEndSessionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context is not { BaseUri.IsAbsoluteUri: true, RequestUri.IsAbsoluteUri: true })
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0127));
                }

                if (string.IsNullOrEmpty(context.Response.RequestUri))
                {
                    return default;
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                var location = context.RequestUri.GetLeftPart(UriPartial.Path);
                foreach (var (key, value) in
                    from parameter in context.Response.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select (parameter.Key, Value: value))
                {
                    location = WebUtilities.AddQueryString(location, key, value);
                }

                response.Redirect(location);
                context.HandleRequest();
                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing end session responses.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public sealed class ProcessQueryResponse : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessQueryResponse>()
                    .SetOrder(ProcessSelfRedirection.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyEndSessionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                {
                    return default;
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6151), context.PostLogoutRedirectUri, context.Response);

                var location = context.PostLogoutRedirectUri;

                // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                // For consistency, multiple parameters with the same name are also supported by this endpoint.
                foreach (var (key, value) in
                    from parameter in context.Response.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select (parameter.Key, Value: value))
                {
                    location = WebUtilities.AddQueryString(location, key, value);
                }

                response.Redirect(location);
                context.HandleRequest();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing end session responses that should trigger a host redirection.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by OWIN.
        /// </summary>
        public sealed class ProcessHostRedirectionResponse : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
                    .AddFilter<RequireOwinRequest>()
                    .UseSingletonHandler<ProcessHostRedirectionResponse>()
                    .SetOrder(ProcessPassthroughErrorResponse<ApplyEndSessionResponseContext, RequireEndSessionEndpointPassthroughEnabled>.Descriptor.Order + 250)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyEndSessionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to OWIN requests. If The OWIN request cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetOwinRequest()?.Context.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0120));

                // Note: this handler only executes if no post_logout_redirect_uri was specified
                // and if the response doesn't correspond to an error, that must be handled locally.
                if (!string.IsNullOrEmpty(context.PostLogoutRedirectUri) ||
                    !string.IsNullOrEmpty(context.Response.Error))
                {
                    return default;
                }

                var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
                if (properties is not null && !string.IsNullOrEmpty(properties.RedirectUri))
                {
                    response.Redirect(properties.RedirectUri);

                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6144));
                    context.HandleRequest();
                }

                return default;
            }
        }
    }
}

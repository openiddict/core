/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace OpenIddict.Server.AspNetCore;

public static partial class OpenIddictServerAspNetCoreHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Authorization request extraction:
             */
            ExtractGetOrPostRequest<ExtractAuthorizationRequestContext>.Descriptor,

            /*
             * Authorization request handling:
             */
            EnablePassthroughMode<HandleAuthorizationRequestContext, RequireAuthorizationEndpointPassthroughEnabled>.Descriptor,

            /*
             * Authorization response processing:
             */
            AttachHttpResponseCode<ApplyAuthorizationResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyAuthorizationResponseContext>.Descriptor,
            ProcessSelfRedirection.Descriptor,
            ProcessFormPostResponse.Descriptor,
            ProcessQueryResponse.Descriptor,
            ProcessFragmentResponse.Descriptor,
            ProcessPassthroughErrorResponse<ApplyAuthorizationResponseContext, RequireAuthorizationEndpointPassthroughEnabled>.Descriptor,
            ProcessStatusCodePagesErrorResponse<ApplyAuthorizationResponseContext>.Descriptor,
            ProcessLocalErrorResponse<ApplyAuthorizationResponseContext>.Descriptor,

            /*
             * Pushed authorization request extraction:
             */
            ExtractPostRequest<ExtractPushedAuthorizationRequestContext>.Descriptor,
            ValidateClientAuthenticationMethod<ExtractPushedAuthorizationRequestContext>.Descriptor,
            ExtractBasicAuthenticationCredentials<ExtractPushedAuthorizationRequestContext>.Descriptor,

            /*
             * Pushed authorization response processing:
             */
            AttachHttpResponseCode<ApplyPushedAuthorizationResponseContext>.Descriptor,
            AttachCacheControlHeader<ApplyPushedAuthorizationResponseContext>.Descriptor,
            AttachWwwAuthenticateHeader<ApplyPushedAuthorizationResponseContext>.Descriptor,
            ProcessJsonResponse<ApplyPushedAuthorizationResponseContext>.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for restoring cached requests from the request_id, if specified.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        [Obsolete("This event handler is obsolete and will be removed in a future version.")]
        public sealed class RestoreCachedRequestParameters : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
        {
            public RestoreCachedRequestParameters() => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            public RestoreCachedRequestParameters(IDistributedCache cache)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .AddFilter<RequireAuthorizationRequestCachingEnabled>()
                    .UseSingletonHandler<RestoreCachedRequestParameters>()
                    .SetOrder(ExtractGetOrPostRequest<ExtractAuthorizationRequestContext>.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));
        }

        /// <summary>
        /// Contains the logic responsible for caching authorization requests, if applicable.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        [Obsolete("This event handler is obsolete and will be removed in a future version.")]
        public sealed class CacheRequestParameters : IOpenIddictServerHandler<ExtractAuthorizationRequestContext>
        {
            public CacheRequestParameters() => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            public CacheRequestParameters(
                IDistributedCache cache,
                IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ExtractAuthorizationRequestContext>()
                    .AddFilter<RequireHttpRequest>()
                    .AddFilter<RequireAuthorizationRequestCachingEnabled>()
                    .UseSingletonHandler<CacheRequestParameters>()
                    .SetOrder(RestoreCachedRequestParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ExtractAuthorizationRequestContext context)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));
        }

        /// <summary>
        /// Contains the logic responsible for removing cached authorization requests from the distributed cache.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        [Obsolete("This event handler is obsolete and will be removed in a future version.")]
        public sealed class RemoveCachedRequest : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            public RemoveCachedRequest() => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            public RemoveCachedRequest(IDistributedCache cache)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .AddFilter<RequireHttpRequest>()
                    .AddFilter<RequireAuthorizationRequestCachingEnabled>()
                    .UseSingletonHandler<RemoveCachedRequest>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
                => throw new NotSupportedException(SR.GetResourceString(SR.ID0403));
        }

        /// <summary>
        /// Contains the logic responsible for processing authorization responses requiring a self-redirection.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public sealed class ProcessSelfRedirection : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessSelfRedirection>()
                    .SetOrder(250_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
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
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

#if SUPPORTS_MULTIPLE_VALUES_IN_QUERYHELPERS
                var location = QueryHelpers.AddQueryString(context.RequestUri.GetLeftPart(UriPartial.Path),
                    from parameter in context.Response.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select KeyValuePair.Create(parameter.Key, value));
#else
                var location = context.RequestUri.GetLeftPart(UriPartial.Path);

                foreach (var (key, value) in
                    from parameter in context.Response.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select (parameter.Key, Value: value))
                {
                    location = QueryHelpers.AddQueryString(location, key, value);
                }
#endif
                response.Redirect(location);
                context.HandleRequest();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing authorization responses using the form_post response mode.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public sealed class ProcessFormPostResponse : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            private readonly HtmlEncoder _encoder;

            public ProcessFormPostResponse(HtmlEncoder encoder)
                => _encoder = encoder;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessFormPostResponse>()
                    .SetOrder(ProcessSelfRedirection.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

                if (string.IsNullOrEmpty(context.RedirectUri) ||
                   !string.Equals(context.ResponseMode, ResponseModes.FormPost, StringComparison.Ordinal))
                {
                    return;
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6147), context.RedirectUri, context.Response);

                using var buffer = new MemoryStream();
                using var writer = new StreamWriter(buffer);

                writer.WriteLine("<!doctype html>");
                writer.WriteLine("<html>");
                writer.WriteLine("<body>");

                // While the redirect_uri parameter should be guarded against unknown values,
                // it's still safer to encode it to avoid cross-site scripting attacks
                // if the authorization server has a relaxed policy concerning redirect URIs.
                writer.WriteLine($@"<form name=""form"" method=""post"" action=""{_encoder.Encode(context.RedirectUri)}"">");

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
                    writer.WriteLine($@"<input type=""hidden"" name=""{_encoder.Encode(key)}"" value=""{_encoder.Encode(value)}"" />");
                }

                writer.WriteLine(@"<noscript>Click here to finish the authorization process: <input type=""submit"" /></noscript>");
                writer.WriteLine("</form>");
                writer.WriteLine("<script>document.form.submit();</script>");
                writer.WriteLine("</body>");
                writer.WriteLine("</html>");
                writer.Flush();

                response.StatusCode = 200;
                response.ContentLength = buffer.Length;
                response.ContentType = "text/html;charset=UTF-8";

                response.Headers[HeaderNames.CacheControl] = "no-cache";
                response.Headers[HeaderNames.Pragma] = "no-cache";
                response.Headers[HeaderNames.Expires] = "-1";

                buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                await buffer.CopyToAsync(response.Body, 4096);

                context.HandleRequest();
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing authorization responses using the query response mode.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public sealed class ProcessQueryResponse : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessQueryResponse>()
                    .SetOrder(ProcessFormPostResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

                if (string.IsNullOrEmpty(context.RedirectUri) ||
                   !string.Equals(context.ResponseMode, ResponseModes.Query, StringComparison.Ordinal))
                {
                    return default;
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6148), context.RedirectUri, context.Response);

                // Note: while initially not allowed by the core OAuth 2.0 specification, multiple parameters
                // with the same name are used by derived drafts like the OAuth 2.0 token exchange specification.
                // For consistency, multiple parameters with the same name are also supported by this endpoint.

#if SUPPORTS_MULTIPLE_VALUES_IN_QUERYHELPERS
                var location = QueryHelpers.AddQueryString(context.RedirectUri,
                    from parameter in context.Response.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select KeyValuePair.Create(parameter.Key, value));
#else
                var location = context.RedirectUri;

                foreach (var (key, value) in
                    from parameter in context.Response.GetParameters()
                    let values = (string?[]?) parameter.Value
                    where values is not null
                    from value in values
                    where !string.IsNullOrEmpty(value)
                    select (parameter.Key, Value: value))
                {
                    location = QueryHelpers.AddQueryString(location, key, value);
                }
#endif
                response.Redirect(location);
                context.HandleRequest();

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing authorization responses using the fragment response mode.
        /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
        /// </summary>
        public sealed class ProcessFragmentResponse : IOpenIddictServerHandler<ApplyAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyAuthorizationResponseContext>()
                    .AddFilter<RequireHttpRequest>()
                    .UseSingletonHandler<ProcessFragmentResponse>()
                    .SetOrder(ProcessQueryResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
                // this may indicate that the request was incorrectly processed by another server stack.
                var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

                if (string.IsNullOrEmpty(context.RedirectUri) ||
                   !string.Equals(context.ResponseMode, ResponseModes.Fragment, StringComparison.Ordinal))
                {
                    return default;
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6149), context.RedirectUri, context.Response);

                var builder = new StringBuilder(context.RedirectUri);

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
                    builder.Append(Contains(builder, '#') ? '&' : '#')
                           .Append(Uri.EscapeDataString(key))
                           .Append('=')
                           .Append(Uri.EscapeDataString(value));
                }

                response.Redirect(builder.ToString());
                context.HandleRequest();

                return default;

                static bool Contains(StringBuilder builder, char delimiter)
                {
                    for (var index = 0; index < builder.Length; index++)
                    {
                        if (builder[index] == delimiter)
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }
        }
    }
}

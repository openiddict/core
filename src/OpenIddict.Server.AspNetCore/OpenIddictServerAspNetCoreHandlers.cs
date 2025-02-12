/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using OpenIddict.Extensions;
using Properties = OpenIddict.Server.AspNetCore.OpenIddictServerAspNetCoreConstants.Properties;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Server.AspNetCore;

[EditorBrowsable(EditorBrowsableState.Never)]
public static partial class OpenIddictServerAspNetCoreHandlers
{
    public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
        /*
         * Top-level request processing:
         */
        ResolveRequestUri.Descriptor,
        ValidateTransportSecurityRequirement.Descriptor,
        ValidateHostHeader.Descriptor,

        /*
         * Challenge processing:
         */
        ResolveHostChallengeProperties.Descriptor,
        AttachHostChallengeError.Descriptor,

        /*
         * Sign-in processing:
         */
        ResolveHostSignInProperties.Descriptor,

        /*
         * Sign-out processing:
         */
        ResolveHostSignOutProperties.Descriptor,

        .. Authentication.DefaultHandlers,
        .. Device.DefaultHandlers,
        .. Discovery.DefaultHandlers,
        .. Exchange.DefaultHandlers,
        .. Introspection.DefaultHandlers,
        .. Revocation.DefaultHandlers,
        .. Session.DefaultHandlers,
        .. UserInfo.DefaultHandlers
    ]);

    /// <summary>
    /// Contains the logic responsible for resolving the request URI from the ASP.NET Core environment.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ResolveRequestUri : IOpenIddictServerHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ResolveRequestUri>()
                .SetOrder(int.MinValue + 50_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // OpenIddict supports both absolute and relative URIs for all its endpoints, but only absolute
            // URIs can be properly canonicalized by the BCL System.Uri class (e.g './path/../' is normalized
            // to './' once the URI is fully constructed). At this stage of the request processing, rejecting
            // requests that lack the host information (e.g because HTTP/1.0 was used and no Host header was
            // sent by the HTTP client) is not desirable as it would affect all requests, including requests
            // that are not meant to be handled by OpenIddict itself. To avoid that, a fake host is temporarily
            // used to build an absolute base URI and a request URI that will be used to determine whether the
            // received request matches one of the URIs assigned to an OpenIddict endpoint. If the request
            // is later handled by OpenIddict, an additional check will be made to require the Host header.

            (context.BaseUri, context.RequestUri) = request.Host switch
            {
                { HasValue: true } host => (
                    BaseUri: new Uri(request.Scheme + Uri.SchemeDelimiter + host + request.PathBase, UriKind.Absolute),
                    RequestUri: new Uri(request.GetEncodedUrl(), UriKind.Absolute)),

                { HasValue: false } => (
                    BaseUri: new UriBuilder
                    {
                        Scheme = request.Scheme,
                        Path = request.PathBase.ToUriComponent()
                    }.Uri,
                    RequestUri: new UriBuilder
                    {
                        Scheme = request.Scheme,
                        Path = (request.PathBase + request.Path).ToUriComponent(),
                        Query = request.QueryString.ToUriComponent()
                    }.Uri)
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for rejecting OpenID Connect requests that don't use transport security.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ValidateTransportSecurityRequirement : IOpenIddictServerHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireTransportSecurityRequirementEnabled>()
                .UseSingletonHandler<ValidateTransportSecurityRequirement>()
                .SetOrder(InferEndpointType.Descriptor.Order + 250)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Don't require that transport security be used if the request is not handled by OpenIddict.
            if (context.EndpointType is not OpenIddictServerEndpointType.Unknown && !request.IsHttps)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2083),
                    uri: SR.FormatID8000(SR.ID2083));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the Host header extracted from the HTTP header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ValidateHostHeader : IOpenIddictServerHandler<ProcessRequestContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ValidateHostHeader>()
                .SetOrder(ValidateTransportSecurityRequirement.Descriptor.Order + 250)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessRequestContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Don't require that the request host be present if the request is not handled by OpenIddict.
            if (context.EndpointType is not OpenIddictServerEndpointType.Unknown && !request.Host.HasValue)
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.FormatID2081(HeaderNames.Host),
                    uri: SR.FormatID8000(SR.ID2081));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// ASP.NET Core authentication properties specified by the application that triggered the challenge operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ResolveHostChallengeProperties : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ResolveHostChallengeProperties>()
                .SetOrder(ValidateChallengeDemand.Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is { Items.Count: > 0 })
            {
                foreach (var property in properties.Items)
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            if (properties is { Parameters.Count: > 0 })
            {
                foreach (var parameter in properties.Parameters)
                {
                    context.Parameters[parameter.Key] = parameter.Value switch
                    {
                        OpenIddictParameter value => value,
                        JsonElement         value => new OpenIddictParameter(value),
                        bool                value => new OpenIddictParameter(value),
                        int                 value => new OpenIddictParameter(value),
                        long                value => new OpenIddictParameter(value),
                        string              value => new OpenIddictParameter(value),
                        string[]            value => new OpenIddictParameter(value),

#if SUPPORTS_JSON_NODES
                        JsonNode            value => new OpenIddictParameter(value),
#endif
                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0115))
                    };
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the error details using the ASP.NET Core authentication properties.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class AttachHostChallengeError : IOpenIddictServerHandler<ProcessChallengeContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<AttachHostChallengeError>()
                .SetOrder(AttachDefaultChallengeError.Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessChallengeContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is not null)
            {
                context.Response.Error = properties.GetString(Properties.Error);
                context.Response.ErrorDescription = properties.GetString(Properties.ErrorDescription);
                context.Response.ErrorUri = properties.GetString(Properties.ErrorUri);
                context.Response.Scope = properties.GetString(Properties.Scope);
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// ASP.NET Core authentication properties specified by the application that triggered the sign-in operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ResolveHostSignInProperties : IOpenIddictServerHandler<ProcessSignInContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignInContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ResolveHostSignInProperties>()
                .SetOrder(ValidateSignInDemand.Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignInContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is { Items.Count: > 0 })
            {
                foreach (var property in properties.Items)
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            if (properties is { Parameters.Count: > 0 })
            {
                foreach (var parameter in properties.Parameters)
                {
                    context.Parameters[parameter.Key] = parameter.Value switch
                    {
                        OpenIddictParameter value => value,
                        JsonElement         value => new OpenIddictParameter(value),
                        bool                value => new OpenIddictParameter(value),
                        int                 value => new OpenIddictParameter(value),
                        long                value => new OpenIddictParameter(value),
                        string              value => new OpenIddictParameter(value),
                        string[]            value => new OpenIddictParameter(value),

#if SUPPORTS_JSON_NODES
                        JsonNode            value => new OpenIddictParameter(value),
#endif
                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0115))
                    };
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for resolving the context-specific properties and parameters stored in the
    /// ASP.NET Core authentication properties specified by the application that triggered the sign-out operation.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ResolveHostSignOutProperties : IOpenIddictServerHandler<ProcessSignOutContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessSignOutContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ResolveHostSignOutProperties>()
                .SetOrder(ValidateSignOutDemand.Descriptor.Order - 500)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(ProcessSignOutContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            var properties = context.Transaction.GetProperty<AuthenticationProperties>(typeof(AuthenticationProperties).FullName!);
            if (properties is { Items.Count: > 0 })
            {
                foreach (var property in properties.Items)
                {
                    context.Properties[property.Key] = property.Value;
                }
            }

            if (properties is { Parameters.Count: > 0 })
            {
                foreach (var parameter in properties.Parameters)
                {
                    context.Parameters[parameter.Key] = parameter.Value switch
                    {
                        OpenIddictParameter value => value,
                        JsonElement         value => new OpenIddictParameter(value),
                        bool                value => new OpenIddictParameter(value),
                        int                 value => new OpenIddictParameter(value),
                        long                value => new OpenIddictParameter(value),
                        string              value => new OpenIddictParameter(value),
                        string[]            value => new OpenIddictParameter(value),

#if SUPPORTS_JSON_NODES
                        JsonNode            value => new OpenIddictParameter(value),
#endif
                        _ => throw new InvalidOperationException(SR.GetResourceString(SR.ID0115))
                    };
                }
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ExtractGetRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ExtractGetRequest<TContext>>()
                .SetOrder(ValidateTransportSecurityRequirement.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            if (HttpMethods.IsGet(request.Method))
            {
                context.Transaction.Request = new OpenIddictRequest(request.Query);
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from GET or POST HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ExtractGetOrPostRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ExtractGetOrPostRequest<TContext>>()
                .SetOrder(ExtractGetRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            if (HttpMethods.IsGet(request.Method))
            {
                context.Transaction.Request = new OpenIddictRequest(request.Query);
            }

            else if (HttpMethods.IsPost(request.Method))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization for more information.
                if (string.IsNullOrEmpty(request.ContentType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6138), HeaderNames.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(HeaderNames.ContentType),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6139), HeaderNames.ContentType, request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(HeaderNames.ContentType),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync(context.CancellationToken));
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting OpenID Connect requests from POST HTTP requests.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ExtractPostRequest<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ExtractPostRequest<TContext>>()
                .SetOrder(ExtractGetOrPostRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            if (HttpMethods.IsPost(request.Method))
            {
                // See http://openid.net/specs/openid-connect-core-1_0.html#FormSerialization for more information.
                if (string.IsNullOrEmpty(request.ContentType))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6138), HeaderNames.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2081(HeaderNames.ContentType),
                        uri: SR.FormatID8000(SR.ID2081));

                    return;
                }

                // May have media/type; charset=utf-8, allow partial match.
                if (!request.ContentType.StartsWith("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6139), HeaderNames.ContentType, request.ContentType);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2082(HeaderNames.ContentType),
                        uri: SR.FormatID8000(SR.ID2082));

                    return;
                }

                context.Transaction.Request = new OpenIddictRequest(await request.ReadFormAsync(context.CancellationToken));
            }

            else
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6137), request.Method);

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2084),
                    uri: SR.FormatID8000(SR.ID2084));

                return;
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for validating the authentication method used by the client application.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ValidateClientAuthenticationMethod<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ValidateClientAuthenticationMethod<TContext>>()
                .SetOrder(ExtractPostRequest<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Reject requests that use client_secret_post if support was explicitly disabled in the options.
            if (!string.IsNullOrEmpty(context.Transaction.Request.ClientSecret) &&
                !context.Options.ClientAuthenticationMethods.Contains(ClientAuthenticationMethods.ClientSecretPost))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6227), ClientAuthenticationMethods.ClientSecretPost);

                context.Reject(
                    error: Errors.InvalidClient,
                    description: SR.FormatID2174(ClientAuthenticationMethods.ClientSecretPost),
                    uri: SR.FormatID8000(SR.ID2174));

                return default;
            }

            // Reject requests that use client_secret_basic if support was explicitly disabled in the options.
            //
            // Note: the client_secret_jwt authentication method is not supported by OpenIddict out-of-the-box but
            // is specified here to account for custom implementations that explicitly add client_secret_jwt support.
            string? header = request.Headers[HeaderNames.Authorization];
            if (!string.IsNullOrEmpty(header) && header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase) &&
                !context.Options.ClientAuthenticationMethods.Contains(ClientAuthenticationMethods.ClientSecretBasic))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6227), ClientAuthenticationMethods.ClientSecretBasic);

                context.Reject(
                    error: Errors.InvalidClient,
                    description: SR.FormatID2174(ClientAuthenticationMethods.ClientSecretBasic),
                    uri: SR.FormatID8000(SR.ID2174));

                return default;
            }

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting client credentials from the standard HTTP Authorization header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ExtractBasicAuthenticationCredentials<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ExtractBasicAuthenticationCredentials<TContext>>()
                .SetOrder(ValidateClientAuthenticationMethod<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            string? header = request.Headers[HeaderNames.Authorization];
            if (string.IsNullOrEmpty(header) || !header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
            {
                return default;
            }

            // At this point, reject requests that use multiple client authentication methods.
            // See https://tools.ietf.org/html/rfc6749#section-2.3 for more information.
            if (!string.IsNullOrEmpty(context.Transaction.Request.ClientAssertion) ||
                !string.IsNullOrEmpty(context.Transaction.Request.ClientSecret))
            {
                context.Logger.LogInformation(SR.GetResourceString(SR.ID6140));

                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2087),
                    uri: SR.FormatID8000(SR.ID2087));

                return default;
            }

            try
            {
                var value = header["Basic ".Length..].Trim();
                var data = Encoding.ASCII.GetString(Convert.FromBase64String(value));

                var index = data.IndexOf(':');
                if (index < 0)
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.GetResourceString(SR.ID2055),
                        uri: SR.FormatID8000(SR.ID2055));

                    return default;
                }

                // Attach the basic authentication credentials to the request message.
                context.Transaction.Request.ClientId = UnescapeDataString(data[..index]);
                context.Transaction.Request.ClientSecret = UnescapeDataString(data[(index + 1)..]);

                return default;
            }

            catch (Exception exception) when (!OpenIddictHelpers.IsFatal(exception))
            {
                context.Reject(
                    error: Errors.InvalidRequest,
                    description: SR.GetResourceString(SR.ID2055),
                    uri: SR.FormatID8000(SR.ID2055));

                return default;
            }

            static string? UnescapeDataString(string data)
            {
                if (string.IsNullOrEmpty(data))
                {
                    return null;
                }

                return Uri.UnescapeDataString(data.Replace("+", "%20"));
            }
        }
    }

    /// <summary>
    /// Contains the logic responsible for extracting an access token from the standard HTTP Authorization header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ExtractAccessToken<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseValidatingContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ExtractAccessToken<TContext>>()
                .SetOrder(ExtractBasicAuthenticationCredentials<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var request = context.Transaction.GetHttpRequest() ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            Debug.Assert(context.Transaction.Request is not null, SR.GetResourceString(SR.ID4008));

            string? header = request.Headers[HeaderNames.Authorization];
            if (string.IsNullOrEmpty(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                return default;
            }

            // Attach the access token to the request message.
            context.Transaction.Request.AccessToken = header["Bearer ".Length..];

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for enabling the pass-through mode for the received request.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class EnablePassthroughMode<TContext, TFilter> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
        where TFilter : IOpenIddictServerHandlerFilter<TContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<TFilter>()
                .UseSingletonHandler<EnablePassthroughMode<TContext, TFilter>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            switch (context.EndpointType)
            {
                // When authorization request caching is enabled and the request doesn't contain a
                // request_uri yet, do not enable the pass-through mode to allow OpenIddict to trigger
                // a sign-in operation that will generate and attach a request token to the parameters.
                case OpenIddictServerEndpointType.Authorization when
                    context.Options.EnableAuthorizationRequestCaching &&
                    string.IsNullOrEmpty(context.Transaction.Request?.RequestUri):
                    return default;

                // When end session request caching is enabled and the request doesn't contain a
                // request_uri yet, do not enable the pass-through mode to allow OpenIddict to trigger
                // a sign-in operation that will generate and attach a request token to the parameters.
                case OpenIddictServerEndpointType.EndSession when
                    context.Options.EnableEndSessionRequestCaching &&
                    string.IsNullOrEmpty(context.Transaction.Request?.RequestUri):
                    return default;

            }

            context.SkipRequest();
            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching an appropriate HTTP status code.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class AttachHttpResponseCode<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<AttachHttpResponseCode<TContext>>()
                .SetOrder(100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            response.StatusCode = (context.EndpointType, context.Transaction.Response.Error) switch
            {
                // Note: for pushed authorization responses, the returned HTTP status code MUST be 201.
                // See https://datatracker.ietf.org/doc/html/rfc9126#section-2.2 for more information.
                (OpenIddictServerEndpointType.PushedAuthorization, null or { Length: 0 }) => 201,

                // Note: the default code may be replaced by another handler (e.g when doing redirects).
                (_, null or { Length: 0 }) => 200,

                // Unlike other server endpoints, errors returned by the userinfo endpoint follow the same logic as
                // errors returned by API endpoints implementing bearer token authentication and MUST be returned
                // as part of the standard WWW-Authenticate header. For more information, see
                // https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError.
                (OpenIddictServerEndpointType.UserInfo, Errors.InvalidToken       or Errors.MissingToken)      => 401,
                (OpenIddictServerEndpointType.UserInfo, Errors.InsufficientAccess or Errors.InsufficientScope) => 403,

                // When client authentication is made using basic authentication, the authorization server
                // MUST return a 401 response with a valid WWW-Authenticate header containing the HTTP Basic
                // authentication scheme. A similar error MAY be returned even when using client_secret_post.
                // To simplify the logic, a 401 response with the Basic scheme is returned for invalid_client
                // errors, even if credentials were specified in the form, as allowed by the specification.
                (not OpenIddictServerEndpointType.UserInfo, Errors.InvalidClient) => 401,

                (_, Errors.ServerError) => 500,

                // Note: unless specified otherwise, errors are expected to result in 400 responses.
                // See https://datatracker.ietf.org/doc/html/rfc6749#section-5.2 for more information.
                _ => 400
            };

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching the appropriate HTTP response cache headers.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class AttachCacheControlHeader<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<AttachCacheControlHeader<TContext>>()
                .SetOrder(AttachHttpResponseCode<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // Prevent the response from being cached.
            response.Headers[HeaderNames.CacheControl] = "no-store";
            response.Headers[HeaderNames.Pragma] = "no-cache";
            response.Headers[HeaderNames.Expires] = "Thu, 01 Jan 1970 00:00:00 GMT";

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for attaching errors details to the WWW-Authenticate header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class AttachWwwAuthenticateHeader<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public AttachWwwAuthenticateHeader(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<AttachWwwAuthenticateHeader<TContext>>()
                .SetOrder(AttachCacheControlHeader<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return default;
            }

            var scheme = (context.EndpointType, context.Transaction.Response.Error) switch
            {
                // Unlike other server endpoints, errors returned by the userinfo endpoint follow the same
                // logic as errors returned by API endpoints implementing bearer token authentication and
                // MUST be returned as part of the standard WWW-Authenticate header. For more information,
                // see https://openid.net/specs/openid-connect-core-1_0.html#UserInfoError.
                (OpenIddictServerEndpointType.UserInfo, _) => Schemes.Bearer,

                // When client authentication is made using basic authentication, the authorization server
                // MUST return a 401 response with a valid WWW-Authenticate header containing the HTTP Basic
                // authentication scheme. A similar error MAY be returned even when using client_secret_post.
                // To simplify the logic, a 401 response with the Basic scheme is returned for invalid_client
                // errors, even if credentials were specified in the form, as allowed by the specification.
                (_, Errors.InvalidClient) => Schemes.Basic,

                // For all other errors, don't return a WWW-Authenticate header and return server errors
                // as formatted JSON responses, as required by the OAuth 2.0 base specification.
                _ => null
            };

            if (string.IsNullOrEmpty(scheme))
            {
                return default;
            }

            var parameters = new Dictionary<string, string>(StringComparer.Ordinal);

            // If a realm was configured in the options, attach it to the parameters.
            if (_options.CurrentValue.Realm is string { Length: > 0 } realm)
            {
                parameters[Parameters.Realm] = realm;
            }

            foreach (var parameter in context.Transaction.Response.GetParameters())
            {
                // Note: the error details are only included if the error was not caused by a missing token, as recommended
                // by the OAuth 2.0 bearer specification: https://tools.ietf.org/html/rfc6750#section-3.1.
                if (context.Transaction.Response.Error is Errors.MissingToken &&
                    parameter.Key is Parameters.Error            or
                                     Parameters.ErrorDescription or
                                     Parameters.ErrorUri)
                {
                    continue;
                }

                // Ignore values that can't be represented as unique strings.
                var value = (string?) parameter.Value;
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                parameters[parameter.Key] = value;
            }

            var builder = new StringBuilder(scheme);

            foreach (var parameter in parameters)
            {
                builder.Append(' ');
                builder.Append(parameter.Key);
                builder.Append('=');
                builder.Append('"');
                builder.Append(parameter.Value.Replace("\"", "\\\""));
                builder.Append('"');
                builder.Append(',');
            }

            // If the WWW-Authenticate header ends with a comma, remove it.
            if (builder[^1] == ',')
            {
                builder.Remove(builder.Length - 1, 1);
            }

            response.Headers.Append(HeaderNames.WWWAuthenticate, builder.ToString());

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing challenge responses that contain a WWW-Authenticate header.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ProcessChallengeErrorResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ProcessChallengeErrorResponse<TContext>>()
                .SetOrder(AttachWwwAuthenticateHeader<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            // If the response doesn't contain a WWW-Authenticate header, don't return an empty response.
            if (!response.Headers.ContainsKey(HeaderNames.WWWAuthenticate))
            {
                return default;
            }

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6141), context.Transaction.Response);
            context.HandleRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that must be returned as JSON.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ProcessJsonResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
    {
        private readonly IOptionsMonitor<OpenIddictServerAspNetCoreOptions> _options;

        public ProcessJsonResponse(IOptionsMonitor<OpenIddictServerAspNetCoreOptions> options)
            => _options = options ?? throw new ArgumentNullException(nameof(options));

        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ProcessJsonResponse<TContext>>()
                .SetOrder(500_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6142), context.Transaction.Response);

            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
            {
                Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                Indented = !_options.CurrentValue.SuppressJsonResponseIndentation
            });

            context.Transaction.Response.WriteTo(writer);
            writer.Flush();

            response.ContentLength = stream.Length;
            response.ContentType = "application/json;charset=UTF-8";

            stream.Seek(offset: 0, loc: SeekOrigin.Begin);
            await stream.CopyToAsync(response.Body, 4096, context.CancellationToken);

            context.HandleRequest();
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that must be handled by another
    /// middleware in the pipeline at a later stage (e.g an ASP.NET Core MVC action or a NancyFX module).
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ProcessPassthroughErrorResponse<TContext, TFilter> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
        where TFilter : IOpenIddictServerHandlerFilter<TContext>
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireErrorPassthroughEnabled>()
                .AddFilter<TFilter>()
                .UseSingletonHandler<ProcessPassthroughErrorResponse<TContext, TFilter>>()
                .SetOrder(ProcessJsonResponse<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return default;
            }

            context.SkipRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses handled by the status code pages middleware.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ProcessStatusCodePagesErrorResponse<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .AddFilter<RequireStatusCodePagesIntegrationEnabled>()
                .UseSingletonHandler<ProcessStatusCodePagesErrorResponse<TContext>>()
                .SetOrder(ProcessPassthroughErrorResponse<TContext, IOpenIddictServerHandlerFilter<TContext>>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return default;
            }

            // Determine if the status code pages middleware has been enabled for this request.
            // If it was not registered or enabled, let the default OpenIddict server handlers render
            // a default error page instead of delegating the rendering to the status code middleware.
            var feature = response.HttpContext.Features.Get<IStatusCodePagesFeature>();
            if (feature is not { Enabled: true })
            {
                return default;
            }

            // Mark the request as fully handled to prevent the other OpenIddict server handlers
            // from displaying the default error page and to allow the status code pages middleware
            // to rewrite the response using the logic defined by the developer when registering it.
            context.HandleRequest();

            return default;
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing context responses that must be returned as plain-text.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ProcessLocalErrorResponse<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ProcessLocalErrorResponse<TContext>>()
                .SetOrder(ProcessStatusCodePagesErrorResponse<TContext>.Descriptor.Order + 1_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public async ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            // This handler only applies to ASP.NET Core requests. If the HTTP context cannot be resolved,
            // this may indicate that the request was incorrectly processed by another server stack.
            var response = context.Transaction.GetHttpRequest()?.HttpContext.Response ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0114));

            Debug.Assert(context.Transaction.Response is not null, SR.GetResourceString(SR.ID4007));

            if (string.IsNullOrEmpty(context.Transaction.Response.Error))
            {
                return;
            }

            // Don't return the state originally sent by the client application.
            context.Transaction.Response.State = null;

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6143), context.Transaction.Response);

            using var stream = new MemoryStream();
            using var writer = new StreamWriter(stream);

            foreach (var parameter in context.Transaction.Response.GetParameters())
            {
                // Ignore null or empty parameters, including JSON
                // objects that can't be represented as strings.
                var value = (string?) parameter.Value;
                if (string.IsNullOrEmpty(value))
                {
                    continue;
                }

                writer.Write(parameter.Key);
                writer.Write(':');
                writer.Write(value);
                writer.WriteLine();
            }

            writer.Flush();

            response.ContentLength = stream.Length;
            response.ContentType = "text/plain;charset=UTF-8";

            stream.Seek(offset: 0, loc: SeekOrigin.Begin);
            await stream.CopyToAsync(response.Body, 4096, context.CancellationToken);

            context.HandleRequest();
        }
    }

    /// <summary>
    /// Contains the logic responsible for processing OpenID Connect responses that don't specify any parameter.
    /// Note: this handler is not used when the OpenID Connect request is not initially handled by ASP.NET Core.
    /// </summary>
    public sealed class ProcessEmptyResponse<TContext> : IOpenIddictServerHandler<TContext>
        where TContext : BaseRequestContext
    {
        /// <summary>
        /// Gets the default descriptor definition assigned to this handler.
        /// </summary>
        public static OpenIddictServerHandlerDescriptor Descriptor { get; }
            = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                .AddFilter<RequireHttpRequest>()
                .UseSingletonHandler<ProcessEmptyResponse<TContext>>()
                .SetOrder(int.MaxValue - 100_000)
                .SetType(OpenIddictServerHandlerType.BuiltIn)
                .Build();

        /// <inheritdoc/>
        public ValueTask HandleAsync(TContext context)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            context.Logger.LogInformation(SR.GetResourceString(SR.ID6145));
            context.HandleRequest();

            return default;
        }
    }
}

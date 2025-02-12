/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Extensions;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Session
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * End-session request top-level processing:
             */
            ExtractEndSessionRequest.Descriptor,
            ValidateEndSessionRequest.Descriptor,
            HandleEndSessionRequest.Descriptor,
            ApplyEndSessionResponse<ProcessErrorContext>.Descriptor,
            ApplyEndSessionResponse<ProcessRequestContext>.Descriptor,
            ApplyEndSessionResponse<ProcessSignInContext>.Descriptor,
            ApplyEndSessionResponse<ProcessSignOutContext>.Descriptor,

            /*
             * End-session request validation:
             */
            ValidateRequestUriParameter.Descriptor,
            ValidatePostLogoutRedirectUriParameter.Descriptor,
            ValidateAuthentication.Descriptor,
            RestorePushedAuthorizationRequestParameters.Descriptor,
            ValidateClientPostLogoutRedirectUri.Descriptor,
            ValidateEndpointPermissions.Descriptor,
            ValidateAuthorizedParty.Descriptor,

            /*
             * End-session request handling:
             */
            AttachPrincipal.Descriptor,

            /*
             * End-session response processing:
             */
            AttachPostLogoutRedirectUri.Descriptor,
            AttachResponseState.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for extracting end session requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractEndSessionRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractEndSessionRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireEndSessionRequest>()
                    .UseScopedHandler<ExtractEndSessionRequest>()
                    .SetOrder(100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ExtractEndSessionRequestContext(context.Transaction);
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

                if (notification.Request is null)
                {
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0050));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6124), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating end session requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateEndSessionRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateEndSessionRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireEndSessionRequest>()
                    .UseScopedHandler<ValidateEndSessionRequest>()
                    .SetOrder(ExtractEndSessionRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateEndSessionRequestContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the redirect_uri without triggering a new validation process.
                context.Transaction.SetProperty(typeof(ValidateEndSessionRequestContext).FullName!, notification);

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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6125));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling end session requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleEndSessionRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleEndSessionRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireEndSessionRequest>()
                    .UseScopedHandler<HandleEndSessionRequest>()
                    .SetOrder(ValidateEndSessionRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleEndSessionRequestContext(context.Transaction);
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

                if (notification.IsSignOutTriggered)
                {
                    var @event = new ProcessSignOutContext(context.Transaction)
                    {
                        Response = new OpenIddictResponse()
                    };

                    if (notification.Parameters.Count > 0)
                    {
                        foreach (var parameter in notification.Parameters)
                        {
                            @event.Parameters.Add(parameter.Key, parameter.Value);
                        }
                    }

                    await _dispatcher.DispatchAsync(@event);

                    if (@event.IsRequestHandled)
                    {
                        context.HandleRequest();
                        return;
                    }

                    else if (@event.IsRequestSkipped)
                    {
                        context.SkipRequest();
                        return;
                    }

                    else if (@event.IsRejected)
                    {
                        context.Reject(
                            error: @event.Error ?? Errors.InvalidRequest,
                            description: @event.ErrorDescription,
                            uri: @event.ErrorUri);
                        return;
                    }
                }

                else if (context.Options.EnableEndSessionRequestCaching &&
                    string.IsNullOrEmpty(context.Transaction.Request?.RequestUri))
                {
                    var @event = new ProcessSignInContext(context.Transaction)
                    {
                        Principal = new ClaimsPrincipal(new ClaimsIdentity()),
                        Response = new OpenIddictResponse()
                    };

                    if (notification.Parameters.Count > 0)
                    {
                        foreach (var parameter in notification.Parameters)
                        {
                            @event.Parameters.Add(parameter.Key, parameter.Value);
                        }
                    }

                    await _dispatcher.DispatchAsync(@event);

                    if (@event.IsRequestHandled)
                    {
                        context.HandleRequest();
                        return;
                    }

                    else if (@event.IsRequestSkipped)
                    {
                        context.SkipRequest();
                        return;
                    }

                    else if (@event.IsRejected)
                    {
                        context.Reject(
                            error: notification.Error ?? Errors.InvalidRequest,
                            description: notification.ErrorDescription,
                            uri: notification.ErrorUri);
                        return;
                    }
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0051));
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing sign-in responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyEndSessionResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyEndSessionResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireEndSessionRequest>()
                    .UseScopedHandler<ApplyEndSessionResponse<TContext>>()
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

                var notification = new ApplyEndSessionResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0052));
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting authorization requests that specify an invalid request_uri parameter.
        /// </summary>
        public sealed class ValidateRequestUriParameter : IOpenIddictServerHandler<ValidateEndSessionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateEndSessionRequestContext>()
                    .UseSingletonHandler<ValidateRequestUriParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.Request.RequestUri))
                {
                    return default;
                }

                // OpenIddict only supports "request_uri" parameters containing a reference to a request token
                // generated via the automatic request caching feature. Since OpenIddict uses a specific URN
                // prefix for request tokens it generates, all the other values are automatically rejected.
                if (!context.Request.RequestUri.StartsWith(RequestUris.Prefixes.Generic, StringComparison.Ordinal))
                {
                    context.Reject(
                        error: Errors.RequestUriNotSupported,
                        description: SR.FormatID2028(Parameters.RequestUri),
                        uri: SR.FormatID8000(SR.ID2028));

                    return default;
                }

                // For consistency with authorization requests, the client_id parameter
                // is also required when using a request_uri parameter is present.
                if (string.IsNullOrEmpty(context.Request.ClientId))
                {
                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2037(Parameters.RequestUri, Parameters.ClientId),
                        uri: SR.FormatID8000(SR.ID2037));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting end session requests that specify an invalid post_logout_redirect_uri parameter.
        /// </summary>
        public sealed class ValidatePostLogoutRedirectUriParameter : IOpenIddictServerHandler<ValidateEndSessionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateEndSessionRequestContext>()
                    .UseSingletonHandler<ValidatePostLogoutRedirectUriParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                {
                    return default;
                }

                // If an optional post_logout_redirect_uri was provided, validate it.
                if (!Uri.TryCreate(context.PostLogoutRedirectUri, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6126), Parameters.PostLogoutRedirectUri, context.PostLogoutRedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2030(Parameters.PostLogoutRedirectUri),
                        uri: SR.FormatID8000(SR.ID2030));

                    return default;
                }

                if (!string.IsNullOrEmpty(uri.Fragment))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6127), Parameters.PostLogoutRedirectUri, context.PostLogoutRedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2031(Parameters.PostLogoutRedirectUri),
                        uri: SR.FormatID8000(SR.ID2031));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for applying the authentication logic to end session requests.
        /// </summary>
        public sealed class ValidateAuthentication : IOpenIddictServerHandler<ValidateEndSessionRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateAuthentication(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateEndSessionRequestContext>()
                    .UseScopedHandler<ValidateAuthentication>()
                    .SetOrder(ValidatePostLogoutRedirectUriParameter.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ProcessAuthenticationContext(context.Transaction);
                await _dispatcher.DispatchAsync(notification);

                // Store the context object in the transaction so it can be later retrieved by handlers
                // that want to access the authentication result without triggering a new authentication flow.
                context.Transaction.SetProperty(typeof(ProcessAuthenticationContext).FullName!, notification);

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

                // Attach the security principals extracted from the tokens to the validation context.
                context.IdentityTokenHintPrincipal = notification.IdentityTokenPrincipal;
                context.RequestTokenPrincipal = notification.RequestTokenPrincipal;
            }
        }

        /// <summary>
        /// Contains the logic responsible for restoring the parameters attached to the pushed authorization request.
        /// </summary>
        public sealed class RestorePushedAuthorizationRequestParameters : IOpenIddictServerHandler<ValidateEndSessionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateEndSessionRequestContext>()
                    .UseSingletonHandler<RestorePushedAuthorizationRequestParameters>()
                    .SetOrder(ValidateAuthentication.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ValidateEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var value = context.RequestTokenPrincipal?.GetClaim(Claims.Private.RequestParameters);
                if (string.IsNullOrEmpty(value))
                {
                    return default;
                }

                using var document = JsonDocument.Parse(value);
                var request = new OpenIddictRequest(document.RootElement.Clone())
                {
                    RequestUri = context.Request.RequestUri
                };

                context.Request = request;
                context.PostLogoutRedirectUri = request.PostLogoutRedirectUri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting logout
        /// requests that use an invalid post_logout_redirect_uri.
        /// Note: this handler is not used when the degraded mode is enabled.
        /// </summary>
        public sealed class ValidateClientPostLogoutRedirectUri : IOpenIddictServerHandler<ValidateEndSessionRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateClientPostLogoutRedirectUri() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateClientPostLogoutRedirectUri(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateEndSessionRequestContext>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    .AddFilter<RequirePostLogoutRedirectUriParameter>()
                    .UseScopedHandler<ValidateClientPostLogoutRedirectUri>()
                    .SetOrder(RestorePushedAuthorizationRequestParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.PostLogoutRedirectUri), SR.FormatID4000(Parameters.PostLogoutRedirectUri));

                // Note: support for the client_id parameter was only added in the second draft of the
                // https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout specification
                // and is optional. To support all client stacks, this handler supports two scenarios:
                //
                //   * The client_id parameter is supported by the client and was explicitly sent:
                //     in this case, the post_logout_redirect_uris allowed for this client application
                //     are retrieved from the database: if one of them matches the specified URI,
                //     the request is considered valid. Otherwise, it's automatically rejected.
                //
                //   * The client_id parameter is not supported by the client or was not explicitly sent:
                //     in this case, all the applications matching the specified post_logout_redirect_uri
                //     are retrieved from the database: if one of them has been granted the correct endpoint
                //     permission, the request is considered valid. Otherwise, it's automatically rejected.
                //
                // Since the first method is more efficient, it's always used if a client_is was specified.

                if (!string.IsNullOrEmpty(context.ClientId))
                {
                    var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                    if (!await _applicationManager.ValidatePostLogoutRedirectUriAsync(application, context.PostLogoutRedirectUri))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6128), context.PostLogoutRedirectUri);

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.FormatID2052(Parameters.PostLogoutRedirectUri),
                            uri: SR.FormatID8000(SR.ID2052));

                        return;
                    }

                    return;
                }

                if (!await ValidatePostLogoutRedirectUriAsync(context.PostLogoutRedirectUri))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6128), context.PostLogoutRedirectUri);

                    context.Reject(
                        error: Errors.InvalidRequest,
                        description: SR.FormatID2052(Parameters.PostLogoutRedirectUri),
                        uri: SR.FormatID8000(SR.ID2052));

                    return;
                }

                async ValueTask<bool> ValidatePostLogoutRedirectUriAsync([StringSyntax(StringSyntaxAttribute.Uri)] string uri)
                {
                    // To be considered valid, a post_logout_redirect_uri must correspond to an existing client application
                    // that was granted the ept:logout permission, unless endpoint permissions checking was explicitly disabled.

                    await foreach (var application in _applicationManager.FindByPostLogoutRedirectUriAsync(uri))
                    {
                        // Note: the legacy "ept:logout" permission is still allowed for backward compatibility.
                        if (!context.Options.IgnoreEndpointPermissions &&
                            !await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.EndSession) &&
                            !await _applicationManager.HasPermissionAsync(application, "ept:logout"))
                        {
                            continue;
                        }

                        if (await _applicationManager.ValidatePostLogoutRedirectUriAsync(application, uri))
                        {
                            return true;
                        }
                    }

                    // If the specified URI is an HTTP/HTTPS URI, points to the local host and doesn't use the
                    // default port, make a second pass to determine whether a native application allowed to use
                    // a relaxed post_logout_redirect_uri comparison policy has the specified URI attached.
                    if (Uri.TryCreate(uri, UriKind.Absolute, out Uri? value) &&
                        // Only apply the relaxed comparison if the URI specified by the client uses a non-default port.
                        !value.IsDefaultPort &&
                        // The relaxed policy only applies to loopback URIs.
                        value.IsLoopback &&
                        // The relaxed policy only applies to HTTP and HTTPS URIs.
                        //
                        // Note: the scheme case is deliberately ignored here as it is always
                        // normalized to a lowercase value by the Uri.TryCreate() API, which
                        // would prevent performing a case-sensitive comparison anyway.
                       (string.Equals(value.Scheme, Uri.UriSchemeHttp,  StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(value.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
                    {
                        await foreach (var application in _applicationManager.FindByPostLogoutRedirectUriAsync(
                            uri: new UriBuilder(value) { Port = -1 }.Uri.AbsoluteUri))
                        {
                            // Note: the legacy "ept:logout" permission is still allowed for backward compatibility.
                            if (!context.Options.IgnoreEndpointPermissions &&
                                !await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.EndSession) &&
                                !await _applicationManager.HasPermissionAsync(application, "ept:logout"))
                            {
                                continue;
                            }

                            if (await _applicationManager.HasApplicationTypeAsync(application, ApplicationTypes.Native) &&
                                await _applicationManager.ValidatePostLogoutRedirectUriAsync(application, uri))
                            {
                                return true;
                            }
                        }
                    }

                    return false;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting end session requests made by unauthorized applications.
        /// Note: this handler is not used when the degraded mode is enabled or when endpoint permissions are disabled.
        /// </summary>
        public sealed class ValidateEndpointPermissions : IOpenIddictServerHandler<ValidateEndSessionRequestContext>
        {
            private readonly IOpenIddictApplicationManager _applicationManager;

            public ValidateEndpointPermissions() => throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));

            public ValidateEndpointPermissions(IOpenIddictApplicationManager applicationManager)
                => _applicationManager = applicationManager ?? throw new ArgumentNullException(nameof(applicationManager));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateEndSessionRequestContext>()
                    .AddFilter<RequireEndpointPermissionsEnabled>()
                    .AddFilter<RequireDegradedModeDisabled>()
                    // Note: support for the client_id parameter was only added in the second draft of the
                    // https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout specification
                    // and is optional. As such, the client permissions are only validated if it was specified.
                    //
                    // Note: if only post_logout_redirect_uri was specified, client permissions are expected to be
                    // enforced by the ValidateClientPostLogoutRedirectUri handler when finding matching clients.
                    .AddFilter<RequireClientIdParameter>()
                    .UseScopedHandler<ValidateEndpointPermissions>()
                    .SetOrder(ValidateClientPostLogoutRedirectUri.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                Debug.Assert(!string.IsNullOrEmpty(context.ClientId), SR.FormatID4000(Parameters.ClientId));

                var application = await _applicationManager.FindByClientIdAsync(context.ClientId) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0032));

                // Reject the request if the application is not allowed to use the end session endpoint.
                //
                // Note: the legacy "ept:logout" permission is still allowed for backward compatibility.
                if (!await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.EndSession) &&
                    !await _applicationManager.HasPermissionAsync(application, "ept:logout"))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6048), context.ClientId);

                    context.Reject(
                        error: Errors.UnauthorizedClient,
                        description: SR.GetResourceString(SR.ID2140),
                        uri: SR.FormatID8000(SR.ID2140));

                    return;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting end session requests that specify an identity
        /// token hint that cannot be used by the client application sending the end session request.
        /// </summary>
        public sealed class ValidateAuthorizedParty : IOpenIddictServerHandler<ValidateEndSessionRequestContext>
        {
            private readonly IOpenIddictApplicationManager? _applicationManager;

            public ValidateAuthorizedParty(IOpenIddictApplicationManager? applicationManager = null)
                => _applicationManager = applicationManager;

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ValidateEndSessionRequestContext>()
                    .UseScopedHandler<ValidateAuthorizedParty>(static provider =>
                    {
                        // Note: the application manager is only resolved if the degraded mode was not enabled to ensure
                        // invalid core configuration exceptions are not thrown even if the managers were registered.
                        var options = provider.GetRequiredService<IOptionsMonitor<OpenIddictServerOptions>>().CurrentValue;

                        return options.EnableDegradedMode ?
                            new ValidateAuthorizedParty() :
                            new ValidateAuthorizedParty(provider.GetService<IOpenIddictApplicationManager>() ??
                                throw new InvalidOperationException(SR.GetResourceString(SR.ID0016)));
                    })
                    .SetOrder(ValidateEndpointPermissions.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                if (context.IdentityTokenHintPrincipal is null)
                {
                    return;
                }

                // This handler is responsible for ensuring that the specified identity token hint
                // was issued to the same client that the one corresponding to the specified client_id
                // or inferred from post_logout_redirect_uri. To achieve that, two approaches are used:
                //
                //   * If an explicit client_id was received, the client_id is directly used to determine
                //     whether the specified id_token_hint lists it as an audience or as a presenter.
                //
                //   * If no explicit client_id was set, all the client applications for which a matching
                //     post_logout_redirect_uri exists are iterated to determine whether the specified
                //     id_token_hint principal lists one of them as a valid audience or presenter.
                //
                // Since the first method is more efficient, it's always used if a client_is was specified.

                if (!string.IsNullOrEmpty(context.ClientId))
                {
                    // If an explicit client_id was specified, it must be listed either as
                    // an audience or as a presenter for the request to be considered valid.
                    if (!context.IdentityTokenHintPrincipal.HasAudience(context.ClientId) &&
                        !context.IdentityTokenHintPrincipal.HasPresenter(context.ClientId))
                    {
                        context.Logger.LogWarning(SR.GetResourceString(SR.ID6198));

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.GetResourceString(SR.ID2141),
                            uri: SR.FormatID8000(SR.ID2141));

                        return;
                    }

                    return;
                }

                if (!context.Options.EnableDegradedMode && !string.IsNullOrEmpty(context.PostLogoutRedirectUri))
                {
                    if (_applicationManager is null)
                    {
                        throw new InvalidOperationException(SR.GetResourceString(SR.ID0016));
                    }

                    if (!await ValidateAuthorizedParty(context.IdentityTokenHintPrincipal, context.PostLogoutRedirectUri))
                    {
                        context.Logger.LogWarning(SR.GetResourceString(SR.ID6198));

                        context.Reject(
                            error: Errors.InvalidRequest,
                            description: SR.GetResourceString(SR.ID2141),
                            uri: SR.FormatID8000(SR.ID2141));

                        return;
                    }

                    return;
                }

                async ValueTask<bool> ValidateAuthorizedParty(ClaimsPrincipal principal,
                    [StringSyntax(StringSyntaxAttribute.Uri)] string uri)
                {
                    // To be considered valid, the specified post_logout_redirect_uri must
                    // be considered valid for one of the listed audiences/presenters.

                    var identifiers = new HashSet<string>(StringComparer.Ordinal);
                    identifiers.UnionWith(principal.GetAudiences());
                    identifiers.UnionWith(principal.GetPresenters());

                    foreach (var identifier in identifiers)
                    {
                        var application = await _applicationManager.FindByClientIdAsync(identifier);
                        if (application is null)
                        {
                            continue;
                        }

                        // Note: the legacy "ept:logout" permission is still allowed for backward compatibility.
                        if (!context.Options.IgnoreEndpointPermissions &&
                            !await _applicationManager.HasPermissionAsync(application, Permissions.Endpoints.EndSession) &&
                            !await _applicationManager.HasPermissionAsync(application, "ept:logout"))
                        {
                            continue;
                        }

                        if (await _applicationManager.ValidatePostLogoutRedirectUriAsync(application, uri))
                        {
                            return true;
                        }
                    }

                    return false;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the principal
        /// extracted from the identity token hint to the event context.
        /// </summary>
        public sealed class AttachPrincipal : IOpenIddictServerHandler<HandleEndSessionRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleEndSessionRequestContext>()
                    .UseSingletonHandler<AttachPrincipal>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleEndSessionRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = context.Transaction.GetProperty<ValidateEndSessionRequestContext>(
                    typeof(ValidateEndSessionRequestContext).FullName!) ??
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0007));

                context.IdentityTokenHintPrincipal ??= notification.IdentityTokenHintPrincipal;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for inferring the redirect URI
        /// used to send the response back to the client application.
        /// </summary>
        public sealed class AttachPostLogoutRedirectUri : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
                    .UseSingletonHandler<AttachPostLogoutRedirectUri>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyEndSessionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If the end session response contains a request token, do not use the
                // post_logout_redirect_uri, as the user agent will be redirected to the same page.
                if (context.Request is null || !string.IsNullOrEmpty(context.Response.RequestUri))
                {
                    return default;
                }

                var notification = context.Transaction.GetProperty<ValidateEndSessionRequestContext>(
                    typeof(ValidateEndSessionRequestContext).FullName!);

                // Note: at this stage, the validated redirect URI property may be null (e.g if
                // an error is returned from the ExtractEndSessionRequest/ValidateEndSessionRequest events).
                if (notification is { IsRejected: false })
                {
                    context.PostLogoutRedirectUri = notification.PostLogoutRedirectUri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the state to the response.
        /// </summary>
        public sealed class AttachResponseState : IOpenIddictServerHandler<ApplyEndSessionResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ApplyEndSessionResponseContext>()
                    .UseSingletonHandler<AttachResponseState>()
                    .SetOrder(AttachPostLogoutRedirectUri.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyEndSessionResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // If the user agent is expected to be redirected to the client application, attach the request
                // state to the end session response to help the client mitigate CSRF/session fixation attacks.
                //
                // Note: don't override the state if one was already attached to the response instance.
                if (!string.IsNullOrEmpty(context.PostLogoutRedirectUri) && string.IsNullOrEmpty(context.Response.State))
                {
                    context.Response.State = context.Request?.State;
                }

                return default;
            }
        }
    }
}

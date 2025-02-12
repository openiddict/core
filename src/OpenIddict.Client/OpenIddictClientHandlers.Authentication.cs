/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OpenIddict.Extensions;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Authentication
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Authorization request top-level processing:
             */
            PrepareAuthorizationRequest.Descriptor,
            ApplyAuthorizationRequest.Descriptor,

            /*
             * Authorization request preparation:
             */
            NormalizeResponseModeParameter.Descriptor,

            /*
             * Authorization request processing:
             */
            AttachAuthorizationEndpoint.Descriptor,

            /*
             * Pushed authorization response handling:
             */
            ValidateWellKnownPushedAuthorizationResponseParameters.Descriptor,
            HandlePushedAuthorizationErrorResponse.Descriptor,
            ValidatePushedAuthorizationRequestUri.Descriptor,
            ValidatePushedAuthorizationExpiration.Descriptor,

            /*
             * Redirection request top-level processing:
             */
            ExtractRedirectionRequest.Descriptor,
            ValidateRedirectionRequest.Descriptor,
            HandleRedirectionRequest.Descriptor,
            ApplyRedirectionResponse<ProcessErrorContext>.Descriptor,
            ApplyRedirectionResponse<ProcessRequestContext>.Descriptor,

            /*
             * Redirection request validation:
             */
            ValidateTokens.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for preparing authorization requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class PrepareAuthorizationRequest : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public PrepareAuthorizationRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireInteractiveGrantType>()
                    .UseScopedHandler<PrepareAuthorizationRequest>()
                    .SetOrder(int.MaxValue - 100_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessChallengeContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new PrepareAuthorizationRequestContext(context.Transaction);
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
            }
        }

        /// <summary>
        /// Contains the logic responsible for applying authorization requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyAuthorizationRequest : IOpenIddictClientHandler<ProcessChallengeContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ApplyAuthorizationRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessChallengeContext>()
                    .AddFilter<RequireInteractiveGrantType>()
                    .UseScopedHandler<ApplyAuthorizationRequest>()
                    .SetOrder(PrepareAuthorizationRequest.Descriptor.Order + 1_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessChallengeContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyAuthorizationRequestContext(context.Transaction)
                {
                    // Note: the endpoint URI is automatically set by a specialized handler if it's not set here.
                    AuthorizationEndpoint = context.AuthorizationEndpoint?.AbsoluteUri!,
                    Nonce = context.Nonce,
                    RedirectUri = context.RedirectUri
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
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the URI of the authorization request to the request.
        /// </summary>
        public sealed class AttachAuthorizationEndpoint : IOpenIddictClientHandler<ApplyAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ApplyAuthorizationRequestContext>()
                    .UseSingletonHandler<AttachAuthorizationEndpoint>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(ApplyAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Don't overwrite the endpoint URI if it was already set.
                if (!string.IsNullOrEmpty(context.AuthorizationEndpoint))
                {
                    return default;
                }

                // Ensure the authorization endpoint is present and is a valid absolute URI.
                if (context.Configuration.AuthorizationEndpoint is not { IsAbsoluteUri: true } ||
                    OpenIddictHelpers.IsImplicitFileUri(context.Configuration.AuthorizationEndpoint))
                {
                    throw new InvalidOperationException(SR.FormatID0301(Metadata.AuthorizationEndpoint));
                }

                context.AuthorizationEndpoint = context.Configuration.AuthorizationEndpoint.AbsoluteUri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the pushed authorization response.
        /// </summary>
        public sealed class ValidateWellKnownPushedAuthorizationResponseParameters : IOpenIddictClientHandler<HandlePushedAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandlePushedAuthorizationResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownPushedAuthorizationResponseParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandlePushedAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                foreach (var parameter in context.Response.GetParameters())
                {
                    if (!ValidateParameterType(parameter.Key, parameter.Value))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2107(parameter.Key),
                            uri: SR.FormatID8000(SR.ID2107));

                        return default;
                    }
                }

                return default;

                // Note: in the typical case, the response parameters should be deserialized from a
                // JSON response and thus natively stored as System.Text.Json.JsonElement instances.
                //
                // In the rare cases where the underlying value wouldn't be a JsonElement instance
                // (e.g when custom parameters are manually added to the response), the static
                // conversion operator would take care of converting the underlying value to a
                // JsonElement instance using the same value type as the original parameter value.
                static bool ValidateParameterType(string name, OpenIddictParameter value) => name switch
                {
                    // Error parameters MUST be formatted as unique strings:
                    Parameters.Error or Parameters.ErrorDescription or Parameters.ErrorUri
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as unique strings:
                    Parameters.RequestUri => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as numeric dates:
                    Parameters.ExpiresIn => (JsonElement) value is { ValueKind: JsonValueKind.Number } element &&
                        element.TryGetDecimal(out decimal result) && result is >= 0,

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible for surfacing potential errors from the pushed authorization response.
        /// </summary>
        public sealed class HandlePushedAuthorizationErrorResponse : IOpenIddictClientHandler<HandlePushedAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandlePushedAuthorizationResponseContext>()
                    .UseSingletonHandler<HandlePushedAuthorizationErrorResponse>()
                    .SetOrder(ValidateWellKnownPushedAuthorizationResponseParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandlePushedAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // For more information, see https://www.rfc-editor.org/rfc/rfc8628#section-3.2.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6234), context.Response);

                    context.Reject(
                        error: context.Response.Error switch
                        {
                            Errors.InvalidClient      => Errors.InvalidRequest,
                            Errors.InvalidScope       => Errors.InvalidScope,
                            Errors.InvalidRequest     => Errors.InvalidRequest,
                            Errors.UnauthorizedClient => Errors.UnauthorizedClient,
                            _                         => Errors.ServerError
                        },
                        description: SR.GetResourceString(SR.ID2179),
                        uri: SR.FormatID8000(SR.ID2179));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the request URI contained in the pushed authorization response.
        /// </summary>
        public sealed class ValidatePushedAuthorizationRequestUri : IOpenIddictClientHandler<HandlePushedAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandlePushedAuthorizationResponseContext>()
                    .UseSingletonHandler<ValidatePushedAuthorizationRequestUri>()
                    .SetOrder(HandlePushedAuthorizationErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandlePushedAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Return an error if the mandatory "request_uri" parameter is missing.
                //
                // For more information, see https://datatracker.ietf.org/doc/html/rfc9126#section-2.2.
                if (string.IsNullOrEmpty(context.Response.RequestUri))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2180(Parameters.RequestUri),
                        uri: SR.FormatID8000(SR.ID2180));

                    return default;
                }

                // Return an error if the "request_uri" parameter is malformed.
                if (!Uri.TryCreate(context.Response.RequestUri, UriKind.Absolute, out Uri? uri) ||
                    OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2181(Parameters.RequestUri),
                        uri: SR.FormatID8000(SR.ID2181));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the "expires_in"
        /// parameter contained in the pushed authorization response.
        /// </summary>
        public sealed class ValidatePushedAuthorizationExpiration : IOpenIddictClientHandler<HandlePushedAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandlePushedAuthorizationResponseContext>()
                    .UseSingletonHandler<ValidatePushedAuthorizationExpiration>()
                    .SetOrder(ValidatePushedAuthorizationRequestUri.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandlePushedAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Return an error if the mandatory "expires_in" parameter is missing.
                //
                // For more information, see https://datatracker.ietf.org/doc/html/rfc9126#section-2.2.
                if (context.Response.ExpiresIn is null)
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2180(Parameters.ExpiresIn),
                        uri: SR.FormatID8000(SR.ID2180));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ExtractRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseScopedHandler<ExtractRedirectionRequest>()
                    .SetOrder(100_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ExtractRedirectionRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0302));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6178), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseScopedHandler<ValidateRedirectionRequest>()
                    .SetOrder(ExtractRedirectionRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateRedirectionRequestContext(context.Transaction);
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6179));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling redirection requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleRedirectionRequest : IOpenIddictClientHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public HandleRedirectionRequest(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseScopedHandler<HandleRedirectionRequest>()
                    .SetOrder(ValidateRedirectionRequest.Descriptor.Order + 1_000)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleRedirectionRequestContext(context.Transaction);
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

                context.Transaction.Response = new OpenIddictResponse();
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing redirection responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyRedirectionResponse<TContext> : IOpenIddictClientHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ApplyRedirectionResponse(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireRedirectionRequest>()
                    .UseScopedHandler<ApplyRedirectionResponse<TContext>>()
                    .SetOrder(500_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(TContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ApplyRedirectionResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0303));
            }
        }

        /// <summary>
        /// Contains the logic responsible for removing the response mode parameter from the
        /// request if it corresponds to the default mode for the selected response type.
        /// </summary>
        public sealed class NormalizeResponseModeParameter : IOpenIddictClientHandler<PrepareAuthorizationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<PrepareAuthorizationRequestContext>()
                    .UseSingletonHandler<NormalizeResponseModeParameter>()
                    .SetOrder(int.MinValue + 100_000)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(PrepareAuthorizationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // When the response mode corresponds to the default mode assigned to the selected
                // response type, the specification explicitly recommends omitting the response mode.
                // As such, this handler is expected to remove the mode parameter in the following cases:
                //   - Authorization code flow: response_mode=query.
                //   - Hybrid flow: response_mode=fragment.
                //   - Implicit flow: response_mode=fragment.
                //
                // For more information, read
                // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes.
                //
                if (!string.IsNullOrEmpty(context.Request.ResponseMode) &&
                   (context.Request.IsAuthorizationCodeFlow() && context.Request.IsQueryResponseMode())    ||
                   (context.Request.IsHybridFlow()            && context.Request.IsFragmentResponseMode()) ||
                   (context.Request.IsImplicitFlow()          && context.Request.IsFragmentResponseMode()))
                {
                    context.Request.ResponseMode = null;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for rejecting redirection requests that don't
        /// specify a valid access token, authorization code, identity token or state token.
        /// </summary>
        public sealed class ValidateTokens : IOpenIddictClientHandler<ValidateRedirectionRequestContext>
        {
            private readonly IOpenIddictClientDispatcher _dispatcher;

            public ValidateTokens(IOpenIddictClientDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<ValidateRedirectionRequestContext>()
                    .UseScopedHandler<ValidateTokens>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ValidateRedirectionRequestContext context)
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
                context.Principal = notification.FrontchannelIdentityTokenPrincipal;
                context.StateTokenPrincipal = notification.StateTokenPrincipal;
            }
        }
    }
}

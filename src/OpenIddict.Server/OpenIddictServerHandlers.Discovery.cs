/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;

namespace OpenIddict.Server;

public static partial class OpenIddictServerHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictServerHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Configuration request top-level processing:
             */
            ExtractConfigurationRequest.Descriptor,
            ValidateConfigurationRequest.Descriptor,
            HandleConfigurationRequest.Descriptor,
            ApplyConfigurationResponse<ProcessErrorContext>.Descriptor,
            ApplyConfigurationResponse<ProcessRequestContext>.Descriptor,

            /*
             * Configuration request handling:
             */
            AttachIssuer.Descriptor,
            AttachEndpoints.Descriptor,
            AttachGrantTypes.Descriptor,
            AttachResponseTypes.Descriptor,
            AttachResponseModes.Descriptor,
            AttachClientAuthenticationMethods.Descriptor,
            AttachCodeChallengeMethods.Descriptor,
            AttachScopes.Descriptor,
            AttachClaims.Descriptor,
            AttachSubjectTypes.Descriptor,
            AttachPromptValues.Descriptor,
            AttachSigningAlgorithms.Descriptor,
            AttachSecurityRequirements.Descriptor,
            AttachAdditionalMetadata.Descriptor,

            /*
             * JSON Web Key Set request top-level processing:
             */
            ExtractJsonWebKeySetRequest.Descriptor,
            ValidateJsonWebKeySetRequest.Descriptor,
            HandleJsonWebKeySetRequest.Descriptor,
            ApplyJsonWebKeySetResponse<ProcessErrorContext>.Descriptor,
            ApplyJsonWebKeySetResponse<ProcessRequestContext>.Descriptor,

            /*
             * JSON Web Key Set request handling:
             */
            AttachSigningKeys.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for extracting configuration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractConfigurationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireConfigurationRequest>()
                    .UseScopedHandler<ExtractConfigurationRequest>()
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

                var notification = new ExtractConfigurationRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0037));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6066), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating configuration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateConfigurationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireConfigurationRequest>()
                    .UseScopedHandler<ValidateConfigurationRequest>()
                    .SetOrder(ExtractConfigurationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateConfigurationRequestContext(context.Transaction);
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6067));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling configuration requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleConfigurationRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleConfigurationRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireConfigurationRequest>()
                    .UseScopedHandler<HandleConfigurationRequest>()
                    .SetOrder(ValidateConfigurationRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleConfigurationRequestContext(context.Transaction);
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

                var response = new OpenIddictResponse
                {
                    [Metadata.Issuer] = notification.Issuer?.AbsoluteUri,
                    [Metadata.AuthorizationEndpoint] = notification.AuthorizationEndpoint?.AbsoluteUri,
                    [Metadata.TokenEndpoint] = notification.TokenEndpoint?.AbsoluteUri,
                    [Metadata.IntrospectionEndpoint] = notification.IntrospectionEndpoint?.AbsoluteUri,
                    [Metadata.EndSessionEndpoint] = notification.EndSessionEndpoint?.AbsoluteUri,
                    [Metadata.RevocationEndpoint] = notification.RevocationEndpoint?.AbsoluteUri,
                    [Metadata.UserInfoEndpoint] = notification.UserInfoEndpoint?.AbsoluteUri,
                    [Metadata.DeviceAuthorizationEndpoint] = notification.DeviceAuthorizationEndpoint?.AbsoluteUri,
                    [Metadata.PushedAuthorizationRequestEndpoint] = notification.PushedAuthorizationEndpoint?.AbsoluteUri,
                    [Metadata.JwksUri] = notification.JsonWebKeySetEndpoint?.AbsoluteUri,
                    [Metadata.GrantTypesSupported] = notification.GrantTypes.ToArray(),
                    [Metadata.ResponseTypesSupported] = notification.ResponseTypes.ToArray(),
                    [Metadata.ResponseModesSupported] = notification.ResponseModes.ToArray(),
                    [Metadata.ScopesSupported] = notification.Scopes.ToArray(),
                    [Metadata.ClaimsSupported] = notification.Claims.ToArray(),
                    [Metadata.IdTokenSigningAlgValuesSupported] = notification.IdTokenSigningAlgorithms.ToArray(),
                    [Metadata.CodeChallengeMethodsSupported] = notification.CodeChallengeMethods.ToArray(),
                    [Metadata.SubjectTypesSupported] = notification.SubjectTypes.ToArray(),
                    [Metadata.PromptValuesSupported] = notification.PromptValues.ToArray(),
                    [Metadata.TokenEndpointAuthMethodsSupported] = notification.TokenEndpointAuthenticationMethods.ToArray(),
                    [Metadata.IntrospectionEndpointAuthMethodsSupported] = notification.IntrospectionEndpointAuthenticationMethods.ToArray(),
                    [Metadata.RevocationEndpointAuthMethodsSupported] = notification.RevocationEndpointAuthenticationMethods.ToArray(),
                    [Metadata.DeviceAuthorizationEndpointAuthMethodsSupported] = notification.DeviceAuthorizationEndpointAuthenticationMethods.ToArray(),
                    [Metadata.PushedAuthorizationRequestEndpointAuthMethodsSupported] = notification.PushedAuthorizationEndpointAuthenticationMethods.ToArray(),
                    [Metadata.RequirePushedAuthorizationRequests] = notification.RequirePushedAuthorizationRequests
                };

                foreach (var metadata in notification.Metadata)
                {
                    response.SetParameter(metadata.Key, metadata.Value);
                }

                context.Transaction.Response = response;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing configuration responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyConfigurationResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyConfigurationResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireConfigurationRequest>()
                    .UseScopedHandler<ApplyConfigurationResponse<TContext>>()
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

                var notification = new ApplyConfigurationResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0272));
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the issuer to the provider discovery document.
        /// </summary>
        public sealed class AttachIssuer : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachIssuer>()
                    .SetOrder(int.MaxValue - 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Issuer = context.Options.Issuer ?? context.BaseUri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the endpoint URIs to the provider discovery document.
        /// </summary>
        public sealed class AttachEndpoints : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachEndpoints>()
                    .SetOrder(AttachIssuer.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: while OpenIddict allows specifying multiple endpoint URIs, the OAuth 2.0
                // and OpenID Connect discovery specifications only allow a single URI per endpoint.

                context.AuthorizationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.AuthorizationEndpointUris.FirstOrDefault());

                context.DeviceAuthorizationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.DeviceAuthorizationEndpointUris.FirstOrDefault());

                context.EndSessionEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.EndSessionEndpointUris.FirstOrDefault());

                context.IntrospectionEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.IntrospectionEndpointUris.FirstOrDefault());

                context.JsonWebKeySetEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.JsonWebKeySetEndpointUris.FirstOrDefault());

                context.PushedAuthorizationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.PushedAuthorizationEndpointUris.FirstOrDefault());

                context.RevocationEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.RevocationEndpointUris.FirstOrDefault());

                context.TokenEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.TokenEndpointUris.FirstOrDefault());

                context.UserInfoEndpoint ??= OpenIddictHelpers.CreateAbsoluteUri(
                    context.BaseUri, context.Options.UserInfoEndpointUris.FirstOrDefault());

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported grant types to the provider discovery document.
        /// </summary>
        public sealed class AttachGrantTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachGrantTypes>()
                    .SetOrder(AttachEndpoints.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.GrantTypes.UnionWith(context.Options.GrantTypes);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported response types to the provider discovery document.
        /// </summary>
        public sealed class AttachResponseTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachResponseTypes>()
                    .SetOrder(AttachGrantTypes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.ResponseTypes.UnionWith(context.Options.ResponseTypes);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported response modes to the provider discovery document.
        /// </summary>
        public sealed class AttachResponseModes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachResponseModes>()
                    .SetOrder(AttachResponseTypes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Only include the response modes if at least one response type is returned.
                if (context.ResponseTypes.Count is 0)
                {
                    return default;
                }

                // Note: returning an access or identity token using the query response mode is explicitly disallowed.
                //
                // To ensure the query response mode is not returned unless at least one response type that doesn't
                // include id_token or token is included in the server configuration, a manual check is done here.
                if (context.Options.ResponseModes.Contains(ResponseModes.Query) &&
                    context.ResponseTypes
                        .Select(static types => types.Split(Separators.Space, StringSplitOptions.None).ToHashSet(StringComparer.Ordinal))
                        .Any(static types => !types.Contains(ResponseTypes.IdToken) && !types.Contains(ResponseTypes.Token)))
                {
                    context.ResponseModes.Add(ResponseModes.Query);
                }

                context.ResponseModes.UnionWith(context.Options.ResponseModes.Where(
                    static mode => mode is not ResponseModes.Query));

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported client
        /// authentication methods to the provider discovery document.
        /// </summary>
        public sealed class AttachClientAuthenticationMethods : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachClientAuthenticationMethods>()
                    .SetOrder(AttachResponseModes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: "device_authorization_endpoint_auth_methods_supported" is not a standard parameter
                // but is supported by OpenIddict 4.3.0 and higher for consistency with the other endpoints.
                if (context.DeviceAuthorizationEndpoint is not null)
                {
                    context.DeviceAuthorizationEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                if (context.IntrospectionEndpoint is not null)
                {
                    context.IntrospectionEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                // Note: "pushed_authorization_request_endpoint_auth_methods_supported" is not a standard parameter
                // but is supported by OpenIddict 6.1.0 and higher for consistency with the other endpoints.
                if (context.PushedAuthorizationEndpoint is not null)
                {
                    context.PushedAuthorizationEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                if (context.RevocationEndpoint is not null)
                {
                    context.RevocationEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                if (context.TokenEndpoint is not null)
                {
                    context.TokenEndpointAuthenticationMethods.UnionWith(context.Options.ClientAuthenticationMethods);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported
        /// code challenge methods to the provider discovery document.
        /// </summary>
        public sealed class AttachCodeChallengeMethods : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachCodeChallengeMethods>()
                    .SetOrder(AttachClientAuthenticationMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Only include the code challenge methods if the authorization code grant type is enabled.
                if (context.GrantTypes.Contains(GrantTypes.AuthorizationCode))
                {
                    context.CodeChallengeMethods.UnionWith(context.Options.CodeChallengeMethods);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported response types to the provider discovery document.
        /// </summary>
        public sealed class AttachScopes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachScopes>()
                    .SetOrder(AttachCodeChallengeMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Scopes.UnionWith(context.Options.Scopes);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported claims to the provider discovery document.
        /// </summary>
        public sealed class AttachClaims : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachClaims>()
                    .SetOrder(AttachScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Claims.UnionWith(context.Options.Claims);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported subject types to the provider discovery document.
        /// </summary>
        public sealed class AttachSubjectTypes : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachSubjectTypes>()
                    .SetOrder(AttachClaims.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.SubjectTypes.UnionWith(context.Options.SubjectTypes);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported prompt values to the provider discovery document.
        /// </summary>
        public sealed class AttachPromptValues : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachPromptValues>()
                    .SetOrder(AttachSubjectTypes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.PromptValues.UnionWith(context.Options.PromptValues);

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the supported signing algorithms to the provider discovery document.
        /// </summary>
        public sealed class AttachSigningAlgorithms : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachSigningAlgorithms>()
                    .SetOrder(AttachPromptValues.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                foreach (var credentials in context.Options.SigningCredentials)
                {
                    // Try to resolve the JWA algorithm short name.
                    var algorithm = credentials.Algorithm switch
                    {
#if SUPPORTS_ECDSA
                        SecurityAlgorithms.EcdsaSha256 or SecurityAlgorithms.EcdsaSha256Signature
                            => SecurityAlgorithms.EcdsaSha256,
                        SecurityAlgorithms.EcdsaSha384 or SecurityAlgorithms.EcdsaSha384Signature
                            => SecurityAlgorithms.EcdsaSha384,
                        SecurityAlgorithms.EcdsaSha512 or SecurityAlgorithms.EcdsaSha512Signature
                            => SecurityAlgorithms.EcdsaSha512,
#endif
                        SecurityAlgorithms.RsaSha256 or SecurityAlgorithms.RsaSha256Signature
                            => SecurityAlgorithms.RsaSha256,
                        SecurityAlgorithms.RsaSha384 or SecurityAlgorithms.RsaSha384Signature
                            => SecurityAlgorithms.RsaSha384,
                        SecurityAlgorithms.RsaSha512 or SecurityAlgorithms.RsaSha512Signature
                            => SecurityAlgorithms.RsaSha512,

                        SecurityAlgorithms.RsaSsaPssSha256 or SecurityAlgorithms.RsaSsaPssSha256Signature
                            => SecurityAlgorithms.RsaSsaPssSha256,
                        SecurityAlgorithms.RsaSsaPssSha384 or SecurityAlgorithms.RsaSsaPssSha384Signature
                            => SecurityAlgorithms.RsaSsaPssSha384,
                        SecurityAlgorithms.RsaSsaPssSha512 or SecurityAlgorithms.RsaSsaPssSha512Signature
                            => SecurityAlgorithms.RsaSsaPssSha512,

                        _ => null
                    };

                    // If the algorithm cannot be resolved, ignore it.
                    if (string.IsNullOrEmpty(algorithm))
                    {
                        continue;
                    }

                    context.IdTokenSigningAlgorithms.Add(algorithm);
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the security requirements to the provider discovery document.
        /// </summary>
        public sealed class AttachSecurityRequirements : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachSecurityRequirements>()
                    .SetOrder(AttachSigningAlgorithms.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.RequirePushedAuthorizationRequests = context.Options.RequirePushedAuthorizationRequests;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching additional metadata to the provider discovery document.
        /// </summary>
        public sealed class AttachAdditionalMetadata : IOpenIddictServerHandler<HandleConfigurationRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleConfigurationRequestContext>()
                    .UseSingletonHandler<AttachAdditionalMetadata>()
                    .SetOrder(AttachSecurityRequirements.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: these optional features are not yet supported by OpenIddict,
                // so "false" is returned to encourage clients not to use them.
                context.Metadata[Metadata.ClaimsParameterSupported] = false;
                context.Metadata[Metadata.RequestParameterSupported] = false;
                context.Metadata[Metadata.RequestUriParameterSupported] = false;
                context.Metadata[Metadata.TlsClientCertificateBoundAccessTokens] = false;

                // As of 3.2.0, OpenIddict automatically returns an "iss" parameter containing its identity as
                // part of authorization responses to help clients mitigate mix-up attacks. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-iss-auth-resp-05.
                context.Metadata[Metadata.AuthorizationResponseIssParameterSupported] = true;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting JSON Web Key Set requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ExtractJsonWebKeySetRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ExtractJsonWebKeySetRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireJsonWebKeySetRequest>()
                    .UseScopedHandler<ExtractJsonWebKeySetRequest>()
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

                var notification = new ExtractJsonWebKeySetRequestContext(context.Transaction);
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
                    throw new InvalidOperationException(SR.GetResourceString(SR.ID0038));
                }

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6068), notification.Request);
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating JSON Web Key Set requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ValidateJsonWebKeySetRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ValidateJsonWebKeySetRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireJsonWebKeySetRequest>()
                    .UseScopedHandler<ValidateJsonWebKeySetRequest>()
                    .SetOrder(ExtractJsonWebKeySetRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new ValidateJsonWebKeySetRequestContext(context.Transaction);
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

                context.Logger.LogInformation(SR.GetResourceString(SR.ID6069));
            }
        }

        /// <summary>
        /// Contains the logic responsible for handling JSON Web Key Set requests and invoking the corresponding event handlers.
        /// </summary>
        public sealed class HandleJsonWebKeySetRequest : IOpenIddictServerHandler<ProcessRequestContext>
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public HandleJsonWebKeySetRequest(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<ProcessRequestContext>()
                    .AddFilter<RequireJsonWebKeySetRequest>()
                    .UseScopedHandler<HandleJsonWebKeySetRequest>()
                    .SetOrder(ValidateJsonWebKeySetRequest.Descriptor.Order + 1_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public async ValueTask HandleAsync(ProcessRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var notification = new HandleJsonWebKeySetRequestContext(context.Transaction);
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

                using var stream = new MemoryStream();
                using var writer = new Utf8JsonWriter(stream);

                writer.WriteStartArray();

                foreach (var key in notification.Keys)
                {
                    // Ensure a key type has been provided.
                    // See https://tools.ietf.org/html/rfc7517#section-4.1
                    if (string.IsNullOrEmpty(key.Kty))
                    {
                        context.Logger.LogWarning(SR.GetResourceString(SR.ID6070), JsonWebKeyParameterNames.Kty);

                        continue;
                    }

                    writer.WriteStartObject();

                    if (!string.IsNullOrEmpty(key.Kid)) writer.WriteString(JsonWebKeyParameterNames.Kid, key.Kid);
                    if (!string.IsNullOrEmpty(key.Use)) writer.WriteString(JsonWebKeyParameterNames.Use, key.Use);
                    if (!string.IsNullOrEmpty(key.Kty)) writer.WriteString(JsonWebKeyParameterNames.Kty, key.Kty);
                    if (!string.IsNullOrEmpty(key.Alg)) writer.WriteString(JsonWebKeyParameterNames.Alg, key.Alg);
                    if (!string.IsNullOrEmpty(key.Crv)) writer.WriteString(JsonWebKeyParameterNames.Crv, key.Crv);
                    if (!string.IsNullOrEmpty(key.E))   writer.WriteString(JsonWebKeyParameterNames.E, key.E);
                    if (!string.IsNullOrEmpty(key.N))   writer.WriteString(JsonWebKeyParameterNames.N, key.N);
                    if (!string.IsNullOrEmpty(key.X))   writer.WriteString(JsonWebKeyParameterNames.X, key.X);
                    if (!string.IsNullOrEmpty(key.Y))   writer.WriteString(JsonWebKeyParameterNames.Y, key.Y);
                    if (!string.IsNullOrEmpty(key.X5t)) writer.WriteString(JsonWebKeyParameterNames.X5t, key.X5t);
                    if (!string.IsNullOrEmpty(key.X5u)) writer.WriteString(JsonWebKeyParameterNames.X5u, key.X5u);

                    if (key.KeyOps.Count is not 0)
                    {
                        writer.WritePropertyName(JsonWebKeyParameterNames.KeyOps);
                        writer.WriteStartArray();

                        for (var index = 0; index < key.KeyOps.Count; index++)
                        {
                            writer.WriteStringValue(key.KeyOps[index]);
                        }

                        writer.WriteEndArray();
                    }

                    if (key.X5c.Count is not 0)
                    {
                        writer.WritePropertyName(JsonWebKeyParameterNames.X5c);
                        writer.WriteStartArray();

                        for (var index = 0; index < key.X5c.Count; index++)
                        {
                            writer.WriteStringValue(key.X5c[index]);
                        }

                        writer.WriteEndArray();
                    }

                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.Flush();
                stream.Seek(0L, SeekOrigin.Begin);

                using var document = JsonDocument.Parse(stream);

                // Note: AddParameter() is used here to ensure the mandatory "keys" node
                // is returned to the caller, even if the key set doesn't expose any key.
                // See https://tools.ietf.org/html/rfc7517#section-5 for more information.
                var response = new OpenIddictResponse();
                response.AddParameter(Parameters.Keys, document.RootElement.Clone());

                context.Transaction.Response = response;
            }
        }

        /// <summary>
        /// Contains the logic responsible for processing JSON Web Key Set responses and invoking the corresponding event handlers.
        /// </summary>
        public sealed class ApplyJsonWebKeySetResponse<TContext> : IOpenIddictServerHandler<TContext> where TContext : BaseRequestContext
        {
            private readonly IOpenIddictServerDispatcher _dispatcher;

            public ApplyJsonWebKeySetResponse(IOpenIddictServerDispatcher dispatcher)
                => _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));

            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<TContext>()
                    .AddFilter<RequireJsonWebKeySetRequest>()
                    .UseScopedHandler<ApplyJsonWebKeySetResponse<TContext>>()
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

                var notification = new ApplyJsonWebKeySetResponseContext(context.Transaction);
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

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0039));
            }
        }

        /// <summary>
        /// Contains the logic responsible for attaching the signing keys to the JSON Web Key Set document.
        /// </summary>
        public sealed class AttachSigningKeys : IOpenIddictServerHandler<HandleJsonWebKeySetRequestContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictServerHandlerDescriptor Descriptor { get; }
                = OpenIddictServerHandlerDescriptor.CreateBuilder<HandleJsonWebKeySetRequestContext>()
                    .UseSingletonHandler<AttachSigningKeys>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictServerHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleJsonWebKeySetRequestContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                foreach (var credentials in context.Options.SigningCredentials)
                {
#if SUPPORTS_ECDSA
                    if (!credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256) &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSsaPssSha256) &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6071), credentials.Key.GetType().Name);

                        continue;
                    }
#else
                    if (!credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256) &&
                        !credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSsaPssSha256))
                    {
                        context.Logger.LogInformation(SR.GetResourceString(SR.ID6072), credentials.Key.GetType().Name);

                        continue;
                    }
#endif

                    var key = new JsonWebKey
                    {
                        Use = JsonWebKeyUseNames.Sig,

                        // Resolve the JWA identifier from the algorithm specified in the credentials.
                        Alg = credentials.Algorithm switch
                        {
#if SUPPORTS_ECDSA
                            SecurityAlgorithms.EcdsaSha256 or SecurityAlgorithms.EcdsaSha256Signature
                                => SecurityAlgorithms.EcdsaSha256,
                            SecurityAlgorithms.EcdsaSha384 or SecurityAlgorithms.EcdsaSha384Signature
                                => SecurityAlgorithms.EcdsaSha384,
                            SecurityAlgorithms.EcdsaSha512 or SecurityAlgorithms.EcdsaSha512Signature
                                => SecurityAlgorithms.EcdsaSha512,
#endif
                            SecurityAlgorithms.RsaSha256 or SecurityAlgorithms.RsaSha256Signature
                                => SecurityAlgorithms.RsaSha256,
                            SecurityAlgorithms.RsaSha384 or SecurityAlgorithms.RsaSha384Signature
                                => SecurityAlgorithms.RsaSha384,
                            SecurityAlgorithms.RsaSha512 or SecurityAlgorithms.RsaSha512Signature
                                => SecurityAlgorithms.RsaSha512,

                            SecurityAlgorithms.RsaSsaPssSha256 or SecurityAlgorithms.RsaSsaPssSha256Signature
                                => SecurityAlgorithms.RsaSsaPssSha256,
                            SecurityAlgorithms.RsaSsaPssSha384 or SecurityAlgorithms.RsaSsaPssSha384Signature
                                => SecurityAlgorithms.RsaSsaPssSha384,
                            SecurityAlgorithms.RsaSsaPssSha512 or SecurityAlgorithms.RsaSsaPssSha512Signature
                                => SecurityAlgorithms.RsaSsaPssSha512,

                            _ => null
                        },

                        // Use the key identifier specified in the signing credentials.
                        Kid = credentials.Kid
                    };

                    if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSha256) ||
                        credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.RsaSsaPssSha256))
                    {
                        // Note: IdentityModel 5 doesn't expose a method allowing to retrieve the underlying algorithm
                        // from a generic asymmetric security key. To work around this limitation, try to cast
                        // the security key to the built-in IdentityModel types to extract the required RSA instance.
                        // See https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues/395.

                        var parameters = credentials.Key switch
                        {
                            X509SecurityKey { PublicKey: RSA algorithm } => algorithm.ExportParameters(includePrivateParameters: false),

                            RsaSecurityKey { Rsa:        RSA algorithm       } => algorithm.ExportParameters(includePrivateParameters: false),
                            RsaSecurityKey { Parameters: RSAParameters value } => value,

                            _ => (RSAParameters?) null
                        };

                        if (parameters is null)
                        {
                            context.Logger.LogWarning(SR.GetResourceString(SR.ID6073), credentials.Key.GetType().Name);

                            continue;
                        }

                        Debug.Assert(parameters.Value.Exponent is not null &&
                                     parameters.Value.Modulus is not null, SR.GetResourceString(SR.ID4003));

                        key.Kty = JsonWebAlgorithmsKeyTypes.RSA;

                        // Note: both E and N must be base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7518#section-6.3.1.1.
                        key.E = Base64UrlEncoder.Encode(parameters.Value.Exponent);
                        key.N = Base64UrlEncoder.Encode(parameters.Value.Modulus);
                    }

#if SUPPORTS_ECDSA
                    else if (credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha256) ||
                             credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha384) ||
                             credentials.Key.IsSupportedAlgorithm(SecurityAlgorithms.EcdsaSha512))
                    {
                        var parameters = credentials.Key switch
                        {
                            X509SecurityKey { PublicKey: ECDsa algorithm } => algorithm.ExportParameters(includePrivateParameters: false),

                            ECDsaSecurityKey { ECDsa: ECDsa algorithm } => algorithm.ExportParameters(includePrivateParameters: false),

                            _ => (ECParameters?) null
                        };

                        if (parameters is null)
                        {
                            context.Logger.LogWarning(SR.GetResourceString(SR.ID6074), credentials.Key.GetType().Name);

                            continue;
                        }

                        var curve =
                            OpenIddictHelpers.IsEcCurve(parameters.Value, ECCurve.NamedCurves.nistP256) ? JsonWebKeyECTypes.P256 :
                            OpenIddictHelpers.IsEcCurve(parameters.Value, ECCurve.NamedCurves.nistP384) ? JsonWebKeyECTypes.P384 :
                            OpenIddictHelpers.IsEcCurve(parameters.Value, ECCurve.NamedCurves.nistP521) ? JsonWebKeyECTypes.P521 : null;

                        if (string.IsNullOrEmpty(curve))
                        {
                            context.Logger.LogWarning(SR.GetResourceString(SR.ID6167), credentials.Key.GetType().Name);

                            continue;
                        }

                        Debug.Assert(parameters.Value.Q.X is not null &&
                                     parameters.Value.Q.Y is not null, SR.GetResourceString(SR.ID4004));

                        Debug.Assert(parameters.Value.Curve.Oid is not null, SR.GetResourceString(SR.ID4011));
                        Debug.Assert(parameters.Value.Curve.IsNamed, SR.GetResourceString(SR.ID4005));

                        key.Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve;
                        key.Crv = curve;

                        // Note: both X and Y must be base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7518#section-6.2.1.2.
                        key.X = Base64UrlEncoder.Encode(parameters.Value.Q.X);
                        key.Y = Base64UrlEncoder.Encode(parameters.Value.Q.Y);
                    }
#endif

                    // If the signing key is embedded in a X.509 certificate, set
                    // the x5t and x5c parameters using the certificate details.
                    var certificate = (credentials.Key as X509SecurityKey)?.Certificate;
                    if (certificate is not null)
                    {
                        // x5t must be base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7517#section-4.8.
                        key.X5t = Base64UrlEncoder.Encode(certificate.GetCertHash());

                        // x5t#S256 must be base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7517#section-4.9.
                        key.X5tS256 = Base64UrlEncoder.Encode(OpenIddictHelpers.ComputeSha256Hash(certificate.RawData));

                        // Unlike E or N, the certificates contained in x5c
                        // must be base64-encoded and not base64url-encoded.
                        // See https://tools.ietf.org/html/rfc7517#section-4.7.
                        key.X5c.Add(Convert.ToBase64String(certificate.RawData));
                    }

                    context.Keys.Add(key);
                }

                return default;
            }
        }
    }
}

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Extensions;

namespace OpenIddict.Client;

public static partial class OpenIddictClientHandlers
{
    public static class Discovery
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Configuration response handling:
             */
            ValidateWellKnownConfigurationParameters.Descriptor,
            HandleConfigurationErrorResponse.Descriptor,
            ValidateIssuer.Descriptor,
            ExtractAuthorizationEndpoint.Descriptor,
            ExtractJsonWebKeySetEndpoint.Descriptor,
            ExtractDeviceAuthorizationEndpoint.Descriptor,
            ExtractIntrospectionEndpoint.Descriptor,
            ExtractEndSessionEndpoint.Descriptor,
            ExtractMtlsDeviceAuthorizationEndpoint.Descriptor,
            ExtractMtlsIntrospectionEndpoint.Descriptor,
            ExtractMtlsPushedAuthorizationEndpoint.Descriptor,
            ExtractMtlsRevocationEndpoint.Descriptor,
            ExtractMtlsTokenEndpoint.Descriptor,
            ExtractMtlsUserInfoEndpoint.Descriptor,
            ExtractPushedAuthorizationEndpoint.Descriptor,
            ExtractRevocationEndpoint.Descriptor,
            ExtractTokenEndpoint.Descriptor,
            ExtractUserInfoEndpoint.Descriptor,
            ExtractGrantTypes.Descriptor,
            ExtractResponseModes.Descriptor,
            ExtractResponseTypes.Descriptor,
            ExtractCodeChallengeMethods.Descriptor,
            ExtractScopes.Descriptor,
            ExtractIssuerParameterRequirement.Descriptor,
            ExtractTlsClientCertificateAccessTokenBindingRequirement.Descriptor,
            ExtractPushedAuthorizationRequirement.Descriptor,
            ExtractDeviceAuthorizationEndpointClientAuthenticationMethods.Descriptor,
            ExtractIntrospectionEndpointClientAuthenticationMethods.Descriptor,
            ExtractPushedAuthorizationEndpointClientAuthenticationMethods.Descriptor,
            ExtractRevocationEndpointClientAuthenticationMethods.Descriptor,
            ExtractTokenEndpointClientAuthenticationMethods.Descriptor,

            /*
             * JSON Web Key Set response handling:
             */
            ValidateWellKnownJsonWebKeySetParameters.Descriptor,
            HandleJsonWebKeySetErrorResponse.Descriptor,
            ExtractSigningKeys.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the configuration response.
        /// </summary>
        public sealed class ValidateWellKnownConfigurationParameters : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownConfigurationParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
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
                    Metadata.AuthorizationEndpoint              or
                    Metadata.DeviceAuthorizationEndpoint        or
                    Metadata.EndSessionEndpoint                 or
                    Metadata.Issuer                             or
                    Metadata.JwksUri                            or
                    Metadata.PushedAuthorizationRequestEndpoint or
                    Metadata.TokenEndpoint                      or
                    Metadata.UserInfoEndpoint
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as arrays of strings:
                    Metadata.CodeChallengeMethodsSupported                          or
                    Metadata.DeviceAuthorizationEndpointAuthMethodsSupported        or
                    Metadata.GrantTypesSupported                                    or
                    Metadata.PushedAuthorizationRequestEndpointAuthMethodsSupported or
                    Metadata.ResponseModesSupported                                 or
                    Metadata.ResponseTypesSupported                                 or
                    Metadata.ScopesSupported                                        or
                    Metadata.TokenEndpointAuthMethodsSupported
                        => ((JsonElement) value) is JsonElement element &&
                            element.ValueKind is JsonValueKind.Array &&
                            OpenIddictHelpers.ValidateArrayElements(element, JsonValueKind.String),

                    // The following parameters MUST be formatted as booleans:
                    Metadata.AuthorizationResponseIssParameterSupported or
                    Metadata.RequirePushedAuthorizationRequests         or
                    Metadata.TlsClientCertificateBoundAccessTokens
                        => ((JsonElement) value).ValueKind is JsonValueKind.True or JsonValueKind.False,

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible for surfacing potential errors from the configuration response.
        /// </summary>
        public sealed class HandleConfigurationErrorResponse : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<HandleConfigurationErrorResponse>()
                    .SetOrder(ValidateWellKnownConfigurationParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the specification doesn't define a standard way to return an error other than
                // returning a 4xx status code. That said, some implementations are known to return
                // JSON payloads similar to standard errored token responses. For more information, see
                // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6203), context.Response);

                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2144),
                        uri: SR.FormatID8000(SR.ID2144));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the issuer from the discovery document.
        /// </summary>
        public sealed class ValidateIssuer : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ValidateIssuer>()
                    .SetOrder(HandleConfigurationErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the issuer returned in the discovery document must exactly match the URI used to access it.
                // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation.

                var issuer = (string?) context.Response[Metadata.Issuer];
                if (string.IsNullOrEmpty(issuer))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2096),
                        uri: SR.FormatID8000(SR.ID2096));

                    return default;
                }

                if (!Uri.TryCreate(issuer, UriKind.Absolute, out Uri? uri))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2097),
                        uri: SR.FormatID8000(SR.ID2097));

                    return default;
                }

                // Ensure the issuer matches the expected value.
                if (uri != context.Registration.Issuer)
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2165),
                        uri: SR.FormatID8000(SR.ID2165));

                    return default;
                }

                context.Configuration.Issuer = uri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authorization endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractAuthorizationEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractAuthorizationEndpoint>()
                    .SetOrder(ValidateIssuer.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the authorization_endpoint node is required by the OpenID Connect discovery specification
                // but is optional in the OAuth 2.0 authorization server metadata specification. To make OpenIddict
                // compatible with the newer OAuth 2.0 specification, null/empty and missing values are allowed here.
                //
                // Handlers that require a non-null authorization endpoint URI are expected to return an error
                // if the authorization endpoint URI couldn't be resolved from the authorization server metadata.
                // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationClient
                // and https://datatracker.ietf.org/doc/html/rfc8414#section-2 for more information.
                //
                var endpoint = (string?) context.Response[Metadata.AuthorizationEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.AuthorizationEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.AuthorizationEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the JSON Web Key Set endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractJsonWebKeySetEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractJsonWebKeySetEndpoint>()
                    .SetOrder(ExtractAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the jwks_uri node is required by the OpenID Connect discovery specification.
                // See https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationClient.
                var endpoint = (string?) context.Response[Metadata.JwksUri];
                if (string.IsNullOrEmpty(endpoint))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2099),
                        uri: SR.FormatID8000(SR.ID2099));

                    return default;
                }

                if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2100(Metadata.JwksUri),
                        uri: SR.FormatID8000(SR.ID2100));

                    return default;
                }

                context.Configuration.JsonWebKeySetUri = uri;

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the device authorization endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractDeviceAuthorizationEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractDeviceAuthorizationEndpoint>()
                    .SetOrder(ExtractJsonWebKeySetEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var endpoint = (string?) context.Response[Metadata.DeviceAuthorizationEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.DeviceAuthorizationEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.DeviceAuthorizationEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the introspection endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractIntrospectionEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractIntrospectionEndpoint>()
                    .SetOrder(ExtractDeviceAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var endpoint = (string?) context.Response[Metadata.IntrospectionEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.IntrospectionEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.IntrospectionEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the end session endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractEndSessionEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractEndSessionEndpoint>()
                    .SetOrder(ExtractIntrospectionEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var endpoint = (string?) context.Response[Metadata.EndSessionEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.EndSessionEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.EndSessionEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the mTLS-enabled
        /// device authorization endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractMtlsDeviceAuthorizationEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractMtlsDeviceAuthorizationEndpoint>()
                    .SetOrder(ExtractEndSessionEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var aliases = context.Response[Metadata.MtlsEndpointAliases]?.GetNamedParameters();
                if (aliases is not { Count: > 0 })
                {
                    return default;
                }

                // Note: as recommended by the specification, values present in the "mtls_endpoint_aliases" node
                // that can't be recognized as OAuth 2.0 endpoints or are not valid URIs are simply ignored.
                var endpoint = (string?) aliases[Metadata.DeviceAuthorizationEndpoint];
                if (Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) && !OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Configuration.MtlsDeviceAuthorizationEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the mTLS-enabled
        /// introspection endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractMtlsIntrospectionEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractMtlsIntrospectionEndpoint>()
                    .SetOrder(ExtractMtlsDeviceAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var aliases = context.Response[Metadata.MtlsEndpointAliases]?.GetNamedParameters();
                if (aliases is not { Count: > 0 })
                {
                    return default;
                }

                // Note: as recommended by the specification, values present in the "mtls_endpoint_aliases" node
                // that can't be recognized as OAuth 2.0 endpoints or are not valid URIs are simply ignored.
                var endpoint = (string?) aliases[Metadata.IntrospectionEndpoint];
                if (Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) && !OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Configuration.MtlsIntrospectionEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the mTLS-enabled pushed authorization endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractMtlsPushedAuthorizationEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractMtlsPushedAuthorizationEndpoint>()
                    .SetOrder(ExtractMtlsIntrospectionEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var aliases = context.Response[Metadata.MtlsEndpointAliases]?.GetNamedParameters();
                if (aliases is not { Count: > 0 })
                {
                    return default;
                }

                // Note: as recommended by the specification, values present in the "mtls_endpoint_aliases" node
                // that can't be recognized as OAuth 2.0 endpoints or are not valid URIs are simply ignored.
                var endpoint = (string?) aliases[Metadata.PushedAuthorizationRequestEndpoint];
                if (Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) && !OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Configuration.MtlsPushedAuthorizationEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the mTLS-enabled revocation endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractMtlsRevocationEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractMtlsRevocationEndpoint>()
                    .SetOrder(ExtractMtlsPushedAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var aliases = context.Response[Metadata.MtlsEndpointAliases]?.GetNamedParameters();
                if (aliases is not { Count: > 0 })
                {
                    return default;
                }

                // Note: as recommended by the specification, values present in the "mtls_endpoint_aliases" node
                // that can't be recognized as OAuth 2.0 endpoints or are not valid URIs are simply ignored.
                var endpoint = (string?) aliases[Metadata.RevocationEndpoint];
                if (Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) && !OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Configuration.MtlsRevocationEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the mTLS-enabled token endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractMtlsTokenEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractMtlsTokenEndpoint>()
                    .SetOrder(ExtractMtlsRevocationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var aliases = context.Response[Metadata.MtlsEndpointAliases]?.GetNamedParameters();
                if (aliases is not { Count: > 0 })
                {
                    return default;
                }

                // Note: as recommended by the specification, values present in the "mtls_endpoint_aliases" node
                // that can't be recognized as OAuth 2.0 endpoints or are not valid URIs are simply ignored.
                var endpoint = (string?) aliases[Metadata.TokenEndpoint];
                if (Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) && !OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Configuration.MtlsTokenEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the mTLS-enabled userinfo endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractMtlsUserInfoEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractMtlsUserInfoEndpoint>()
                    .SetOrder(ExtractMtlsTokenEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var aliases = context.Response[Metadata.MtlsEndpointAliases]?.GetNamedParameters();
                if (aliases is not { Count: > 0 })
                {
                    return default;
                }

                // Note: as recommended by the specification, values present in the "mtls_endpoint_aliases" node
                // that can't be recognized as OAuth 2.0 endpoints or are not valid URIs are simply ignored.
                var endpoint = (string?) aliases[Metadata.UserInfoEndpoint];
                if (Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) && !OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Configuration.MtlsUserInfoEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the pushed authorization endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractPushedAuthorizationEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractPushedAuthorizationEndpoint>()
                    .SetOrder(ExtractEndSessionEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var endpoint = (string?) context.Response[Metadata.PushedAuthorizationRequestEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.PushedAuthorizationRequestEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.PushedAuthorizationEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the revocation endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractRevocationEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractRevocationEndpoint>()
                    .SetOrder(ExtractPushedAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var endpoint = (string?) context.Response[Metadata.RevocationEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.RevocationEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.RevocationEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the token endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractTokenEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractTokenEndpoint>()
                    .SetOrder(ExtractRevocationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var endpoint = (string?) context.Response[Metadata.TokenEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.TokenEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.TokenEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the userinfo endpoint URI from the discovery document.
        /// </summary>
        public sealed class ExtractUserInfoEndpoint : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractUserInfoEndpoint>()
                    .SetOrder(ExtractTokenEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var endpoint = (string?) context.Response[Metadata.UserInfoEndpoint];
                if (!string.IsNullOrEmpty(endpoint))
                {
                    if (!Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? uri) || OpenIddictHelpers.IsImplicitFileUri(uri))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.FormatID2100(Metadata.UserInfoEndpoint),
                            uri: SR.FormatID8000(SR.ID2100));

                        return default;
                    }

                    context.Configuration.UserInfoEndpoint = uri;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported grant types from the discovery document.
        /// </summary>
        public sealed class ExtractGrantTypes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractGrantTypes>()
                    .SetOrder(ExtractAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the grant types supported by the authorization endpoint, if available.
                var types = context.Response[Metadata.GrantTypesSupported]?.GetUnnamedParameters();
                if (types is { Count: > 0 })
                {
                    for (var index = 0; index < types.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var type = (string?) types[index];
                        if (!string.IsNullOrEmpty(type))
                        {
                            context.Configuration.GrantTypesSupported.Add(type);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported response types from the discovery document.
        /// </summary>
        public sealed class ExtractResponseModes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractResponseModes>()
                    .SetOrder(ExtractAuthorizationEndpoint.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the response modes supported by the authorization endpoint, if available.
                var modes = context.Response[Metadata.ResponseModesSupported]?.GetUnnamedParameters();
                if (modes is { Count: > 0 })
                {
                    for (var index = 0; index < modes.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var mode = (string?) modes[index];
                        if (!string.IsNullOrEmpty(mode))
                        {
                            context.Configuration.ResponseModesSupported.Add(mode);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported response types from the discovery document.
        /// </summary>
        public sealed class ExtractResponseTypes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractResponseTypes>()
                    .SetOrder(ExtractResponseModes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the response types supported by the authorization endpoint, if available.
                var types = context.Response[Metadata.ResponseTypesSupported]?.GetUnnamedParameters();
                if (types is { Count: > 0 })
                {
                    for (var index = 0; index < types.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var type = (string?) types[index];
                        if (!string.IsNullOrEmpty(type))
                        {
                            context.Configuration.ResponseTypesSupported.Add(type);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported code challenge methods from the discovery document.
        /// </summary>
        public sealed class ExtractCodeChallengeMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractCodeChallengeMethods>()
                    .SetOrder(ExtractResponseTypes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the code challenge methods supported by the authorization endpoint, if available.
                var methods = context.Response[Metadata.CodeChallengeMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.CodeChallengeMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the supported scopes from the discovery document.
        /// </summary>
        public sealed class ExtractScopes : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractScopes>()
                    .SetOrder(ExtractCodeChallengeMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the scopes supported by the remote server, if available.
                var scopes = context.Response[Metadata.ScopesSupported]?.GetUnnamedParameters();
                if (scopes is { Count: > 0 })
                {
                    for (var index = 0; index < scopes.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var scope = (string?) scopes[index];
                        if (!string.IsNullOrEmpty(scope))
                        {
                            context.Configuration.ScopesSupported.Add(scope);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the flag indicating
        /// whether the "iss" parameter is supported from the discovery document.
        /// </summary>
        public sealed class ExtractIssuerParameterRequirement : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractIssuerParameterRequirement>()
                    .SetOrder(ExtractScopes.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Configuration.AuthorizationResponseIssParameterSupported = (bool?)
                    context.Response[Metadata.AuthorizationResponseIssParameterSupported];

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the flag indicating whether client
        /// certificate-bound access tokens are supported from the discovery document.
        /// </summary>
        public sealed class ExtractTlsClientCertificateAccessTokenBindingRequirement : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractTlsClientCertificateAccessTokenBindingRequirement>()
                    .SetOrder(ExtractIssuerParameterRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Configuration.TlsClientCertificateBoundAccessTokens = (bool?)
                    context.Response[Metadata.TlsClientCertificateBoundAccessTokens];

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the flag indicating whether pushed
        /// authorization requests (PAR) are considered mandatory from the discovery document.
        /// </summary>
        public sealed class ExtractPushedAuthorizationRequirement : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractPushedAuthorizationRequirement>()
                    .SetOrder(ExtractTlsClientCertificateAccessTokenBindingRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                context.Configuration.RequirePushedAuthorizationRequests = (bool?)
                    context.Response[Metadata.RequirePushedAuthorizationRequests];

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authentication methods
        /// supported by the device authorization endpoint from the discovery document.
        /// </summary>
        public sealed class ExtractDeviceAuthorizationEndpointClientAuthenticationMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractDeviceAuthorizationEndpointClientAuthenticationMethods>()
                    .SetOrder(ExtractPushedAuthorizationRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the client authentication methods supported by the device authorization endpoint, if available.
                //
                // Note: "device_authorization_endpoint_auth_methods_supported" is not a standard parameter
                // but is supported by OpenIddict 4.3.0 and higher for consistency with the other endpoints.
                var methods = context.Response[Metadata.DeviceAuthorizationEndpointAuthMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.DeviceAuthorizationEndpointAuthMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authentication methods
        /// supported by the introspection endpoint from the discovery document.
        /// </summary>
        public sealed class ExtractIntrospectionEndpointClientAuthenticationMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractIntrospectionEndpointClientAuthenticationMethods>()
                    .SetOrder(ExtractDeviceAuthorizationEndpointClientAuthenticationMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the client authentication methods supported by the introspection endpoint, if available.
                var methods = context.Response[Metadata.IntrospectionEndpointAuthMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.IntrospectionEndpointAuthMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authentication methods
        /// supported by the pushed authorization endpoint from the discovery document.
        /// </summary>
        public sealed class ExtractPushedAuthorizationEndpointClientAuthenticationMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractPushedAuthorizationEndpointClientAuthenticationMethods>()
                    .SetOrder(ExtractTlsClientCertificateAccessTokenBindingRequirement.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the client authentication methods supported by the pushed authorization endpoint, if available.
                //
                // Note: "pushed_authorization_request_endpoint_auth_methods_supported" is not a standard parameter
                // but is supported by OpenIddict 6.1.0 and higher for consistency with the other endpoints.
                var methods = context.Response[Metadata.PushedAuthorizationRequestEndpointAuthMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.PushedAuthorizationEndpointAuthMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authentication methods
        /// supported by the revocation endpoint from the discovery document.
        /// </summary>
        public sealed class ExtractRevocationEndpointClientAuthenticationMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractRevocationEndpointClientAuthenticationMethods>()
                    .SetOrder(ExtractPushedAuthorizationEndpointClientAuthenticationMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the client authentication methods supported by the revocation endpoint, if available.
                var methods = context.Response[Metadata.RevocationEndpointAuthMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.RevocationEndpointAuthMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the authentication methods
        /// supported by the token endpoint from the discovery document.
        /// </summary>
        public sealed class ExtractTokenEndpointClientAuthenticationMethods : IOpenIddictClientHandler<HandleConfigurationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleConfigurationResponseContext>()
                    .UseSingletonHandler<ExtractTokenEndpointClientAuthenticationMethods>()
                    .SetOrder(ExtractRevocationEndpointClientAuthenticationMethods.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleConfigurationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Resolve the client authentication methods supported by the token endpoint, if available.
                var methods = context.Response[Metadata.TokenEndpointAuthMethodsSupported]?.GetUnnamedParameters();
                if (methods is { Count: > 0 })
                {
                    for (var index = 0; index < methods.Count; index++)
                    {
                        // Note: custom values are allowed in this case.
                        var method = (string?) methods[index];
                        if (!string.IsNullOrEmpty(method))
                        {
                            context.Configuration.TokenEndpointAuthMethodsSupported.Add(method);
                        }
                    }
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the JSON Web Key Set response.
        /// </summary>
        public sealed class ValidateWellKnownJsonWebKeySetParameters : IOpenIddictClientHandler<HandleJsonWebKeySetResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleJsonWebKeySetResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownJsonWebKeySetParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleJsonWebKeySetResponseContext context)
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

                    // The following parameters MUST be formatted as arrays of objects:
                    JsonWebKeySetParameterNames.Keys => ((JsonElement) value) is JsonElement element &&
                        element.ValueKind is JsonValueKind.Array && ValidateObjectArray(element),

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };

                static bool ValidateObjectArray(JsonElement element)
                {
                    foreach (var item in element.EnumerateArray())
                    {
                        if (item.ValueKind is not JsonValueKind.Object)
                        {
                            return false;
                        }
                    }

                    return true;
                }
            }
        }

        /// <summary>
        /// Contains the logic responsible for surfacing potential errors from the JSON Web Key Set response.
        /// </summary>
        public sealed class HandleJsonWebKeySetErrorResponse : IOpenIddictClientHandler<HandleJsonWebKeySetResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleJsonWebKeySetResponseContext>()
                    .UseSingletonHandler<HandleJsonWebKeySetErrorResponse>()
                    .SetOrder(ValidateWellKnownJsonWebKeySetParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleJsonWebKeySetResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Note: the specification doesn't define a standard way to return an error other than
                // returning a 4xx status code. That said, some implementations are known to return
                // JSON payloads similar to standard errored token responses. For more information, see
                // https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationResponse.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6204), context.Response);

                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.GetResourceString(SR.ID2145),
                        uri: SR.FormatID8000(SR.ID2145));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for extracting the signing keys from the JSON Web Key Set document.
        /// </summary>
        public sealed class ExtractSigningKeys : IOpenIddictClientHandler<HandleJsonWebKeySetResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleJsonWebKeySetResponseContext>()
                    .UseSingletonHandler<ExtractSigningKeys>()
                    .SetOrder(HandleJsonWebKeySetErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleJsonWebKeySetResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                var keys = context.Response[JsonWebKeySetParameterNames.Keys]?.GetUnnamedParameters();
                if (keys is not { Count: > 0 })
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2102(JsonWebKeySetParameterNames.Keys),
                        uri: SR.FormatID8000(SR.ID2102));

                    return default;
                }

                for (var index = 0; index < keys.Count; index++)
                {
                    // Note: the "use" parameter is defined as optional by the JSON Web Key Set specification
                    // but is required by the OpenID Connect discovery specification if both signing
                    // and encryption keys are present in the returned list. If the "use" parameter
                    // is not explicitly specified or has an empty value, assume it is a signing key.
                    //
                    // For more information, see https://www.rfc-editor.org/rfc/rfc7517#section-4.2
                    // and https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata.
                    var use = (string?) keys[index][JsonWebKeyParameterNames.Use];
                    if (string.IsNullOrEmpty(use))
                    {
                        use = JsonWebKeyUseNames.Sig;
                    }

                    // Ignore security keys that are not used for signing.
                    if (!string.Equals(use, JsonWebKeyUseNames.Sig, StringComparison.Ordinal))
                    {
                        continue;
                    }

                    var key = (string?) keys[index][JsonWebKeyParameterNames.Kty] switch
                    {
                        JsonWebAlgorithmsKeyTypes.RSA => new JsonWebKey
                        {
                            Kty = JsonWebAlgorithmsKeyTypes.RSA,
                            E = (string?) keys[index][JsonWebKeyParameterNames.E],
                            N = (string?) keys[index][JsonWebKeyParameterNames.N]
                        },

                        JsonWebAlgorithmsKeyTypes.EllipticCurve => new JsonWebKey
                        {
                            Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                            Crv = (string?) keys[index][JsonWebKeyParameterNames.Crv],
                            X = (string?) keys[index][JsonWebKeyParameterNames.X],
                            Y = (string?) keys[index][JsonWebKeyParameterNames.Y]
                        },

                        _ => null
                    };

                    if (key is null)
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.GetResourceString(SR.ID2103),
                            uri: SR.FormatID8000(SR.ID2103));

                        return default;
                    }

                    // If the key is a RSA key, ensure the mandatory parameters are all present.
                    if (string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal) &&
                       (string.IsNullOrEmpty(key.E) || string.IsNullOrEmpty(key.N)))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.GetResourceString(SR.ID2104),
                            uri: SR.FormatID8000(SR.ID2104));

                        return default;
                    }

                    // If the key is an EC key, ensure the mandatory parameters are all present.
                    if (string.Equals(key.Kty, JsonWebAlgorithmsKeyTypes.EllipticCurve, StringComparison.Ordinal) &&
                       (string.IsNullOrEmpty(key.Crv) || string.IsNullOrEmpty(key.X) || string.IsNullOrEmpty(key.Y)))
                    {
                        context.Reject(
                            error: Errors.ServerError,
                            description: SR.GetResourceString(SR.ID2104),
                            uri: SR.FormatID8000(SR.ID2104));

                        return default;
                    }

                    key.KeyId = (string?) keys[index][JsonWebKeyParameterNames.Kid];
                    key.X5t = (string?) keys[index][JsonWebKeyParameterNames.X5t];
                    key.X5tS256 = (string?) keys[index][JsonWebKeyParameterNames.X5tS256];

                    if (keys[index].TryGetNamedParameter(JsonWebKeyParameterNames.X5c, out var chain))
                    {
                        foreach (string? certificate in chain.GetUnnamedParameters())
                        {
                            if (string.IsNullOrEmpty(certificate))
                            {
                                continue;
                            }

                            key.X5c.Add(certificate);
                        }
                    }

                    context.JsonWebKeySet.Keys.Add(key);
                }

                return default;
            }
        }
    }
}

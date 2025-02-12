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
    public static class Device
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Device authorization response handling:
             */
            ValidateWellKnownParameters.Descriptor,
            HandleErrorResponse.Descriptor,
            ValidateVerificationEndpointUri.Descriptor,
            ValidateExpiration.Descriptor
        ]);

        /// <summary>
        /// Contains the logic responsible for validating the well-known parameters contained in the device authorization response.
        /// </summary>
        public sealed class ValidateWellKnownParameters : IOpenIddictClientHandler<HandleDeviceAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleDeviceAuthorizationResponseContext>()
                    .UseSingletonHandler<ValidateWellKnownParameters>()
                    .SetOrder(int.MinValue + 100_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleDeviceAuthorizationResponseContext context)
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
                    Parameters.DeviceCode      or Parameters.UserCode or
                    Parameters.VerificationUri or Parameters.VerificationUriComplete
                        => ((JsonElement) value).ValueKind is JsonValueKind.String,

                    // The following parameters MUST be formatted as numeric dates:
                    Parameters.ExpiresIn => (JsonElement) value is { ValueKind: JsonValueKind.Number } element &&
                        element.TryGetDecimal(out decimal result) && result is >= 0,

                    // The following parameters MUST be formatted as positive integers:
                    Parameters.Interval => (JsonElement) value is { ValueKind: JsonValueKind.Number } element &&
                        element.TryGetDecimal(out decimal result) && result is >= 0,

                    // Parameters that are not in the well-known list can be of any type.
                    _ => true
                };
            }
        }

        /// <summary>
        /// Contains the logic responsible for surfacing potential errors from the device authorization response.
        /// </summary>
        public sealed class HandleErrorResponse : IOpenIddictClientHandler<HandleDeviceAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleDeviceAuthorizationResponseContext>()
                    .UseSingletonHandler<HandleErrorResponse>()
                    .SetOrder(ValidateWellKnownParameters.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleDeviceAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // For more information, see https://www.rfc-editor.org/rfc/rfc8628#section-3.2.
                if (!string.IsNullOrEmpty(context.Response.Error))
                {
                    context.Logger.LogInformation(SR.GetResourceString(SR.ID6216), context.Response);

                    context.Reject(
                        error: context.Response.Error switch
                        {
                            Errors.InvalidClient      => Errors.InvalidRequest,
                            Errors.InvalidScope       => Errors.InvalidScope,
                            Errors.InvalidRequest     => Errors.InvalidRequest,
                            Errors.UnauthorizedClient => Errors.UnauthorizedClient,
                            _                         => Errors.ServerError
                        },
                        description: SR.GetResourceString(SR.ID2167),
                        uri: SR.FormatID8000(SR.ID2167));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the verification
        /// endpoint URI contained in the device authorization response.
        /// </summary>
        public sealed class ValidateVerificationEndpointUri : IOpenIddictClientHandler<HandleDeviceAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleDeviceAuthorizationResponseContext>()
                    .UseSingletonHandler<ValidateVerificationEndpointUri>()
                    .SetOrder(HandleErrorResponse.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleDeviceAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Return an error if the mandatory "verification_uri" parameter is missing.
                // For more information, see https://www.rfc-editor.org/rfc/rfc8628#section-3.2.
                if (string.IsNullOrEmpty(context.Response.VerificationUri))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2168(Parameters.VerificationUri),
                        uri: SR.FormatID8000(SR.ID2168));

                    return default;
                }

                // Return an error if the "verification_uri" parameter is malformed.
                if (!Uri.TryCreate(context.Response.VerificationUri, UriKind.Absolute, out Uri? uri) ||
                    OpenIddictHelpers.IsImplicitFileUri(uri))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2169(Parameters.VerificationUri),
                        uri: SR.FormatID8000(SR.ID2169));

                    return default;
                }

                // Note: the "verification_uri_complete" parameter is optional and MUST NOT
                // cause an error if it's missing from the device authorization response.
                if (!string.IsNullOrEmpty(context.Response.VerificationUriComplete) &&
                   (!Uri.TryCreate(context.Response.VerificationUriComplete, UriKind.Absolute, out uri) ||
                    OpenIddictHelpers.IsImplicitFileUri(uri)))
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2169(Parameters.VerificationUriComplete),
                        uri: SR.FormatID8000(SR.ID2169));

                    return default;
                }

                return default;
            }
        }

        /// <summary>
        /// Contains the logic responsible for validating the "expires_in"
        /// parameter contained in the device authorization response.
        /// </summary>
        public sealed class ValidateExpiration : IOpenIddictClientHandler<HandleDeviceAuthorizationResponseContext>
        {
            /// <summary>
            /// Gets the default descriptor definition assigned to this handler.
            /// </summary>
            public static OpenIddictClientHandlerDescriptor Descriptor { get; }
                = OpenIddictClientHandlerDescriptor.CreateBuilder<HandleDeviceAuthorizationResponseContext>()
                    .UseSingletonHandler<ValidateExpiration>()
                    .SetOrder(ValidateVerificationEndpointUri.Descriptor.Order + 1_000)
                    .SetType(OpenIddictClientHandlerType.BuiltIn)
                    .Build();

            /// <inheritdoc/>
            public ValueTask HandleAsync(HandleDeviceAuthorizationResponseContext context)
            {
                if (context is null)
                {
                    throw new ArgumentNullException(nameof(context));
                }

                // Return an error if the mandatory "expires_in" parameter is missing.
                // For more information, see https://www.rfc-editor.org/rfc/rfc8628#section-3.2.
                if (context.Response.ExpiresIn is null)
                {
                    context.Reject(
                        error: Errors.ServerError,
                        description: SR.FormatID2168(Parameters.ExpiresIn),
                        uri: SR.FormatID8000(SR.ID2168));

                    return default;
                }

                return default;
            }
        }
    }
}

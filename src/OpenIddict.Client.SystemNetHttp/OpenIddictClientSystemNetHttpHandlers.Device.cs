/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Device
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Device authorization request processing:
             */
            CreateHttpClient<PrepareDeviceAuthorizationRequestContext>.Descriptor,
            PreparePostHttpRequest<PrepareDeviceAuthorizationRequestContext>.Descriptor,
            AttachHttpVersion<PrepareDeviceAuthorizationRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PrepareDeviceAuthorizationRequestContext>.Descriptor,
            AttachUserAgentHeader<PrepareDeviceAuthorizationRequestContext>.Descriptor,
            AttachFromHeader<PrepareDeviceAuthorizationRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials<PrepareDeviceAuthorizationRequestContext>.Descriptor,
            AttachHttpParameters<PrepareDeviceAuthorizationRequestContext>.Descriptor,
            SendHttpRequest<ApplyDeviceAuthorizationRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyDeviceAuthorizationRequestContext>.Descriptor,

            /*
             * Device authorization response processing:
             */
            DecompressResponseContent<ExtractDeviceAuthorizationResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractDeviceAuthorizationResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractDeviceAuthorizationResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractDeviceAuthorizationResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractDeviceAuthorizationResponseContext>.Descriptor
        ]);
    }
}

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;

namespace OpenIddict.Client.SystemNetHttp;

public static partial class OpenIddictClientSystemNetHttpHandlers
{
    public static class Authorization
    {
        public static ImmutableArray<OpenIddictClientHandlerDescriptor> DefaultHandlers { get; } = ImmutableArray.Create([
            /*
             * Pushed authorization request processing:
             */
            CreateHttpClient<PreparePushedAuthorizationRequestContext>.Descriptor,
            PreparePostHttpRequest<PreparePushedAuthorizationRequestContext>.Descriptor,
            AttachHttpVersion<PreparePushedAuthorizationRequestContext>.Descriptor,
            AttachJsonAcceptHeaders<PreparePushedAuthorizationRequestContext>.Descriptor,
            AttachUserAgentHeader<PreparePushedAuthorizationRequestContext>.Descriptor,
            AttachFromHeader<PreparePushedAuthorizationRequestContext>.Descriptor,
            AttachBasicAuthenticationCredentials<PreparePushedAuthorizationRequestContext>.Descriptor,
            AttachHttpParameters<PreparePushedAuthorizationRequestContext>.Descriptor,
            SendHttpRequest<ApplyPushedAuthorizationRequestContext>.Descriptor,
            DisposeHttpRequest<ApplyPushedAuthorizationRequestContext>.Descriptor,

            /*
             * Pushed authorization response processing:
             */
            DecompressResponseContent<ExtractPushedAuthorizationResponseContext>.Descriptor,
            ExtractJsonHttpResponse<ExtractPushedAuthorizationResponseContext>.Descriptor,
            ExtractWwwAuthenticateHeader<ExtractPushedAuthorizationResponseContext>.Descriptor,
            ValidateHttpResponse<ExtractPushedAuthorizationResponseContext>.Descriptor,
            DisposeHttpResponse<ExtractPushedAuthorizationResponseContext>.Descriptor
        ]);
    }
}

﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;

namespace OpenIddict.Server.Internal
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    public sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        public override Task ExtractConfigurationRequest([NotNull] ExtractConfigurationRequestContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ExtractConfigurationRequest(context));

        public override Task ValidateConfigurationRequest([NotNull] ValidateConfigurationRequestContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ValidateConfigurationRequest(context));

        public override Task HandleConfigurationRequest([NotNull] HandleConfigurationRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            // Note: though it's natively supported by the OpenID Connect server middleware,
            // OpenIddict disallows the use of the unsecure code_challenge_method=plain method,
            // which is manually removed from the code_challenge_methods_supported property.
            // See https://tools.ietf.org/html/rfc7636#section-7.2 for more information.
            context.CodeChallengeMethods.Remove(OpenIdConnectConstants.CodeChallengeMethods.Plain);

            // Note: the OpenID Connect server middleware automatically populates grant_types_supported
            // by determining whether the authorization and token endpoints are enabled or not but
            // OpenIddict uses a different approach and relies on a configurable "grants list".
            context.GrantTypes.Clear();
            context.GrantTypes.UnionWith(options.GrantTypes);

            // Only return the scopes and the claims configured by the developer.
            context.Scopes.Clear();
            context.Scopes.UnionWith(options.Scopes);
            context.Claims.Clear();
            context.Claims.UnionWith(options.Claims);

            // Note: the optional claims/request/request_uri parameters are not supported
            // by OpenIddict, so "false" is returned to encourage clients not to use them.
            context.Metadata[OpenIdConnectConstants.Metadata.ClaimsParameterSupported] = false;
            context.Metadata[OpenIdConnectConstants.Metadata.RequestParameterSupported] = false;
            context.Metadata[OpenIdConnectConstants.Metadata.RequestUriParameterSupported] = false;

            return GetEventService(context.HttpContext.RequestServices).PublishAsync(new OpenIddictServerEvents.HandleConfigurationRequest(context));
        }

        public override Task ApplyConfigurationResponse([NotNull] ApplyConfigurationResponseContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ApplyConfigurationResponse(context));

        public override Task ExtractCryptographyRequest([NotNull] ExtractCryptographyRequestContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ExtractCryptographyRequest(context));

        public override Task ValidateCryptographyRequest([NotNull] ValidateCryptographyRequestContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ValidateCryptographyRequest(context));

        public override Task HandleCryptographyRequest([NotNull] HandleCryptographyRequestContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.HandleCryptographyRequest(context));

        public override Task ApplyCryptographyResponse([NotNull] ApplyCryptographyResponseContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ApplyCryptographyResponse(context));
    }
}

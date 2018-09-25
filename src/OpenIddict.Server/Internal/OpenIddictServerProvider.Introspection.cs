﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Primitives;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;

namespace OpenIddict.Server.Internal
{
    /// <summary>
    /// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
    /// Note: this API supports the OpenIddict infrastructure and is not intended to be used
    /// directly from your code. This API may change or be removed in future minor releases.
    /// </summary>
    public sealed partial class OpenIddictServerProvider : OpenIdConnectServerProvider
    {
        public override Task ExtractIntrospectionRequest([NotNull] ExtractIntrospectionRequestContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ExtractIntrospectionRequest(context));

        public override async Task ValidateIntrospectionRequest([NotNull] ValidateIntrospectionRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            var logger = GetLogger(context.HttpContext.RequestServices);
            var applicationManager = GetApplicationManager(context.HttpContext.RequestServices);

            // Note: the OpenID Connect server middleware supports unauthenticated introspection requests
            // but OpenIddict uses a stricter policy preventing unauthenticated/public applications
            // from using the introspection endpoint, as required by the specifications.
            // See https://tools.ietf.org/html/rfc7662#section-2.1 for more information.
            if (string.IsNullOrEmpty(context.ClientId) || string.IsNullOrEmpty(context.ClientSecret))
            {
                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidRequest,
                    description: "The mandatory 'client_id' and/or 'client_secret' parameters are missing.");

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await applicationManager.FindByClientIdAsync(context.ClientId);
            if (application == null)
            {
                logger.LogError("The introspection request was rejected because the client " +
                                "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The specified 'client_id' parameter is invalid.");

                return;
            }

            // Store the application entity as a request property to make it accessible
            // from the other provider methods without having to call the store twice.
            context.Request.SetProperty($"{OpenIddictConstants.Properties.Application}:{context.ClientId}", application);

            // Reject the request if the application is not allowed to use the introspection endpoint.
            if (!options.IgnoreEndpointPermissions &&
                !await applicationManager.HasPermissionAsync(application, OpenIddictConstants.Permissions.Endpoints.Introspection))
            {
                logger.LogError("The introspection request was rejected because the application '{ClientId}' " +
                                "was not allowed to use the introspection endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.UnauthorizedClient,
                    description: "This client application is not allowed to use the introspection endpoint.");

                return;
            }

            // Reject introspection requests sent by public applications.
            if (await applicationManager.IsPublicAsync(application))
            {
                logger.LogError("The introspection request was rejected because the public application " +
                                "'{ClientId}' was not allowed to use this endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "This client application is not allowed to use the introspection endpoint.");

                return;
            }

            // Validate the client credentials.
            if (!await applicationManager.ValidateClientSecretAsync(application, context.ClientSecret))
            {
                logger.LogError("The introspection request was rejected because the confidential or hybrid application " +
                                "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                context.Reject(
                    error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The specified client credentials are invalid.");

                return;
            }

            context.Validate();

            await GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ValidateIntrospectionRequest(context));
        }

        public override async Task HandleIntrospectionRequest([NotNull] HandleIntrospectionRequestContext context)
        {
            var options = (OpenIddictServerOptions) context.Options;

            var logger = GetLogger(context.HttpContext.RequestServices);
            var authorizationManager = GetAuthorizationManager(context.HttpContext.RequestServices);
            var tokenManager = GetTokenManager(context.HttpContext.RequestServices);

            Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");
            Debug.Assert(!string.IsNullOrEmpty(context.Request.ClientId), "The client_id parameter shouldn't be null.");

            var identifier = context.Ticket.GetProperty(OpenIddictConstants.Properties.InternalTokenId);
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The authentication ticket should contain a token identifier.");

            if (!context.Ticket.IsAccessToken())
            {
                logger.LogError("The token '{Identifier}' is not an access token and thus cannot be introspected.", identifier);

                context.Active = false;

                return;
            }

            // Note: the OpenID Connect server middleware allows authorized presenters (e.g relying parties) to introspect
            // tokens but OpenIddict uses a stricter policy that only allows resource servers to use the introspection endpoint.
            // For that, an error is automatically returned if no explicit audience is attached to the authentication ticket.
            if (!context.Ticket.HasAudience())
            {
                logger.LogError("The token '{Identifier}' doesn't have any audience attached " +
                                "and cannot be introspected. To add an audience, use the " +
                                "'ticket.SetResources(...)' extension when creating the ticket.", identifier);

                context.Active = false;

                return;
            }

            if (!context.Ticket.HasAudience(context.Request.ClientId))
            {
                logger.LogError("The client application '{ClientId}' is not allowed to introspect the access " +
                                "token '{Identifier}' because it's not listed as a valid audience.",
                                context.Request.ClientId, identifier);

                context.Active = false;

                return;
            }

            // If an authorization was attached to the access token, ensure it is still valid.
            if (!options.DisableAuthorizationStorage &&
                 context.Ticket.HasProperty(OpenIddictConstants.Properties.InternalAuthorizationId))
            {
                var authorization = await authorizationManager.FindByIdAsync(
                    context.Ticket.GetProperty(OpenIddictConstants.Properties.InternalAuthorizationId));

                if (authorization == null || !await authorizationManager.IsValidAsync(authorization))
                {
                    logger.LogError("The token '{Identifier}' was declared as inactive because " +
                                    "the associated authorization was no longer valid.", identifier);

                    context.Active = false;

                    return;
                }
            }

            // If the received token is a reference access token - i.e a token for
            // which an entry exists in the database - ensure it is still valid.
            if (options.UseReferenceTokens)
            {
                // Retrieve the token from the request properties. If it's marked as invalid, return active = false.
                var token = context.Request.GetProperty($"{OpenIddictConstants.Properties.Token}:{identifier}");
                Debug.Assert(token != null, "The token shouldn't be null.");

                if (!await tokenManager.IsValidAsync(token))
                {
                    logger.LogInformation("The token '{Identifier}' was declared as inactive because it was revoked.", identifier);

                    context.Active = false;

                    return;
                }
            }

            await GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.HandleIntrospectionRequest(context));
        }

        public override Task ApplyIntrospectionResponse([NotNull] ApplyIntrospectionResponseContext context)
            => GetEventService(context.HttpContext.RequestServices)
                .PublishAsync(new OpenIddictServerEvents.ApplyIntrospectionResponse(context));
    }
}

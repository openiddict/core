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
using Microsoft.Extensions.Logging;
using OpenIddict.Core;

namespace OpenIddict
{
    public partial class OpenIddictProvider<TApplication, TAuthorization, TScope, TToken> : OpenIdConnectServerProvider
        where TApplication : class where TAuthorization : class where TScope : class where TToken : class
    {
        public override async Task ValidateTokenRequest([NotNull] ValidateTokenRequestContext context)
        {
            var options = (OpenIddictOptions) context.Options;

            // Reject token requests that don't specify a supported grant type.
            if (!options.GrantTypes.Contains(context.Request.GrantType))
            {
                Logger.LogError("The token request was rejected because the '{GrantType}' " +
                                "grant type is not supported.", context.Request.GrantType);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnsupportedGrantType,
                    description: "The specified 'grant_type' parameter is not supported.");

                return;
            }

            // Reject token requests that specify scope=offline_access if the refresh token flow is not enabled.
            if (context.Request.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess) &&
               !options.GrantTypes.Contains(OpenIdConnectConstants.GrantTypes.RefreshToken))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not allowed.");

                return;
            }

            // Optimization: the OpenID Connect server middleware automatically rejects grant_type=authorization_code
            // requests missing the redirect_uri parameter if one was specified in the initial authorization request.
            // Since OpenIddict doesn't allow redirect_uri-less authorization requests, an earlier check can be made here,
            // which saves the OpenID Connect server middleware from having to deserialize the authorization code ticket.
            // See http://openid.net/specs/openid-connect-core-1_0.html#TokenRequestValidation for more information.
            if (context.Request.IsAuthorizationCodeGrantType() && string.IsNullOrEmpty(context.Request.RedirectUri))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The mandatory 'redirect_uri' parameter is missing.");

                return;
            }

            // Note: the OpenID Connect server middleware allows returning a refresh token with grant_type=client_credentials,
            // though it's usually not recommended by the OAuth2 specification. To encourage developers to make a new
            // grant_type=client_credentials request instead of using refresh tokens, OpenIddict uses a stricter policy
            // that rejects grant_type=client_credentials requests containing the 'offline_access' scope.
            // See https://tools.ietf.org/html/rfc6749#section-4.4.3 for more information.
            if (context.Request.IsClientCredentialsGrantType() &&
                context.Request.HasScope(OpenIdConnectConstants.Scopes.OfflineAccess))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The 'offline_access' scope is not valid for the specified 'grant_type' parameter.");

                return;
            }

            // Optimization: the OpenID Connect server middleware automatically rejects grant_type=client_credentials
            // requests when validation is skipped but an earlier check is made here to avoid making unnecessary
            // database roundtrips to retrieve the client application corresponding to the client_id.
            if (context.Request.IsClientCredentialsGrantType() && (string.IsNullOrEmpty(context.Request.ClientId) ||
                                                                   string.IsNullOrEmpty(context.Request.ClientSecret)))
            {
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The 'client_id' and 'client_secret' parameters are " +
                                 "required when using the client credentials grant.");

                return;
            }

            // At this stage, skip client authentication if the client identifier is missing
            // or reject the token request if client identification is set as required.
            // Note: the OpenID Connect server middleware will automatically ensure that
            // the calling application cannot use an authorization code or a refresh token
            // if it's not the intended audience, even if client authentication was skipped.
            if (string.IsNullOrEmpty(context.ClientId))
            {
                // Reject the request if client identification is mandatory.
                if (options.RequireClientIdentification)
                {
                    Logger.LogError("The token request was rejected becaused the " +
                                    "mandatory client_id parameter was missing or empty.");

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The mandatory 'client_id' parameter is missing.");

                    return;
                }

                Logger.LogDebug("The token request validation process was partially skipped " +
                                "because the 'client_id' parameter was missing or empty.");

                context.Skip();

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await Applications.FindByClientIdAsync(context.ClientId, context.HttpContext.RequestAborted);
            if (application == null)
            {
                Logger.LogError("The token request was rejected because the client " +
                                "application was not found: '{ClientId}'.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified 'client_id' parameter is invalid.");

                return;
            }

            // Store the application entity as a request property to make it accessible
            // from the other provider methods without having to call the store twice.
            context.Request.SetProperty($"{OpenIddictConstants.Properties.Application}:{context.ClientId}", application);

            // Reject the request if the application is not allowed to use the token endpoint.
            if (!await Applications.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Endpoints.Token, context.HttpContext.RequestAborted))
            {
                Logger.LogError("The token request was rejected because the application '{ClientId}' " +
                                "was not allowed to use the token endpoint.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnauthorizedClient,
                    description: "This client application is not allowed to use the token endpoint.");

                return;
            }

            // Reject the request if the application is not allowed to use the specified grant type.
            if (!await Applications.HasPermissionAsync(application,
                OpenIddictConstants.Permissions.Prefixes.GrantType + context.Request.GrantType, context.HttpContext.RequestAborted))
            {
                Logger.LogError("The token request was rejected because the application '{ClientId}' was not allowed to " +
                                "use the specified grant type: {GrantType}.", context.ClientId, context.Request.GrantType);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.UnauthorizedClient,
                    description: "This client application is not allowed to use the specified grant type.");

                return;
            }

            if (await Applications.IsPublicAsync(application, context.HttpContext.RequestAborted))
            {
                // Note: public applications are not allowed to use the client credentials grant.
                if (context.Request.IsClientCredentialsGrantType())
                {
                    Logger.LogError("The token request was rejected because the public client application '{ClientId}' " +
                                    "was not allowed to use the client credentials grant.", context.Request.ClientId);

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.UnauthorizedClient,
                        description: "The specified 'grant_type' parameter is not valid for this client application.");

                    return;
                }

                // Reject token requests containing a client_secret when the client is a public application.
                if (!string.IsNullOrEmpty(context.ClientSecret))
                {
                    Logger.LogError("The token request was rejected because the public application '{ClientId}' " +
                                    "was not allowed to send a client secret.", context.ClientId);

                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The 'client_secret' parameter is not valid for this client application.");

                    return;
                }

                Logger.LogDebug("The token request validation process was not fully validated because " +
                                "the client '{ClientId}' was a public application.", context.ClientId);

                // If client authentication cannot be enforced, call context.Skip() to inform
                // the OpenID Connect server middleware that the caller cannot be fully trusted.
                context.Skip();

                return;
            }

            // Confidential and hybrid applications MUST authenticate
            // to protect them from impersonation attacks.
            if (string.IsNullOrEmpty(context.ClientSecret))
            {
                Logger.LogError("The token request was rejected because the confidential or hybrid application " +
                                "'{ClientId}' didn't specify a client secret.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The 'client_secret' parameter required for this client application is missing.");

                return;
            }

            if (!await Applications.ValidateClientSecretAsync(application, context.ClientSecret, context.HttpContext.RequestAborted))
            {
                Logger.LogError("The token request was rejected because the confidential or hybrid application " +
                                "'{ClientId}' didn't specify valid client credentials.", context.ClientId);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "The specified client credentials are invalid.");

                return;
            }

            context.Validate();
        }

        public override async Task HandleTokenRequest([NotNull] HandleTokenRequestContext context)
        {
            var options = (OpenIddictOptions) context.Options;

            if (context.Ticket != null)
            {
                // Store the authentication ticket as a request property so it can be later retrieved, if necessary.
                context.Request.SetProperty(OpenIddictConstants.Properties.AuthenticationTicket, context.Ticket);
            }

            if (options.DisableTokenRevocation || (!context.Request.IsAuthorizationCodeGrantType() &&
                                                   !context.Request.IsRefreshTokenGrantType()))
            {
                // Invoke the rest of the pipeline to allow
                // the user code to handle the token request.
                context.SkipHandler();

                return;
            }

            Debug.Assert(context.Ticket != null, "The authentication ticket shouldn't be null.");

            // Extract the token identifier from the authentication ticket.
            var identifier = context.Ticket.GetTokenId();
            Debug.Assert(!string.IsNullOrEmpty(identifier), "The authentication ticket should contain a token identifier.");

            // Retrieve the authorization code/refresh token from the request properties.
            var token = context.Request.GetProperty<TToken>($"{OpenIddictConstants.Properties.Token}:{identifier}");
            Debug.Assert(token != null, "The token shouldn't be null.");

            // If the authorization code/refresh token is already marked as redeemed, this may indicate that
            // it was compromised. In this case, revoke the authorization and all the associated tokens. 
            // See https://tools.ietf.org/html/rfc6749#section-10.5 for more information.
            if (await Tokens.IsRedeemedAsync(token, context.HttpContext.RequestAborted))
            {
                // Try to revoke the authorization and the associated tokens.
                // If the operation fails, the helpers will automatically log
                // and swallow the exception to ensure that a valid error
                // response will be returned to the client application.
                await TryRevokeAuthorizationAsync(context.Ticket, context.HttpContext);
                await TryRevokeTokensAsync(context.Ticket, context.HttpContext);

                Logger.LogError("The token request was rejected because the authorization code " +
                                "or refresh token '{Identifier}' has already been redeemed.", identifier);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: context.Request.IsAuthorizationCodeGrantType() ?
                        "The specified authorization code has already been redeemed." :
                        "The specified refresh token has already been redeemed.");

                return;
            }

            else if (!await Tokens.IsValidAsync(token, context.HttpContext.RequestAborted))
            {
                Logger.LogError("The token request was rejected because the authorization code " +
                                "or refresh token '{Identifier}' was no longer valid.", identifier);

                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidGrant,
                    description: context.Request.IsAuthorizationCodeGrantType() ?
                        "The specified authorization code is no longer valid." :
                        "The specified refresh token is no longer valid.");

                return;
            }

            // Invoke the rest of the pipeline to allow
            // the user code to handle the token request.
            context.SkipHandler();
        }
    }
}
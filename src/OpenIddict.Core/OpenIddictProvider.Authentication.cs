﻿/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNet.Security.OpenIdConnect.Extensions;
using AspNet.Security.OpenIdConnect.Server;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace OpenIddict
{
    public partial class OpenIddictProvider<TUser, TApplication> : OpenIdConnectServerProvider where TUser : class where TApplication : class {
        public override async Task ValidateAuthorizationRequest([NotNull] ValidateAuthorizationRequestContext context) {
            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<OpenIddictProvider<TUser, TApplication>>>();

            // Note: redirect_uri is not required for pure OAuth2 requests
            // but this provider uses a stricter policy making it mandatory,
            // as required by the OpenID Connect core specification.
            // See http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest.
            if (string.IsNullOrEmpty(context.RedirectUri)) {
                logger.LogWarning("The required redirect_uri parameter was missing.");
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "The required redirect_uri parameter was missing.");

                return;
            }

            // Retrieve the application details corresponding to the requested client_id.
            var application = await services.Applications.FindApplicationByIdAsync(context.ClientId);
            if (application == null) {
                logger.LogWarning($"Application not found in the database with client_id '{context.ClientId}'.");
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Application not found in the database: ensure that your client_id is correct.");

                return;
            }

            if (!await services.Applications.ValidateRedirectUriAsync(application, context.RedirectUri)) {
                logger.LogWarning($"Validation for redirect_uri {context.RedirectUri} failed.");
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidClient,
                    description: "Invalid redirect_uri.");

                return;
            }

            // To prevent downgrade attacks, ensure that authorization requests using the hybrid/implicit
            // flow are rejected if the client identifier corresponds to a confidential application.
            // Note: when using the authorization code grant, ValidateClientAuthentication is responsible of
            // rejecting the token request if the client_id corresponds to an unauthenticated confidential client.
            if (await services.Applications.IsConfidentialApplicationAsync(application) && !context.Request.IsAuthorizationCodeFlow()) {
                logger.LogWarning($"Confidential clients cannot use response_type '{context.Request.ResponseType}'.");
                context.Reject(
                    error: OpenIdConnectConstants.Errors.InvalidRequest,
                    description: "Confidential clients can only use response_type=code.");

                return;
            }

            // If the user is connected, ensure that a corresponding profile exists and that
            // the appropriate set of scopes is requested to prevent personal data leakage.
            if (context.HttpContext.User.Identities.Any(identity => identity.IsAuthenticated)) {
                // Ensure the user profile still exists in the database.
                var user = await services.Users.GetUserAsync(context.HttpContext.User);
                if (user == null) {
                    logger.LogWarning("Unable to retrieve the logged user from the store.");
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.ServerError,
                        description: "An internal error has occurred.");

                    return;
                }

                // Return an error if the username corresponds to the registered
                // email address and if the "email" scope has not been requested.
                if (services.Users.SupportsUserEmail && context.Request.HasScope(OpenIdConnectConstants.Scopes.Profile) &&
                                                       !context.Request.HasScope(OpenIdConnectConstants.Scopes.Email)) {
                    // Retrieve the username and the email address associated with the user.
                    var username = await services.Users.GetUserNameAsync(user);
                    var email = await services.Users.GetEmailAsync(user);

                    if (!string.IsNullOrEmpty(email) && string.Equals(username, email, StringComparison.OrdinalIgnoreCase)) {
                        logger.LogWarning("The username correspond to the email address and we carefully avoid leaking the user email if the 'email' scope is not requested.");
                        context.Reject(
                            error: OpenIdConnectConstants.Errors.InvalidRequest,
                            description: "The 'email' scope is required.");

                        return;
                    }
                }
            }

            // Run additional checks for prompt=none requests.
            if (string.Equals(context.Request.Prompt, "none", StringComparison.Ordinal)) {
                // If the user is not authenticated, return an error to the client application.
                // See http://openid.net/specs/openid-connect-core-1_0.html#Authenticates
                if (!context.HttpContext.User.Identities.Any(identity => identity.IsAuthenticated)) {
                    logger.LogWarning("Unable to silently authenticate the user and none already authenticated was found.");
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.LoginRequired,
                        description: "The user must be authenticated.");

                    return;
                }

                // Ensure that the authentication cookie contains the required NameIdentifier claim.
                var identifier = context.HttpContext.User.GetClaim(ClaimTypes.NameIdentifier);
                if (string.IsNullOrEmpty(identifier)) {
                    logger.LogWarning($"The authenticated user is invalid, it doesn't have a claim of type '{ClaimTypes.NameIdentifier}'.");
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.ServerError,
                        description: "The authorization request cannot be processed.");

                    return;
                }

                // Extract the principal contained in the id_token_hint parameter.
                // If no principal can be extracted, an error is returned to the client aplication.
                var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
                if (principal == null) {
                    logger.LogWarning("The required id_token_hint parameter is missing.");
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The required id_token_hint parameter is missing.");

                    return;
                }

                // Ensure the client application is listed as a valid audience in the identity token
                // and that the identity token corresponds to the authenticated user.
                if (!principal.HasClaim(OpenIdConnectConstants.Claims.Audience, context.Request.ClientId) ||
                    !principal.HasClaim(ClaimTypes.NameIdentifier, identifier)) {
                    logger.LogWarning("The id_token_hint parameter is invalid.");
                    context.Reject(
                        error: OpenIdConnectConstants.Errors.InvalidRequest,
                        description: "The id_token_hint parameter is invalid.");

                    return;
                }
            }

            logger.LogInformation("ValidateAuthorizationRequestContext is validated succesfully.");
            context.Validate();
        }

        public override async Task HandleAuthorizationRequest([NotNull] HandleAuthorizationRequestContext context) {
            // Only handle prompt=none requests at this stage.
            if (!string.Equals(context.Request.Prompt, "none", StringComparison.Ordinal)) {
                return;
            }

            var services = context.HttpContext.RequestServices.GetRequiredService<OpenIddictServices<TUser, TApplication>>();

            // Note: principal is guaranteed to be non-null since ValidateAuthorizationRequest
            // rejects prompt=none requests missing or having an invalid id_token_hint.
            var principal = await context.HttpContext.Authentication.AuthenticateAsync(context.Options.AuthenticationScheme);
            Debug.Assert(principal != null);

            // Note: user may be null if the user was removed after
            // the initial check made by ValidateAuthorizationRequest.
            // In this case, ignore the prompt=none request and
            // continue to the next middleware in the pipeline.
            var user = await services.Users.GetUserAsync(principal);
            if (user == null) {
                return;
            }

            // Note: filtering the username is not needed at this stage as OpenIddictController.Accept
            // and OpenIddictProvider.GrantResourceOwnerCredentials are expected to reject requests that
            // don't include the "email" scope if the username corresponds to the registed email address.
            var identity = await services.Applications.CreateIdentityAsync(user, context.Request.GetScopes());
            Debug.Assert(identity != null);

            // Create a new authentication ticket holding the user identity.
            var ticket = new AuthenticationTicket(
                new ClaimsPrincipal(identity),
                new AuthenticationProperties(),
                context.Options.AuthenticationScheme);

            ticket.SetResources(context.Request.GetResources());
            ticket.SetScopes(context.Request.GetScopes());

            // Call SignInAsync to create and return a new OpenID Connect response containing the serialized code/tokens.
            await context.HttpContext.Authentication.SignInAsync(ticket.AuthenticationScheme, ticket.Principal, ticket.Properties);

            // Mark the response as handled
            // to skip the rest of the pipeline.
            context.HandleResponse();
        }
    }
}
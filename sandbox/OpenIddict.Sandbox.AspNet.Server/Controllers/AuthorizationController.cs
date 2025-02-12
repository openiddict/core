/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using OpenIddict.Client.Owin;
using OpenIddict.Sandbox.AspNet.Server.Helpers;
using OpenIddict.Sandbox.AspNet.Server.ViewModels.Authorization;
using OpenIddict.Server.Owin;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.AspNet.Server.Controllers;

public class AuthorizationController : Controller
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly OpenIddictClientService _clientService;
    private readonly IOpenIddictScopeManager _scopeManager;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        OpenIddictClientService clientService,
        IOpenIddictScopeManager scopeManager)
    {
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _clientService = clientService;
        _scopeManager = scopeManager;
    }

    [HttpGet, Route("~/connect/authorize")]
    public async Task<ActionResult> Authorize()
    {
        // Note: the request object contains all the parameters specified in the query string or request form
        // or initially sent to the pushed authorization endpoint for a PAR-enabled authorization flow.
        // As such, the data contained in this object MUST NOT be serialized or returned unprotected to the
        // user agent (e.g as HTML hidden input fields). If only the query string or request form parameters
        // need to be resolved, the Request.QueryString and Request.Form collections must be used instead.
        var context = HttpContext.GetOwinContext();
        var request = context.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie.
        // If a max_age parameter was provided, ensure that the cookie is not too old.
        // If the user principal can't be extracted or the cookie is too old, redirect the user to the login page.
        var result = await context.Authentication.AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie);
        if (result?.Identity == null || (request.MaxAge != null && result.Properties?.IssuedUtc != null &&
            DateTimeOffset.UtcNow - result.Properties.IssuedUtc > TimeSpan.FromSeconds(request.MaxAge.Value)))
        {
            // For applications that want to allow the client to select the external authentication provider
            // that will be used to authenticate the user, the identity_provider parameter can be used for that.
            if (!string.IsNullOrEmpty(request.IdentityProvider))
            {
                var registrations = await _clientService.GetClientRegistrationsAsync();
                if (!registrations.Any(registration => string.Equals(registration.ProviderName,
                    request.IdentityProvider, StringComparison.Ordinal)))
                {
                    context.Authentication.Challenge(
                        authenticationTypes: OpenIddictServerOwinDefaults.AuthenticationType,
                        properties: new AuthenticationProperties(new Dictionary<string, string>
                        {
                            [OpenIddictServerOwinConstants.Properties.Error] = Errors.InvalidRequest,
                            [OpenIddictServerOwinConstants.Properties.ErrorDescription] =
                                "The specified identity provider is not valid."
                        }));

                    return new EmptyResult();
                }

                var properties = new AuthenticationProperties(new Dictionary<string, string>
                {
                    // Note: when only one client is registered in the client options,
                    // specifying the issuer URI or the provider name is not required.
                    [OpenIddictClientOwinConstants.Properties.ProviderName] = request.IdentityProvider
                })
                {
                    // Once the callback is handled, redirect the user agent to the ASP.NET Identity
                    // page responsible for showing the external login confirmation form if necessary.
                    RedirectUri = Url.Action("ExternalLoginCallback", "Account", new
                    {
                        ReturnUrl = Request.RawUrl
                    })
                };

                // Ask the OpenIddict client middleware to redirect the user agent to the identity provider.
                context.Authentication.Challenge(properties, OpenIddictClientOwinDefaults.AuthenticationType);
                return new EmptyResult();
            }

            context.Authentication.Challenge(DefaultAuthenticationTypes.ApplicationCookie);
            return new EmptyResult();
        }

        // Retrieve the profile of the logged in user.
        var user = await context.GetUserManager<ApplicationUserManager>().FindByIdAsync(result.Identity.GetUserId()) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        // Retrieve the application details from the database.
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
            subject: user.Id,
            client : await _applicationManager.GetIdAsync(application),
            status : Statuses.Valid,
            type   : AuthorizationTypes.Permanent,
            scopes : request.GetScopes()).ToListAsync();

        switch (await _applicationManager.GetConsentTypeAsync(application))
        {
            // If the consent is external (e.g when authorizations are granted by a sysadmin),
            // immediately return an error if no authorization can be found in the database.
            case ConsentTypes.External when authorizations.Count is 0:
                context.Authentication.Challenge(
                    authenticationTypes: OpenIddictServerOwinDefaults.AuthenticationType,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerOwinConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerOwinConstants.Properties.ErrorDescription] =
                            "The logged in user is not allowed to access this client application."
                    }));

                return new EmptyResult();

            // If the consent is implicit or if an authorization was found,
            // return an authorization response without displaying the consent form.
            case ConsentTypes.Implicit:
            case ConsentTypes.External when authorizations.Count is not 0:
            case ConsentTypes.Explicit when authorizations.Count is not 0 && !request.HasPromptValue(PromptValues.Consent):
                // Create the claims-based identity that will be used by OpenIddict to generate tokens.
                var identity = new ClaimsIdentity(
                    authenticationType: OpenIddictServerOwinDefaults.AuthenticationType,
                    nameType: Claims.Name,
                    roleType: Claims.Role);

                // Add the claims that will be persisted in the tokens.
                identity.SetClaim(Claims.Subject, user.Id)
                        .SetClaim(Claims.Email, user.Email)
                        .SetClaim(Claims.Name, user.UserName)
                        .SetClaim(Claims.PreferredUsername, user.UserName)
                        .SetClaims(Claims.Role, (await context.Get<ApplicationUserManager>().GetRolesAsync(user.Id)).ToImmutableArray());

                // Note: in this sample, the granted scopes match the requested scope
                // but you may want to allow the user to uncheck specific scopes.
                // For that, simply restrict the list of scopes before calling SetScopes.
                identity.SetScopes(request.GetScopes());
                identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

                // Automatically create a permanent authorization to avoid requiring explicit consent
                // for future authorization or token requests containing the same scopes.
                var authorization = authorizations.LastOrDefault();
                authorization ??= await _authorizationManager.CreateAsync(
                    identity: identity,
                    subject : user.Id,
                    client  : await _applicationManager.GetIdAsync(application),
                    type    : AuthorizationTypes.Permanent,
                    scopes  : identity.GetScopes());

                identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
                identity.SetDestinations(GetDestinations);

                context.Authentication.SignIn(new AuthenticationProperties(), identity);

                return new EmptyResult();

            // At this point, no authorization was found in the database and an error must be returned
            // if the client application specified prompt=none in the authorization request.
            case ConsentTypes.Explicit   when request.HasPromptValue(PromptValues.None):
            case ConsentTypes.Systematic when request.HasPromptValue(PromptValues.None):
                context.Authentication.Challenge(
                    authenticationTypes: OpenIddictServerOwinDefaults.AuthenticationType,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerOwinConstants.Properties.Error] = Errors.ConsentRequired,
                        [OpenIddictServerOwinConstants.Properties.ErrorDescription] =
                            "Interactive user consent is required."
                    }));

                return new EmptyResult();

            // In every other case, render the consent form.
            default: return View(new AuthorizeViewModel
            {
                ApplicationName = await _applicationManager.GetDisplayNameAsync(application),
                Scope = request.Scope,

                // Flow the request parameters so they can be received by the Accept/Reject actions.
                Parameters = string.Equals(Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase) ?
                    from name in Request.Form.AllKeys
                    from value in Request.Form.GetValues(name)
                    select new KeyValuePair<string, string>(name, value) :
                    from name in Request.QueryString.AllKeys
                    from value in Request.QueryString.GetValues(name)
                    select new KeyValuePair<string, string>(name, value)
            });
        }
    }

    [Authorize, FormValueRequired("submit.Accept")]
    [HttpPost, Route("~/connect/authorize"), ValidateAntiForgeryToken]
    public async Task<ActionResult> Accept()
    {
        // Note: the request object contains all the parameters specified in the query string or request form
        // (or initially sent to the pushed authorization endpoint for a PAR-enabled authorization flow).
        // As such, the data contained in this object MUST NOT be serialized or returned unprotected to the
        // user agent (e.g as HTML hidden input fields). If only the query string or request form parameters
        // need to be resolved, the Request.QueryString and Request.Form collections must be used instead.
        var context = HttpContext.GetOwinContext();
        var request = context.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        // Retrieve the user principal stored in the authentication cookie.
        var result = await context.Authentication.AuthenticateAsync(DefaultAuthenticationTypes.ApplicationCookie);
        if (result == null || result.Identity == null)
        {
            context.Authentication.Challenge(DefaultAuthenticationTypes.ApplicationCookie);

            return new EmptyResult();
        }

        // Retrieve the profile of the logged in user.
        var user = await context.GetUserManager<ApplicationUserManager>().FindByIdAsync(result.Identity.GetUserId()) ??
            throw new InvalidOperationException("The user details cannot be retrieved.");

        // Retrieve the application details from the database.
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId) ??
            throw new InvalidOperationException("Details concerning the calling client application cannot be found.");

        // Retrieve the permanent authorizations associated with the user and the calling client application.
        var authorizations = await _authorizationManager.FindAsync(
            subject: user.Id,
            client : await _applicationManager.GetIdAsync(application),
            status : Statuses.Valid,
            type   : AuthorizationTypes.Permanent,
            scopes : request.GetScopes()).ToListAsync();

        // Note: the same check is already made in the other action but is repeated
        // here to ensure a malicious user can't abuse this POST-only endpoint and
        // force it to return a valid response without the external authorization.
        if (authorizations.Count is 0 && await _applicationManager.HasConsentTypeAsync(application, ConsentTypes.External))
        {
            context.Authentication.Challenge(
                authenticationTypes: OpenIddictServerOwinDefaults.AuthenticationType,
                properties: new AuthenticationProperties(new Dictionary<string, string>
                {
                    [OpenIddictServerOwinConstants.Properties.Error] = Errors.ConsentRequired,
                    [OpenIddictServerOwinConstants.Properties.ErrorDescription] =
                        "The logged in user is not allowed to access this client application."
                }));

            return new EmptyResult();
        }

        // Create the claims-based identity that will be used by OpenIddict to generate tokens.
        var identity = new ClaimsIdentity(
            authenticationType: OpenIddictServerOwinDefaults.AuthenticationType,
            nameType: Claims.Name,
            roleType: Claims.Role);

        // Add the claims that will be persisted in the tokens.
        identity.SetClaim(Claims.Subject, user.Id)
                .SetClaim(Claims.Email, user.Email)
                .SetClaim(Claims.Name, user.UserName)
                .SetClaim(Claims.PreferredUsername, user.UserName)
                .SetClaims(Claims.Role, (await context.Get<ApplicationUserManager>().GetRolesAsync(user.Id)).ToImmutableArray());

        // Note: in this sample, the granted scopes match the requested scope
        // but you may want to allow the user to uncheck specific scopes.
        // For that, simply restrict the list of scopes before calling SetScopes.
        identity.SetScopes(request.GetScopes());
        identity.SetResources(await _scopeManager.ListResourcesAsync(identity.GetScopes()).ToListAsync());

        // Automatically create a permanent authorization to avoid requiring explicit consent
        // for future authorization or token requests containing the same scopes.
        var authorization = authorizations.LastOrDefault();
        authorization ??= await _authorizationManager.CreateAsync(
            identity: identity,
            subject : user.Id,
            client  : await _applicationManager.GetIdAsync(application),
            type    : AuthorizationTypes.Permanent,
            scopes  : identity.GetScopes());

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(GetDestinations);

        // Returning a SignInResult will ask OpenIddict to issue the appropriate access/identity tokens.
        context.Authentication.SignIn(new AuthenticationProperties(), identity);

        return new EmptyResult();
    }

    [Authorize, FormValueRequired("submit.Deny")]
    [HttpPost, Route("~/connect/authorize"), ValidateAntiForgeryToken]
    // Notify OpenIddict that the authorization grant has been denied by the resource owner
    // to redirect the user agent to the client application using the appropriate response_mode.
    public ActionResult Deny()
    {
        var context = HttpContext.GetOwinContext();
        context.Authentication.Challenge(OpenIddictServerOwinDefaults.AuthenticationType);

        return new EmptyResult();
    }

    [HttpGet, Route("~/connect/endsession")]
    public ActionResult EndSession() => View(new AuthorizeViewModel
    {
        // Flow the request parameters so they can be received by the Accept/Reject actions.
        Parameters = string.Equals(Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase) ?
            from name in Request.Form.AllKeys
            from value in Request.Form.GetValues(name)
            select new KeyValuePair<string, string>(name, value) :
            from name in Request.QueryString.AllKeys
            from value in Request.QueryString.GetValues(name)
            select new KeyValuePair<string, string>(name, value)
    });

    [ActionName(nameof(EndSession)), HttpPost, Route("~/connect/endsession"), ValidateAntiForgeryToken]
    public ActionResult EndSessionPost()
    {
        var context = HttpContext.GetOwinContext();
        context.Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);

        context.Authentication.SignOut(
            authenticationTypes: OpenIddictServerOwinDefaults.AuthenticationType,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });

        return new EmptyResult();
    }

    [HttpPost, Route("~/connect/token")]
    public async Task<ActionResult> Exchange()
    {
        var context = HttpContext.GetOwinContext();
        var request = context.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        if (request.IsAuthorizationCodeGrantType() || request.IsRefreshTokenGrantType())
        {
            // Retrieve the claims identity stored in the authorization code/device code/refresh token.
            var result = await context.Authentication.AuthenticateAsync(OpenIddictServerOwinDefaults.AuthenticationType);

            // Retrieve the user profile corresponding to the authorization code/refresh token.
            var user = await context.GetUserManager<ApplicationUserManager>().FindByIdAsync(result.Identity.GetClaim(Claims.Subject));
            if (user == null)
            {
                context.Authentication.Challenge(
                    authenticationTypes: OpenIddictServerOwinDefaults.AuthenticationType,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerOwinConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerOwinConstants.Properties.ErrorDescription] = "The token is no longer valid."
                    }));

                return new EmptyResult();
            }

            // Ensure the user is still allowed to sign in.
            if (context.GetUserManager<ApplicationUserManager>().IsLockedOut(user.Id))
            {
                context.Authentication.Challenge(
                    authenticationTypes: OpenIddictServerOwinDefaults.AuthenticationType,
                    properties: new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerOwinConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerOwinConstants.Properties.ErrorDescription] = "The user is no longer allowed to sign in."
                    }));

                return new EmptyResult();
            }

            var identity = new ClaimsIdentity(result.Identity.Claims,
                authenticationType: OpenIddictServerOwinDefaults.AuthenticationType,
                nameType: Claims.Name,
                roleType: Claims.Role);

            // Override the user claims present in the principal in case they
            // changed since the authorization code/refresh token was issued.
            identity.SetClaim(Claims.Subject, user.Id)
                    .SetClaim(Claims.Email, user.Email)
                    .SetClaim(Claims.Name, user.UserName)
                    .SetClaim(Claims.PreferredUsername, user.UserName)
                    .SetClaims(Claims.Role, (await context.Get<ApplicationUserManager>().GetRolesAsync(user.Id)).ToImmutableArray());

            identity.SetDestinations(GetDestinations);

            // Ask OpenIddict to issue the appropriate access/identity tokens.
            context.Authentication.SignIn(new AuthenticationProperties(), identity);

            return new EmptyResult();
        }

        throw new InvalidOperationException("The specified grant type is not supported.");
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            case Claims.Name or Claims.PreferredUsername:
                yield return Destinations.AccessToken;

                if (claim.Subject.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Email:
                yield return Destinations.AccessToken;

                if (claim.Subject.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;

                yield break;

            case Claims.Role:
                yield return Destinations.AccessToken;

                if (claim.Subject.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}

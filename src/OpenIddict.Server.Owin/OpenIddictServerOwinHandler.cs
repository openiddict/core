/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;
using Microsoft.Owin.Security.Infrastructure;
using static OpenIddict.Server.Owin.OpenIddictServerOwinConstants;
using Properties = OpenIddict.Server.Owin.OpenIddictServerOwinConstants.Properties;

namespace OpenIddict.Server.Owin;

/// <summary>
/// Provides the entry point necessary to register the OpenIddict server in an OWIN pipeline.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictServerOwinHandler : AuthenticationHandler<OpenIddictServerOwinOptions>
{
    private readonly IOpenIddictServerDispatcher _dispatcher;
    private readonly IOpenIddictServerFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictServerOwinHandler"/> class.
    /// </summary>
    /// <param name="dispatcher">The OpenIddict server dispatcher used by this instance.</param>
    /// <param name="factory">The OpenIddict server factory used by this instance.</param>
    public OpenIddictServerOwinHandler(
        IOpenIddictServerDispatcher dispatcher,
        IOpenIddictServerFactory factory)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    /// <inheritdoc/>
    protected override async Task InitializeCoreAsync()
    {
        // Note: the transaction may be already attached when replaying an OWIN request
        // (e.g when using a status code pages middleware re-invoking the OWIN pipeline).
        var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName);
        if (transaction is null)
        {
            // Create a new transaction and attach the OWIN request to make it available to the OWIN handlers.
            transaction = await _factory.CreateTransactionAsync();
            transaction.Properties[typeof(IOwinRequest).FullName!] = new WeakReference<IOwinRequest>(Request);

            // Attach the OpenIddict server transaction to the OWIN shared dictionary
            // so that it can retrieved while performing sign-in/sign-out operations.
            Context.Set(typeof(OpenIddictServerTransaction).FullName, transaction);
        }

        var context = new ProcessRequestContext(transaction)
        {
            CancellationToken = Request.CallCancelled
        };

        await _dispatcher.DispatchAsync(context);

        // Store the context in the transaction so that it can be retrieved from InvokeAsync().
        transaction.SetProperty(typeof(ProcessRequestContext).FullName!, context);
    }

    /// <inheritdoc/>
    public override async Task<bool> InvokeAsync()
    {
        // Note: due to internal differences between ASP.NET Core and Katana, the request MUST start being processed
        // in InitializeCoreAsync() to ensure the request context is available from AuthenticateCoreAsync() when
        // active authentication is used, as AuthenticateCoreAsync() is always called before InvokeAsync() in this case.

        var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        var context = transaction.GetProperty<ProcessRequestContext>(typeof(ProcessRequestContext).FullName!) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        if (context.IsRequestHandled)
        {
            return true;
        }

        else if (context.IsRequestSkipped)
        {
            return false;
        }

        else if (context.IsRejected)
        {
            var notification = new ProcessErrorContext(transaction)
            {
                CancellationToken = Request.CallCancelled,
                Error = context.Error ?? Errors.InvalidRequest,
                ErrorDescription = context.ErrorDescription,
                ErrorUri = context.ErrorUri,
                Response = new OpenIddictResponse()
            };

            await _dispatcher.DispatchAsync(notification);

            if (notification.IsRequestHandled)
            {
                return true;
            }

            else if (notification.IsRequestSkipped)
            {
                return false;
            }
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0111));

        }

        return false;
    }

    /// <inheritdoc/>
    protected override async Task<AuthenticationTicket?> AuthenticateCoreAsync()
    {
        var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        // Note: in many cases, the authentication token was already validated by the time this action is called
        // (generally later in the pipeline, when using the pass-through mode). To avoid having to re-validate it,
        // the authentication context is resolved from the transaction. If it's not available, a new one is created.
        var context = transaction.GetProperty<ProcessAuthenticationContext>(typeof(ProcessAuthenticationContext).FullName!);
        if (context is null)
        {
            await _dispatcher.DispatchAsync(context = new ProcessAuthenticationContext(transaction)
            {
                CancellationToken = Request.CallCancelled
            });

            // Store the context object in the transaction so it can be later retrieved by handlers
            // that want to access the authentication result without triggering a new authentication flow.
            transaction.SetProperty(typeof(ProcessAuthenticationContext).FullName!, context);
        }

        if (context.IsRequestHandled || context.IsRequestSkipped)
        {
            return null;
        }

        else if (context.IsRejected)
        {
            // Note: the missing_token error is special-cased to indicate to Katana
            // that no authentication result could be produced due to the lack of token.
            // This also helps reducing the logging noise when no token is specified.
            if (string.Equals(context.Error, Errors.MissingToken, StringComparison.Ordinal))
            {
                return null;
            }

            var properties = CreateAuthenticationProperties();
            properties.Dictionary[Properties.Error] = context.Error;
            properties.Dictionary[Properties.ErrorDescription] = context.ErrorDescription;
            properties.Dictionary[Properties.ErrorUri] = context.ErrorUri;

            return new AuthenticationTicket(new ClaimsIdentity(), properties);
        }

        else
        {
            // A single main claims-based principal instance can be attached to an authentication ticket.
            var principal = context.EndpointType switch
            {
                OpenIddictServerEndpointType.Authorization or OpenIddictServerEndpointType.EndSession
                    => context.IdentityTokenPrincipal,

                OpenIddictServerEndpointType.EndUserVerification => context.UserCodePrincipal,

                OpenIddictServerEndpointType.Introspection or OpenIddictServerEndpointType.Revocation
                    => context.AccessTokenPrincipal       ??
                       context.RefreshTokenPrincipal      ??
                       context.IdentityTokenPrincipal     ??
                       context.AuthorizationCodePrincipal ??
                       context.DeviceCodePrincipal        ??
                       context.UserCodePrincipal,

                OpenIddictServerEndpointType.Token when context.Request.IsAuthorizationCodeGrantType()
                    => context.AuthorizationCodePrincipal,
                OpenIddictServerEndpointType.Token when context.Request.IsDeviceCodeGrantType()
                    => context.DeviceCodePrincipal,
                OpenIddictServerEndpointType.Token when context.Request.IsRefreshTokenGrantType()
                    => context.RefreshTokenPrincipal,

                OpenIddictServerEndpointType.UserInfo => context.AccessTokenPrincipal,

                _ => null
            };

            var properties = CreateAuthenticationProperties(principal);

            return new AuthenticationTicket(principal?.Identity as ClaimsIdentity ?? new ClaimsIdentity(), properties);
        }

        AuthenticationProperties CreateAuthenticationProperties(ClaimsPrincipal? principal = null)
        {
            var properties = new AuthenticationProperties
            {
                ExpiresUtc = principal?.GetExpirationDate(),
                IssuedUtc = principal?.GetCreationDate()
            };

            foreach (var property in context.Properties)
            {
                properties.Dictionary[property.Key] = property.Value;
            }

            // Attach the tokens to allow any OWIN component (e.g a controller)
            // to retrieve them (e.g to make an API request to another application).

            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                properties.Dictionary[Tokens.AccessToken] = context.AccessToken;
            }

            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                properties.Dictionary[Tokens.AuthorizationCode] = context.AuthorizationCode;
            }

            if (!string.IsNullOrEmpty(context.ClientAssertion))
            {
                properties.Dictionary[Tokens.ClientAssertion] = context.ClientAssertion;
            }

            if (!string.IsNullOrEmpty(context.DeviceCode))
            {
                properties.Dictionary[Tokens.DeviceCode] = context.DeviceCode;
            }

            if (!string.IsNullOrEmpty(context.IdentityToken))
            {
                properties.Dictionary[Tokens.IdentityToken] = context.IdentityToken;
            }

            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                properties.Dictionary[Tokens.RefreshToken] = context.RefreshToken;
            }

            if (!string.IsNullOrEmpty(context.UserCode))
            {
                properties.Dictionary[Tokens.UserCode] = context.UserCode;
            }

            return properties;
        }
    }

    /// <inheritdoc/>
    protected override async Task TeardownCoreAsync()
    {
        // Note: OWIN authentication handlers cannot reliably write to the response stream
        // from ApplyResponseGrantAsync() or ApplyResponseChallengeAsync() because these methods
        // are susceptible to be invoked from AuthenticationHandler.OnSendingHeaderCallback(),
        // where calling Write() or WriteAsync() on the response stream may result in a deadlock
        // on hosts using streamed responses. To work around this limitation, this handler
        // doesn't implement ApplyResponseGrantAsync() but TeardownCoreAsync(), which is never
        // called by AuthenticationHandler.OnSendingHeaderCallback(). In theory, this would prevent
        // OpenIddictServerOwinMiddleware from both applying the response grant and allowing
        // the next middleware in the pipeline to alter the response stream but in practice,
        // OpenIddictServerOwinMiddleware is assumed to be the only middleware allowed to write
        // to the response stream when a response grant (sign-in/out or challenge) was applied.

        // Note: unlike the ASP.NET Core host, the OWIN host MUST check whether the status code
        // corresponds to a challenge response, as LookupChallenge() will always return a non-null
        // value when active authentication is used, even if no challenge was actually triggered.
        var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
        if (challenge is not null && Response.StatusCode is 401 or 403)
        {
            var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

            transaction.Properties[typeof(AuthenticationProperties).FullName!] = challenge.Properties ?? new AuthenticationProperties();

            var context = new ProcessChallengeContext(transaction)
            {
                CancellationToken = Request.CallCancelled,
                Response = new OpenIddictResponse()
            };

            await _dispatcher.DispatchAsync(context);

            if (context.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            else if (context.IsRejected)
            {
                var notification = new ProcessErrorContext(transaction)
                {
                    CancellationToken = Request.CallCancelled,
                    Error = context.Error ?? Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri,
                    Response = new OpenIddictResponse()
                };

                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled || context.IsRequestSkipped)
                {
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0111));
            }
        }

        var signin = Helper.LookupSignIn(Options.AuthenticationType);
        if (signin is not null)
        {
            var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

            transaction.Properties[typeof(AuthenticationProperties).FullName!] = signin.Properties ?? new AuthenticationProperties();

            var context = new ProcessSignInContext(transaction)
            {
                CancellationToken = Request.CallCancelled,
                Principal = signin.Principal,
                Response = new OpenIddictResponse()
            };

            await _dispatcher.DispatchAsync(context);

            if (context.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            else if (context.IsRejected)
            {
                var notification = new ProcessErrorContext(transaction)
                {
                    CancellationToken = Request.CallCancelled,
                    Error = context.Error ?? Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri,
                    Response = new OpenIddictResponse()
                };

                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled || context.IsRequestSkipped)
                {
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0111));
            }
        }

        var signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode);
        if (signout is not null)
        {
            var transaction = Context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

            transaction.Properties[typeof(AuthenticationProperties).FullName!] = signout.Properties ?? new AuthenticationProperties();

            var context = new ProcessSignOutContext(transaction)
            {
                CancellationToken = Request.CallCancelled,
                Response = new OpenIddictResponse()
            };

            await _dispatcher.DispatchAsync(context);

            if (context.IsRequestHandled || context.IsRequestSkipped)
            {
                return;
            }

            else if (context.IsRejected)
            {
                var notification = new ProcessErrorContext(transaction)
                {
                    CancellationToken = Request.CallCancelled,
                    Error = context.Error ?? Errors.InvalidRequest,
                    ErrorDescription = context.ErrorDescription,
                    ErrorUri = context.ErrorUri,
                    Response = new OpenIddictResponse()
                };

                await _dispatcher.DispatchAsync(notification);

                if (notification.IsRequestHandled || context.IsRequestSkipped)
                {
                    return;
                }

                throw new InvalidOperationException(SR.GetResourceString(SR.ID0111));
            }
        }
    }
}

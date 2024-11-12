/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using Microsoft.Owin.Security.Infrastructure;
using static OpenIddict.Client.Owin.OpenIddictClientOwinConstants;
using Properties = OpenIddict.Client.Owin.OpenIddictClientOwinConstants.Properties;

namespace OpenIddict.Client.Owin;

/// <summary>
/// Provides the entry point necessary to register the OpenIddict client in an OWIN pipeline.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientOwinHandler : AuthenticationHandler<OpenIddictClientOwinOptions>
{
    private readonly IOpenIddictClientDispatcher _dispatcher;
    private readonly IOpenIddictClientFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientOwinHandler"/> class.
    /// </summary>
    /// <param name="dispatcher">The OpenIddict client dispatcher used by this instance.</param>
    /// <param name="factory">The OpenIddict client factory used by this instance.</param>
    public OpenIddictClientOwinHandler(
        IOpenIddictClientDispatcher dispatcher,
        IOpenIddictClientFactory factory)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }

    /// <inheritdoc/>
    protected override async Task InitializeCoreAsync()
    {
        // Note: the transaction may be already attached when replaying an OWIN request
        // (e.g when using a status code pages middleware re-invoking the OWIN pipeline).
        var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName);
        if (transaction is null)
        {
            // Create a new transaction and attach the OWIN request to make it available to the OWIN handlers.
            transaction = await _factory.CreateTransactionAsync();
            transaction.Properties[typeof(IOwinRequest).FullName!] = new WeakReference<IOwinRequest>(Request);

            // Attach the OpenIddict client transaction to the OWIN shared dictionary
            // so that it can retrieved while performing sign-in/sign-out operations.
            Context.Set(typeof(OpenIddictClientTransaction).FullName, transaction);
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

        var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

        var context = transaction.GetProperty<ProcessRequestContext>(typeof(ProcessRequestContext).FullName!) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

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
        var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName) ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

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
            var properties = CreateAuthenticationProperties();

            return new AuthenticationTicket(context.MergedPrincipal?.Identity as ClaimsIdentity ?? new ClaimsIdentity(), properties);
        }

        AuthenticationProperties CreateAuthenticationProperties()
        {
            var properties = new AuthenticationProperties
            {
                ExpiresUtc = context.StateTokenPrincipal?.GetExpirationDate(),
                IssuedUtc = context.StateTokenPrincipal?.GetCreationDate(),

                // Restore the target link URI that was stored in the state
                // token when the challenge operation started, if available.
                RedirectUri = context.StateTokenPrincipal?.GetClaim(Claims.TargetLinkUri)
            };

            foreach (var property in context.Properties)
            {
                properties.Dictionary[property.Key] = property.Value;
            }

            // Attach the tokens to allow any OWIN component (e.g a controller)
            // to retrieve them (e.g to make an API request to another application).
            //
            // Note: for consistency with the OWIN OpenID Connect middleware, the expiration
            // dates of the backchannel/frontchannel access tokens are also stored as tokens.

            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                properties.Dictionary[Tokens.AuthorizationCode] = context.AuthorizationCode;
            }

            if (!string.IsNullOrEmpty(context.BackchannelAccessToken))
            {
                properties.Dictionary[Tokens.BackchannelAccessToken] = context.BackchannelAccessToken;
            }

            if (context.BackchannelAccessTokenExpirationDate is not null)
            {
                properties.Dictionary[Tokens.BackchannelAccessTokenExpirationDate] =
                    context.BackchannelAccessTokenExpirationDate.Value.ToString("o", CultureInfo.InvariantCulture);
            }

            if (!string.IsNullOrEmpty(context.BackchannelIdentityToken))
            {
                properties.Dictionary[Tokens.BackchannelIdentityToken] = context.BackchannelIdentityToken;
            }

            if (!string.IsNullOrEmpty(context.FrontchannelAccessToken))
            {
                properties.Dictionary[Tokens.FrontchannelAccessToken] = context.FrontchannelAccessToken;
            }

            if (context.FrontchannelAccessTokenExpirationDate is not null)
            {
                properties.Dictionary[Tokens.FrontchannelAccessTokenExpirationDate] =
                    context.FrontchannelAccessTokenExpirationDate.Value.ToString("o", CultureInfo.InvariantCulture);
            }

            if (!string.IsNullOrEmpty(context.FrontchannelIdentityToken))
            {
                properties.Dictionary[Tokens.FrontchannelIdentityToken] = context.FrontchannelIdentityToken;
            }

            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                properties.Dictionary[Tokens.RefreshToken] = context.RefreshToken;
            }

            if (!string.IsNullOrEmpty(context.StateToken))
            {
                properties.Dictionary[Tokens.StateToken] = context.StateToken;
            }

            if (!string.IsNullOrEmpty(context.UserInfoToken))
            {
                properties.Dictionary[Tokens.UserInfoToken] = context.UserInfoToken;
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
        // OpenIddictClientOwinMiddleware from both applying the response grant and allowing
        // the next middleware in the pipeline to alter the response stream but in practice,
        // OpenIddictClientOwinMiddleware is assumed to be the only middleware allowed to write
        // to the response stream when a response grant (sign-in/out or challenge) was applied.

        // Note: unlike the ASP.NET Core host, the OWIN host MUST check whether the status code
        // corresponds to a challenge response, as LookupChallenge() will always return a non-null
        // value when active authentication is used, even if no challenge was actually triggered.
        var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode) ?? LookupForwardedChallenge();
        if (challenge is not null && Response.StatusCode is 401 or 403)
        {
            var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

            transaction.Properties[typeof(AuthenticationProperties).FullName!] = challenge.Properties ?? new AuthenticationProperties();

            var context = new ProcessChallengeContext(transaction)
            {
                CancellationToken = Request.CallCancelled,
                Principal = new ClaimsPrincipal(new ClaimsIdentity()),
                Request = new OpenIddictRequest()
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

        var signout = Helper.LookupSignOut(Options.AuthenticationType, Options.AuthenticationMode) ?? LookupForwardedSignOut();
        if (signout is not null)
        {
            var transaction = Context.Get<OpenIddictClientTransaction>(typeof(OpenIddictClientTransaction).FullName) ??
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

            transaction.Properties[typeof(AuthenticationProperties).FullName!] = signout.Properties ?? new AuthenticationProperties();

            var context = new ProcessSignOutContext(transaction)
            {
                CancellationToken = Request.CallCancelled,
                Principal = new ClaimsPrincipal(new ClaimsIdentity()),
                Request = new OpenIddictRequest()
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

        AuthenticationResponseChallenge? LookupForwardedChallenge()
        {
            // Note: unlike its server counterpart, the OpenIddict OWIN client authentication handler allows
            // associating additional authentication types to trigger a provider-specific challenge. For that,
            // the authentication types attached to the context are iterated: if a type matches one of the types
            // managed by OpenIddict, a challenge pointing to the OpenIddict OWIN client authentication handler
            // is dynamically forwarded with the appropriate provider name authentication property attached.

            if (Context.Authentication.AuthenticationResponseChallenge?.AuthenticationTypes is { Length: > 0 } types)
            {
                foreach (var type in types)
                {
                    if (TryGetForwardedAuthenticationType(type, out _))
                    {
                        // Ensure no client registration information was attached to the authentication properties.
                        if (Context.Authentication.AuthenticationResponseChallenge.Properties is AuthenticationProperties properties &&
                           (properties.Dictionary.ContainsKey(Properties.Issuer) ||
                            properties.Dictionary.ContainsKey(Properties.ProviderName) ||
                            properties.Dictionary.ContainsKey(Properties.RegistrationId)))
                        {
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0417));
                        }

                        return new AuthenticationResponseChallenge(
                            authenticationTypes: [OpenIddictClientOwinDefaults.AuthenticationType],
                            properties         : new AuthenticationProperties(dictionary: new Dictionary<string, string>(
                                Context.Authentication.AuthenticationResponseChallenge.Properties.Dictionary ??
                                ImmutableDictionary.Create<string, string>())
                                {
                                    [Properties.ProviderName] = type
                                }));
                    }
                }
            }

            return null;
        }

        AuthenticationResponseRevoke? LookupForwardedSignOut()
        {
            // Note: unlike its server counterpart, the OpenIddict OWIN client authentication handler allows
            // associating additional authentication types to trigger a provider-specific sign-out. For that,
            // the authentication types attached to the context are iterated: if a type matches one of the types
            // managed by OpenIddict, a sign-out pointing to the OpenIddict OWIN client authentication handler
            // is dynamically forwarded with the appropriate provider name authentication property attached.

            if (Context.Authentication.AuthenticationResponseRevoke?.AuthenticationTypes is { Length: > 0 } types)
            {
                foreach (var type in types)
                {
                    if (TryGetForwardedAuthenticationType(type, out _))
                    {
                        // Ensure no client registration information was attached to the authentication properties.
                        if (Context.Authentication.AuthenticationResponseRevoke.Properties is AuthenticationProperties properties &&
                           (properties.Dictionary.ContainsKey(Properties.Issuer) ||
                            properties.Dictionary.ContainsKey(Properties.ProviderName) ||
                            properties.Dictionary.ContainsKey(Properties.RegistrationId)))
                        {
                            throw new InvalidOperationException(SR.GetResourceString(SR.ID0417));
                        }

                        return new AuthenticationResponseRevoke(
                            authenticationTypes: [OpenIddictClientOwinDefaults.AuthenticationType],
                            properties         : new AuthenticationProperties(dictionary: new Dictionary<string, string>(
                                Context.Authentication.AuthenticationResponseRevoke.Properties.Dictionary ??
                                ImmutableDictionary.Create<string, string>())
                                {
                                    [Properties.ProviderName] = type
                                }));
                    }
                }
            }

            return null;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        bool TryGetForwardedAuthenticationType(string type, [NotNullWhen(true)] out AuthenticationDescription? result)
        {
            foreach (var description in Options.ForwardedAuthenticationTypes)
            {
                if (string.Equals(description.AuthenticationType, type, StringComparison.Ordinal))
                {
                    result = description;
                    return true;
                }
            }

            result = null;
            return false;
        }
    }
}

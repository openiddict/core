/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Globalization;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants;
using Properties = OpenIddict.Client.AspNetCore.OpenIddictClientAspNetCoreConstants.Properties;

namespace OpenIddict.Client.AspNetCore;

/// <summary>
/// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictClientAspNetCoreHandler : AuthenticationHandler<OpenIddictClientAspNetCoreOptions>,
    IAuthenticationRequestHandler,
    IAuthenticationSignOutHandler
{
    private readonly IOpenIddictClientDispatcher _dispatcher;
    private readonly IOpenIddictClientFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictClientAspNetCoreHandler"/> class.
    /// </summary>
#if SUPPORTS_TIME_PROVIDER
    public OpenIddictClientAspNetCoreHandler(
        IOpenIddictClientDispatcher dispatcher,
        IOpenIddictClientFactory factory,
        IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }
#else
    public OpenIddictClientAspNetCoreHandler(
        IOpenIddictClientDispatcher dispatcher,
        IOpenIddictClientFactory factory,
        IOptionsMonitor<OpenIddictClientAspNetCoreOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock)
        : base(options, logger, encoder, clock)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }
#endif

    /// <inheritdoc/>
    public async Task<bool> HandleRequestAsync()
    {
        // Note: the transaction may be already attached when replaying an ASP.NET Core request
        // (e.g when using the built-in status code pages middleware with the re-execute mode).
        var transaction = Context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction;
        if (transaction is null)
        {
            // Create a new transaction and attach the HTTP request to make it available to the ASP.NET Core handlers.
            transaction = await _factory.CreateTransactionAsync();
            transaction.Properties[typeof(HttpRequest).FullName!] = new WeakReference<HttpRequest>(Request);

            // Attach the OpenIddict client transaction to the ASP.NET Core features
            // so that it can retrieved while performing sign-in/sign-out operations.
            Context.Features.Set(new OpenIddictClientAspNetCoreFeature { Transaction = transaction });
        }

        var context = new ProcessRequestContext(transaction)
        {
            CancellationToken = Context.RequestAborted
        };

        await _dispatcher.DispatchAsync(context);

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
                CancellationToken = Context.RequestAborted,
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
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var transaction = Context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

        // Note: in many cases, the authentication token was already validated by the time this action is called
        // (generally later in the pipeline, when using the pass-through mode). To avoid having to re-validate it,
        // the authentication context is resolved from the transaction. If it's not available, a new one is created.
        var context = transaction.GetProperty<ProcessAuthenticationContext>(typeof(ProcessAuthenticationContext).FullName!);
        if (context is null)
        {
            await _dispatcher.DispatchAsync(context = new ProcessAuthenticationContext(transaction)
            {
                CancellationToken = Context.RequestAborted
            });

            // Store the context object in the transaction so it can be later retrieved by handlers
            // that want to access the authentication result without triggering a new authentication flow.
            transaction.SetProperty(typeof(ProcessAuthenticationContext).FullName!, context);
        }

        if (context.IsRequestHandled || context.IsRequestSkipped)
        {
            return AuthenticateResult.NoResult();
        }

        else if (context.IsRejected)
        {
            // Note: the missing_token error is special-cased to indicate to ASP.NET Core
            // that no authentication result could be produced due to the lack of token.
            // This also helps reducing the logging noise when no token is specified.
            if (string.Equals(context.Error, Errors.MissingToken, StringComparison.Ordinal))
            {
                return AuthenticateResult.NoResult();
            }

            var properties = CreateAuthenticationProperties();
            properties.Items[Properties.Error] = context.Error;
            properties.Items[Properties.ErrorDescription] = context.ErrorDescription;
            properties.Items[Properties.ErrorUri] = context.ErrorUri;

            return AuthenticateResult.Fail(SR.GetResourceString(SR.ID0113), properties);
        }

        else
        {
            var properties = CreateAuthenticationProperties();

            return AuthenticateResult.Success(new AuthenticationTicket(
                context.MergedPrincipal ?? new ClaimsPrincipal(new ClaimsIdentity()), properties,
                OpenIddictClientAspNetCoreDefaults.AuthenticationScheme));
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
                properties.Items[property.Key] = property.Value;
            }

            List<AuthenticationToken>? tokens = null;

            // Attach the tokens to allow any ASP.NET Core component (e.g a controller)
            // to retrieve them (e.g to make an API request to another application).
            //
            // Note: for consistency with the ASP.NET Core OpenID Connect handler, the expiration
            // dates of the backchannel/frontchannel access tokens are also stored as tokens.

            if (!string.IsNullOrEmpty(context.AuthorizationCode))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.AuthorizationCode,
                    Value = context.AuthorizationCode
                });
            }

            if (!string.IsNullOrEmpty(context.BackchannelAccessToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.BackchannelAccessToken,
                    Value = context.BackchannelAccessToken
                });
            }

            if (context.BackchannelAccessTokenExpirationDate is not null)
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.BackchannelAccessTokenExpirationDate,
                    Value = context.BackchannelAccessTokenExpirationDate.Value.ToString("o", CultureInfo.InvariantCulture)
                });
            }

            if (!string.IsNullOrEmpty(context.BackchannelIdentityToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.BackchannelIdentityToken,
                    Value = context.BackchannelIdentityToken
                });
            }

            if (!string.IsNullOrEmpty(context.FrontchannelAccessToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.FrontchannelAccessToken,
                    Value = context.FrontchannelAccessToken
                });
            }

            if (context.FrontchannelAccessTokenExpirationDate is not null)
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.FrontchannelAccessTokenExpirationDate,
                    Value = context.FrontchannelAccessTokenExpirationDate.Value.ToString("o", CultureInfo.InvariantCulture)
                });
            }

            if (!string.IsNullOrEmpty(context.FrontchannelIdentityToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.FrontchannelIdentityToken,
                    Value = context.FrontchannelIdentityToken
                });
            }

            if (!string.IsNullOrEmpty(context.RefreshToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.RefreshToken,
                    Value = context.RefreshToken
                });
            }

            if (!string.IsNullOrEmpty(context.StateToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.StateToken,
                    Value = context.StateToken
                });
            }

            if (!string.IsNullOrEmpty(context.UserInfoToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.UserInfoToken,
                    Value = context.UserInfoToken
                });
            }

            if (tokens is { Count: > 0 })
            {
                properties.StoreTokens(tokens);
            }

            if (context.AuthorizationCodePrincipal is not null)
            {
                properties.SetParameter(Properties.AuthorizationCodePrincipal, context.AuthorizationCodePrincipal);
            }

            if (context.BackchannelAccessTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.BackchannelAccessTokenPrincipal, context.BackchannelAccessTokenPrincipal);
            }

            if (context.BackchannelIdentityTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.BackchannelIdentityTokenPrincipal, context.BackchannelIdentityTokenPrincipal);
            }

            if (context.FrontchannelAccessTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.FrontchannelAccessTokenPrincipal, context.FrontchannelAccessTokenPrincipal);
            }

            if (context.FrontchannelIdentityTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.FrontchannelIdentityTokenPrincipal, context.FrontchannelIdentityTokenPrincipal);
            }

            if (context.RefreshTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.RefreshTokenPrincipal, context.RefreshTokenPrincipal);
            }

            if (context.StateTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.StateTokenPrincipal, context.StateTokenPrincipal);
            }

            if (context.UserInfoTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.UserInfoTokenPrincipal, context.UserInfoTokenPrincipal);
            }

            return properties;
        }
    }

    /// <inheritdoc/>
    protected override async Task HandleChallengeAsync(AuthenticationProperties? properties)
    {
        var transaction = Context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0315));

        transaction.Properties[typeof(AuthenticationProperties).FullName!] = properties ?? new AuthenticationProperties();

        var context = new ProcessChallengeContext(transaction)
        {
            CancellationToken = Context.RequestAborted,
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
                CancellationToken = Context.RequestAborted,
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

    /// <inheritdoc/>
    protected override Task HandleForbiddenAsync(AuthenticationProperties? properties)
        => HandleChallengeAsync(properties);

    /// <inheritdoc/>
    public async Task SignOutAsync(AuthenticationProperties? properties)
    {
        var transaction = Context.Features.Get<OpenIddictClientAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0112));

        var context = new ProcessSignOutContext(transaction)
        {
            CancellationToken = Context.RequestAborted,
            Principal = new ClaimsPrincipal(new ClaimsIdentity()),
            Request = new OpenIddictRequest()
        };

        transaction.Properties[typeof(AuthenticationProperties).FullName!] = properties ?? new AuthenticationProperties();

        await _dispatcher.DispatchAsync(context);

        if (context.IsRequestHandled || context.IsRequestSkipped)
        {
            return;
        }

        else if (context.IsRejected)
        {
            var notification = new ProcessErrorContext(transaction)
            {
                CancellationToken = Context.RequestAborted,
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

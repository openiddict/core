/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreConstants;
using Properties = OpenIddict.Validation.AspNetCore.OpenIddictValidationAspNetCoreConstants.Properties;

namespace OpenIddict.Validation.AspNetCore;

/// <summary>
/// Provides the logic necessary to extract, validate and handle OpenID Connect requests.
/// </summary>
[EditorBrowsable(EditorBrowsableState.Advanced)]
public sealed class OpenIddictValidationAspNetCoreHandler : AuthenticationHandler<OpenIddictValidationAspNetCoreOptions>,
    IAuthenticationRequestHandler
{
    private readonly IOpenIddictValidationDispatcher _dispatcher;
    private readonly IOpenIddictValidationFactory _factory;

    /// <summary>
    /// Creates a new instance of the <see cref="OpenIddictValidationAspNetCoreHandler"/> class.
    /// </summary>
#if SUPPORTS_TIME_PROVIDER
    public OpenIddictValidationAspNetCoreHandler(
        IOpenIddictValidationDispatcher dispatcher,
        IOpenIddictValidationFactory factory,
        IOptionsMonitor<OpenIddictValidationAspNetCoreOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder)
        : base(options, logger, encoder)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _factory = factory ?? throw new ArgumentNullException(nameof(factory));
    }
#else
    public OpenIddictValidationAspNetCoreHandler(
        IOpenIddictValidationDispatcher dispatcher,
        IOpenIddictValidationFactory factory,
        IOptionsMonitor<OpenIddictValidationAspNetCoreOptions> options,
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
        var transaction = Context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction;
        if (transaction is null)
        {
            // Create a new transaction and attach the HTTP request to make it available to the ASP.NET Core handlers.
            transaction = await _factory.CreateTransactionAsync();
            transaction.Properties[typeof(HttpRequest).FullName!] = new WeakReference<HttpRequest>(Request);

            // Attach the OpenIddict validation transaction to the ASP.NET Core features
            // so that it can retrieved while performing challenge/forbid operations.
            Context.Features.Set(new OpenIddictValidationAspNetCoreFeature { Transaction = transaction });
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
        var transaction = Context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0166));

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
            // A single main claims-based principal instance can be attached to an authentication ticket.
            // To return the most appropriate one, the principal is selected based on the endpoint type.
            // Independently of the selected main principal, all principals resolved from validated tokens
            // are attached to the authentication properties bag so they can be accessed from user code.
            var principal = context.EndpointType switch
            {
                OpenIddictValidationEndpointType.Unknown => context.AccessTokenPrincipal,

                _ => null
            };

            var properties = CreateAuthenticationProperties(principal);

            return AuthenticateResult.Success(new AuthenticationTicket(
                principal ?? new ClaimsPrincipal(new ClaimsIdentity()), properties,
                OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme));
        }

        AuthenticationProperties CreateAuthenticationProperties(ClaimsPrincipal? principal = null)
        {
            var properties = new AuthenticationProperties
            {
                ExpiresUtc = principal?.GetExpirationDate(),
                IssuedUtc = principal?.GetCreationDate()
            };

            List<AuthenticationToken>? tokens = null;

            // Attach the tokens to allow any ASP.NET Core component (e.g a controller)
            // to retrieve them (e.g to make an API request to another application).

            if (!string.IsNullOrEmpty(context.AccessToken))
            {
                tokens ??= new(capacity: 1);
                tokens.Add(new AuthenticationToken
                {
                    Name = Tokens.AccessToken,
                    Value = context.AccessToken
                });
            }

            if (context.AccessTokenPrincipal is not null)
            {
                properties.SetParameter(Properties.AccessTokenPrincipal, context.AccessTokenPrincipal);
            }

            if (tokens is { Count: > 0 })
            {
                properties.StoreTokens(tokens);
            }

            return properties;
        }
    }

    /// <inheritdoc/>
    protected override async Task HandleChallengeAsync(AuthenticationProperties? properties)
    {
        var transaction = Context.Features.Get<OpenIddictValidationAspNetCoreFeature>()?.Transaction ??
            throw new InvalidOperationException(SR.GetResourceString(SR.ID0166));

        transaction.Properties[typeof(AuthenticationProperties).FullName!] = properties ?? new AuthenticationProperties();

        var context = new ProcessChallengeContext(transaction)
        {
            CancellationToken = Context.RequestAborted,
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
}

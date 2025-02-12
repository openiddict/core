/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Client;

public static partial class OpenIddictClientEvents
{
    /// <summary>
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class BaseContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseContext"/> class.
        /// </summary>
        protected BaseContext(OpenIddictClientTransaction transaction)
            => Transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));

        /// <summary>
        /// Gets the environment associated with the current request being processed.
        /// </summary>
        public OpenIddictClientTransaction Transaction { get; }

        /// <summary>
        /// Gets or sets the cancellation token that will be
        /// used to determine if the operation was aborted.
        /// </summary>
        /// <remarks>
        /// Note: for security reasons, this property shouldn't be used by event
        /// handlers to abort security-sensitive operations. As such, it is
        /// recommended to use this property only for user-dependent operations.
        /// </remarks>
        public CancellationToken CancellationToken
        {
            get => Transaction.CancellationToken;
            set => Transaction.CancellationToken = value;
        }

        /// <summary>
        /// Gets or sets the endpoint type that handled the request, if applicable.
        /// </summary>
        public OpenIddictClientEndpointType EndpointType
        {
            get => Transaction.EndpointType;
            set => Transaction.EndpointType = value;
        }

        /// <summary>
        /// Gets or sets the request <see cref="Uri"/> of the current transaction, if available.
        /// </summary>
        public Uri? RequestUri
        {
            get => Transaction.RequestUri;
            set => Transaction.RequestUri = value;
        }

        /// <summary>
        /// Gets or sets the base <see cref="Uri"/> of the host, if available.
        /// </summary>
        public Uri? BaseUri
        {
            get => Transaction.BaseUri;
            set => Transaction.BaseUri = value;
        }

        /// <summary>
        /// Gets the logger responsible for logging processed operations.
        /// </summary>
        public ILogger Logger => Transaction.Logger;

        /// <summary>
        /// Gets the OpenIddict client options.
        /// </summary>
        public OpenIddictClientOptions Options => Transaction.Options;

        /// <summary>
        /// Gets or sets the server configuration used for the current request.
        /// </summary>
        public OpenIddictConfiguration Configuration
        {
            get => Transaction.Configuration;
            set => Transaction.Configuration = value;
        }

        /// <summary>
        /// Gets or sets the client registration used for the current request.
        /// </summary>
        public OpenIddictClientRegistration Registration
        {
            get => Transaction.Registration;
            set => Transaction.Registration = value;
        }
    }

    /// <summary>
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class BaseRequestContext : BaseContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseRequestContext"/> class.
        /// </summary>
        protected BaseRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets a boolean indicating whether the request was fully handled.
        /// </summary>
        public bool IsRequestHandled { get; private set; }

        /// <summary>
        /// Gets a boolean indicating whether the request processing was skipped.
        /// </summary>
        public bool IsRequestSkipped { get; private set; }

        /// <summary>
        /// Marks the request as fully handled. Once declared handled,
        /// a request shouldn't be processed further by the underlying host.
        /// </summary>
        public void HandleRequest() => IsRequestHandled = true;

        /// <summary>
        /// Marks the request as skipped. Once declared skipped, a request
        /// shouldn't be processed further by OpenIddict but should be allowed
        /// to go through the next components in the processing pipeline
        /// (if this pattern is supported by the underlying host).
        /// </summary>
        public void SkipRequest() => IsRequestSkipped = true;
    }

    /// <summary>
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class BaseExternalContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseRequestContext"/> class.
        /// </summary>
        protected BaseExternalContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the URI of the external endpoint to communicate with.
        /// </summary>
        public Uri? RemoteUri { get; set; }

        /// <summary>
        /// Gets or sets the client authentication method used
        /// when communicating with the external endpoint, if applicable.
        /// </summary>
        public string? ClientAuthenticationMethod { get; set; }

        /// <summary>
        /// Gets or sets the token binding method used when communicating with the external endpoint, if applicable.
        /// </summary>
        public HashSet<string> TokenBindingMethods { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class BaseValidatingContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseValidatingContext"/> class.
        /// </summary>
        protected BaseValidatingContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets a boolean indicating whether the request will be rejected.
        /// </summary>
        public bool IsRejected { get; protected set; }

        /// <summary>
        /// Gets or sets the "error" parameter returned to the client application.
        /// </summary>
        public string? Error { get; private set; }

        /// <summary>
        /// Gets or sets the "error_description" parameter returned to the client application.
        /// </summary>
        public string? ErrorDescription { get; private set; }

        /// <summary>
        /// Gets or sets the "error_uri" parameter returned to the client application.
        /// </summary>
        public string? ErrorUri { get; private set; }

        /// <summary>
        /// Rejects the request.
        /// </summary>
        /// <param name="error">The "error" parameter returned to the client application.</param>
        /// <param name="description">The "error_description" parameter returned to the client application.</param>
        /// <param name="uri">The "error_uri" parameter returned to the client application.</param>
        public virtual void Reject(string? error = null, string? description = null, string? uri = null)
        {
            Error = error;
            ErrorDescription = description;
            ErrorUri = uri;

            IsRejected = true;
        }
    }

    /// <summary>
    /// Represents an abstract base class used for certain event contexts.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class BaseValidatingTicketContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseValidatingTicketContext"/> class.
        /// </summary>
        protected BaseValidatingTicketContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the security principal.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing an incoming request.
    /// </summary>
    public sealed class ProcessRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessRequestContext"/> class.
        /// </summary>
        public ProcessRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }
    }

    /// <summary>
    /// Represents an event called when processing an errored response.
    /// </summary>
    public sealed class ProcessErrorContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessErrorContext"/> class.
        /// </summary>
        public ProcessErrorContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it couldn't be extracted.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }

        /// <summary>
        /// Gets or sets the error returned to the caller.
        /// </summary>
        public string? Error { get; set; }

        /// <summary>
        /// Gets or sets the error description returned to the caller.
        /// </summary>
        public string? ErrorDescription { get; set; }

        /// <summary>
        /// Gets or sets the error URI returned to the caller.
        /// </summary>
        public string? ErrorUri { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// Represents an event called when processing an authentication operation.
    /// </summary>
    public sealed class ProcessAuthenticationContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessAuthenticationContext"/> class.
        /// </summary>
        public ProcessAuthenticationContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets the user-defined authentication properties, if available.
        /// </summary>
        public Dictionary<string, string?> Properties { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the nonce used to identify the authentication demand, if applicable.
        /// </summary>
        public string? Nonce { get; set; }

        /// <summary>
        /// Gets or sets the identifier that will be used to resolve the client registration, if applicable.
        /// </summary>
        public string? RegistrationId { get; set; }

        /// <summary>
        /// Gets or sets the issuer URI of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public Uri? Issuer { get; set; }

        /// <summary>
        /// Gets or sets the name of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public string? ProviderName { get; set; }

        /// <summary>
        /// Gets or sets the grant type used for the authentication demand, if applicable.
        /// </summary>
        public string? GrantType { get; set; }

        /// <summary>
        /// Gets or sets the response type used for the authentication demand, if applicable.
        /// </summary>
        public string? ResponseType { get; set; }

        /// <summary>
        /// Gets or sets the request forgery protection resolved from the user session, if applicable.
        /// </summary>
        public string? RequestForgeryProtection { get; set; }

        /// <summary>
        /// Gets the scopes that will be sent to the authorization server, if applicable.
        /// </summary>
        public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the URI of the token endpoint, if applicable.
        /// </summary>
        public Uri? TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the client authentication method used
        /// when communicating with the token endpoint, if applicable.
        /// </summary>
        public string? TokenEndpointClientAuthenticationMethod { get; set; }

        /// <summary>
        /// Gets or sets the URI of the userinfo endpoint, if applicable.
        /// </summary>
        public Uri? UserInfoEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the token binding methods used when
        /// communicating with the userinfo endpoint, if applicable.
        /// </summary>
        public HashSet<string> UserInfoEndpointTokenBindingMethods { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets a boolean indicating whether a token request should be sent.
        /// </summary>
        public bool SendTokenRequest { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a token request should be sent.
        /// </summary>
        public bool SendUserInfoRequest { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an authorization
        /// code should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a backchannel
        /// access token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractBackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a backchannel
        /// identity token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractBackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a frontchannel
        /// access token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractFrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a frontchannel
        /// identity token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractFrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a refresh
        /// token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a state
        /// token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a userinfo
        /// token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractUserInfoToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an authorization
        /// code must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a backchannel access
        /// token must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireBackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a backchannel identity
        /// token must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireBackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a frontchannel identity
        /// token must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireFrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a frontchannel identity
        /// token must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireFrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a refresh token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a state token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a userinfo token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireUserInfoToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the authorization
        /// code extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the backchannel access
        /// token extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateBackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the backchannel identity
        /// token extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateBackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the frontchannel access
        /// token extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateFrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the frontchannel identity
        /// token extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateFrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the refresh token
        /// extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the state token
        /// extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the userinfo token
        /// extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateUserInfoToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid authorization code
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid backchannel access token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectBackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid backchannel identity token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectBackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid frontchannel access token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectFrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid frontchannel identity token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectFrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid refresh token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid state token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid userinfo token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectUserInfoToken { get; set; }

        /// <summary>
        /// Gets or sets the authorization code to validate, if applicable.
        /// </summary>
        public string? AuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets the backchannel access token to validate, if applicable.
        /// </summary>
        public string? BackchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets the expiration date of the backchannel access token, if applicable.
        /// </summary>
        public DateTimeOffset? BackchannelAccessTokenExpirationDate { get; set; }

        /// <summary>
        /// Gets or sets the backchannel identity token to validate, if applicable.
        /// </summary>
        public string? BackchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets the device code to validate, if applicable.
        /// </summary>
        public string? DeviceCode { get; set; }

        /// <summary>
        /// Gets or sets the frontchannel access token to validate, if applicable.
        /// </summary>
        public string? FrontchannelAccessToken { get; set; }

        /// <summary>
        /// Gets or sets the expiration date of the frontchannel access token, if applicable.
        /// </summary>
        public DateTimeOffset? FrontchannelAccessTokenExpirationDate { get; set; }

        /// <summary>
        /// Gets or sets the frontchannel identity token to validate, if applicable.
        /// </summary>
        public string? FrontchannelIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets the refresh token to validate, if applicable.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the username to send to the server, if applicable.
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// Gets or sets the password to send to the server, if applicable.
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// Gets or sets the frontchannel state token to validate, if applicable.
        /// </summary>
        public string? StateToken { get; set; }

        /// <summary>
        /// Gets or sets the userinfo token to validate, if applicable.
        /// </summary>
        public string? UserInfoToken { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the authorization code, if applicable.
        /// </summary>
        public ClaimsPrincipal? AuthorizationCodePrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the backchannel access token, if applicable.
        /// </summary>
        public ClaimsPrincipal? BackchannelAccessTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the backchannel identity token, if applicable.
        /// </summary>
        public ClaimsPrincipal? BackchannelIdentityTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the frontchannel access token, if applicable.
        /// </summary>
        public ClaimsPrincipal? FrontchannelAccessTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the frontchannel identity token, if applicable.
        /// </summary>
        public ClaimsPrincipal? FrontchannelIdentityTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the merged principal containing the claims of the other principals.
        /// </summary>
        public ClaimsPrincipal MergedPrincipal { get; set; } = new ClaimsPrincipal(new ClaimsIdentity());

        /// <summary>
        /// Gets or sets the principal extracted from the refresh token, if applicable.
        /// </summary>
        public ClaimsPrincipal? RefreshTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the state token, if applicable.
        /// </summary>
        public ClaimsPrincipal? StateTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the userinfo token, if applicable.
        /// </summary>
        public ClaimsPrincipal? UserInfoTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the request sent to the token endpoint, if applicable.
        /// </summary>
        public OpenIddictRequest? TokenRequest { get; set; }

        /// <summary>
        /// Gets or sets the response returned by the token endpoint, if applicable.
        /// </summary>
        public OpenIddictResponse? TokenResponse { get; set; }

        /// <summary>
        /// Gets or sets the request sent to the userinfo endpoint, if applicable.
        /// </summary>
        public OpenIddictRequest? UserInfoRequest { get; set; }

        /// <summary>
        /// Gets or sets the response returned by the userinfo endpoint, if applicable.
        /// </summary>
        public OpenIddictResponse? UserInfoResponse { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a client assertion
        /// token should be generated (and optionally included in the request).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated client
        /// assertion should be included as part of the request.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets the generated client assertion, if applicable.
        /// The client assertion will only be returned if
        /// <see cref="IncludeClientAssertion"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets type of the generated client assertion, if applicable.
        /// The client assertion type will only be returned if
        /// <see cref="IncludeClientAssertion"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertionType { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that will be
        /// used to create the client assertion, if applicable.
        /// </summary>
        public ClaimsPrincipal? ClientAssertionPrincipal { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether backchannel
        /// identity token nonce validation should be disabled.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool DisableBackchannelIdentityTokenNonceValidation { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether frontchannel
        /// identity token nonce validation should be disabled.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool DisableFrontchannelIdentityTokenNonceValidation { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether userinfo retrieval should be disabled.
        /// </summary>
        public bool DisableUserInfoRetrieval { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether userinfo validation should be disabled.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool DisableUserInfoValidation { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing a challenge operation.
    /// </summary>
    public sealed class ProcessChallengeContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessChallengeContext"/> class.
        /// </summary>
        public ProcessChallengeContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }

        /// <summary>
        /// Gets the user-defined authentication properties, if available.
        /// </summary>
        public Dictionary<string, string?> Properties { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the identifier that will be used to resolve the client registration, if applicable.
        /// </summary>
        public string? RegistrationId { get; set; }

        /// <summary>
        /// Gets or sets the issuer URI of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public Uri? Issuer { get; set; }

        /// <summary>
        /// Gets or sets the name of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public string? ProviderName { get; set; }

        /// <summary>
        /// Gets or sets the URI of the authorization endpoint, if applicable.
        /// </summary>
        public Uri? AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the client identifier that will be used for the challenge demand.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the grant type that will be used for the challenge demand.
        /// </summary>
        public string? GrantType { get; set; }

        /// <summary>
        /// Gets or sets the response mode that will be
        /// used for the challenge demand, if applicable.
        /// </summary>
        public string? ResponseMode { get; set; }

        /// <summary>
        /// Gets or sets the response type that will be
        /// used for the challenge demand, if applicable.
        /// </summary>
        public string? ResponseType { get; set; }

        /// <summary>
        /// Gets or sets the redirection endpoint that will
        /// be used for the challenge demand, if applicable.
        /// </summary>
        [StringSyntax(StringSyntaxAttribute.Uri)]
        public string? RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the code challenge that will
        /// be used for the challenge demand, if applicable.
        /// </summary>
        public string? CodeChallenge { get; set; }

        /// <summary>
        /// Gets or sets the code challenge method that will
        /// be used for the challenge demand, if applicable.
        /// </summary>
        public string? CodeChallengeMethod { get; set; }

        /// <summary>
        /// Gets or sets the code verifier that will be stored in the state token, if applicable.
        /// </summary>
        public string? CodeVerifier { get; set; }

        /// <summary>
        /// Gets or sets the nonce that will be used for the challenge demand, if applicable.
        /// Note: this value MUST NOT be user-defined or extracted from any request and MUST be random
        /// (generated by a random number generator suitable for cryptographic operations).
        /// </summary>
        public string? Nonce { get; set; }

        /// <summary>
        /// Gets or sets the request forgery protection that will be stored in the state token, if applicable.
        /// Note: this value MUST NOT be user-defined or extracted from any request and MUST be random
        /// (generated by a random number generator suitable for cryptographic operations).
        /// </summary>
        public string? RequestForgeryProtection { get; set; }

        /// <summary>
        /// Gets or sets the optional target link URI that will be stored in the state token, if applicable.
        /// </summary>
        [StringSyntax(StringSyntaxAttribute.Uri)]
        public string? TargetLinkUri { get; set; }

        /// <summary>
        /// Gets or sets the optional identity token hint that will
        /// be sent to the authorization server, if applicable.
        /// </summary>
        public string? IdentityTokenHint { get; set; }

        /// <summary>
        /// Gets or sets the optional login hint that will be sent to the authorization server, if applicable.
        /// </summary>
        public string? LoginHint { get; set; }

        /// <summary>
        /// Gets the set of scopes that will be requested to the authorization server.
        /// </summary>
        public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the URI of the device authorization endpoint, if applicable.
        /// </summary>
        public Uri? DeviceAuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the client authentication method used when
        /// communicating with the device authorization endpoint, if applicable.
        /// </summary>
        public string? DeviceAuthorizationEndpointClientAuthenticationMethod { get; set; }

        /// <summary>
        /// Gets or sets the URI of the pushed authorization endpoint, if applicable.
        /// </summary>
        public Uri? PushedAuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the client authentication method used when communicating
        /// with the pushed authorization endpoint, if applicable.
        /// </summary>
        public string? PushedAuthorizationEndpointClientAuthenticationMethod { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a state token
        /// should be generated (and optionally included in the request).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated
        /// state token should be included as part of the request.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeStateToken { get; set; }

        /// <summary>
        /// Gets or sets the generated state token, if applicable.
        /// The state token will only be returned if
        /// <see cref="IncludeStateToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? StateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a device authorization request should be sent.
        /// </summary>
        public bool SendDeviceAuthorizationRequest { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a pushed authorization request should be sent.
        /// </summary>
        public bool SendPushedAuthorizationRequest { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a client assertion
        /// token should be generated (and optionally included in the request).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated client
        /// assertion should be included as part of the request.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets the generated client assertion, if applicable.
        /// The client assertion will only be returned if
        /// <see cref="IncludeClientAssertion"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets type of the generated client assertion, if applicable.
        /// The client assertion type will only be returned if
        /// <see cref="IncludeClientAssertion"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertionType { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that will be
        /// used to create the client assertion, if applicable.
        /// </summary>
        public ClaimsPrincipal? ClientAssertionPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the state token, if applicable.
        /// </summary>
        public ClaimsPrincipal? StateTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the request sent to the device authorization endpoint, if applicable.
        /// </summary>
        public OpenIddictRequest? DeviceAuthorizationRequest { get; set; }

        /// <summary>
        /// Gets or sets the response returned by the device authorization endpoint, if applicable.
        /// </summary>
        public OpenIddictResponse? DeviceAuthorizationResponse { get; set; }

        /// <summary>
        /// Gets or sets the request sent to the pushed authorization endpoint, if applicable.
        /// </summary>
        public OpenIddictRequest? PushedAuthorizationRequest { get; set; }

        /// <summary>
        /// Gets or sets the response returned by the pushed authorization endpoint, if applicable.
        /// </summary>
        public OpenIddictResponse? PushedAuthorizationResponse { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a device
        /// code should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a request token
        /// should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a user
        /// code should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractUserCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a device code must
        /// be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a request token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a user code must
        /// be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireUserCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the device code
        /// extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the request token
        /// extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the user code
        /// extracted from the current context should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateUserCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid device code will
        /// cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid request token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid user code will
        /// cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectUserCode { get; set; }

        /// <summary>
        /// Gets or sets the device code to validate, if applicable.
        /// </summary>
        public string? DeviceCode { get; set; }

        /// <summary>
        /// Gets or sets the request token to validate, if applicable.
        /// </summary>
        public string? RequestToken { get; set; }

        /// <summary>
        /// Gets or sets the user code to validate, if applicable.
        /// </summary>
        public string? UserCode { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing an introspection operation.
    /// </summary>
    public sealed class ProcessIntrospectionContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessIntrospectionContext"/> class.
        /// </summary>
        public ProcessIntrospectionContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }

        /// <summary>
        /// Gets or sets the token to introspect.
        /// </summary>
        public string? Token { get; set; }

        /// <summary>
        /// Gets or sets the token type of the token to introspect, used as a hint by the remote server.
        /// </summary>
        public string? TokenTypeHint { get; set; }

        /// <summary>
        /// Gets the user-defined authentication properties, if available.
        /// </summary>
        public Dictionary<string, string?> Properties { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the identifier that will be used to resolve the client registration, if applicable.
        /// </summary>
        public string? RegistrationId { get; set; }

        /// <summary>
        /// Gets or sets the issuer URI of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public Uri? Issuer { get; set; }

        /// <summary>
        /// Gets or sets the name of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public string? ProviderName { get; set; }

        /// <summary>
        /// Gets or sets the URI of the introspection endpoint, if applicable.
        /// </summary>
        public Uri? IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the client authentication method used when
        /// communicating with the introspection endpoint, if applicable.
        /// </summary>
        public string? IntrospectionEndpointClientAuthenticationMethod { get; set; }

        /// <summary>
        /// Gets or sets the client identifier that will be used for the introspection demand.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an introspection request should be sent.
        /// </summary>
        public bool SendIntrospectionRequest { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a client assertion
        /// token should be generated (and optionally included in the request).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated client
        /// assertion should be included as part of the request.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets the generated client assertion, if applicable.
        /// The client assertion will only be returned if
        /// <see cref="IncludeClientAssertion"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets type of the generated client assertion, if applicable.
        /// The client assertion type will only be returned if
        /// <see cref="IncludeClientAssertion"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertionType { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that will be
        /// used to create the client assertion, if applicable.
        /// </summary>
        public ClaimsPrincipal? ClientAssertionPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the request sent to the introspection endpoint, if applicable.
        /// </summary>
        public OpenIddictRequest? IntrospectionRequest { get; set; }

        /// <summary>
        /// Gets or sets the response returned by the introspection endpoint, if applicable.
        /// </summary>
        public OpenIddictResponse? IntrospectionResponse { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing an revocation operation.
    /// </summary>
    public sealed class ProcessRevocationContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessRevocationContext"/> class.
        /// </summary>
        public ProcessRevocationContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }

        /// <summary>
        /// Gets or sets the token to introspect.
        /// </summary>
        public string? Token { get; set; }

        /// <summary>
        /// Gets or sets the token type of the token to introspect, used as a hint by the remote server.
        /// </summary>
        public string? TokenTypeHint { get; set; }

        /// <summary>
        /// Gets the user-defined authentication properties, if available.
        /// </summary>
        public Dictionary<string, string?> Properties { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the identifier that will be used to resolve the client registration, if applicable.
        /// </summary>
        public string? RegistrationId { get; set; }

        /// <summary>
        /// Gets or sets the issuer URI of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public Uri? Issuer { get; set; }

        /// <summary>
        /// Gets or sets the name of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public string? ProviderName { get; set; }

        /// <summary>
        /// Gets or sets the URI of the revocation endpoint, if applicable.
        /// </summary>
        public Uri? RevocationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the client authentication method used when
        /// communicating with the revocation endpoint, if applicable.
        /// </summary>
        public string? RevocationEndpointClientAuthenticationMethod { get; set; }

        /// <summary>
        /// Gets or sets the client identifier that will be used for the revocation demand.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an revocation request should be sent.
        /// </summary>
        public bool SendRevocationRequest { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a client assertion
        /// token should be generated (and optionally included in the request).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated client
        /// assertion should be included as part of the request.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets the generated client assertion, if applicable.
        /// The client assertion will only be returned if
        /// <see cref="IncludeClientAssertion"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets type of the generated client assertion, if applicable.
        /// The client assertion type will only be returned if
        /// <see cref="IncludeClientAssertion"/> is set to <see langword="true"/>.
        /// </summary>
        public string? ClientAssertionType { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that will be
        /// used to create the client assertion, if applicable.
        /// </summary>
        public ClaimsPrincipal? ClientAssertionPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the request sent to the revocation endpoint, if applicable.
        /// </summary>
        public OpenIddictRequest? RevocationRequest { get; set; }

        /// <summary>
        /// Gets or sets the response returned by the revocation endpoint, if applicable.
        /// </summary>
        public OpenIddictResponse? RevocationResponse { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing a sign-out response.
    /// </summary>
    public sealed class ProcessSignOutContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessSignOutContext"/> class.
        /// </summary>
        public ProcessSignOutContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets or sets the response.
        /// </summary>
        public OpenIddictResponse Response
        {
            get => Transaction.Response!;
            set => Transaction.Response = value;
        }

        /// <summary>
        /// Gets the user-defined authentication properties, if available.
        /// </summary>
        public Dictionary<string, string?> Properties { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the identifier that will be used to resolve the client registration, if applicable.
        /// </summary>
        public string? RegistrationId { get; set; }

        /// <summary>
        /// Gets or sets the issuer URI of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public Uri? Issuer { get; set; }

        /// <summary>
        /// Gets or sets the name of the provider that will be
        /// used to resolve the client registration, if applicable.
        /// </summary>
        public string? ProviderName { get; set; }

        /// <summary>
        /// Gets or sets the URI of the end session endpoint, if applicable.
        /// </summary>
        public Uri? EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the client identifier that will be used for the sign-out demand.
        /// </summary>
        public string? ClientId { get; set; }

        /// <summary>
        /// Gets or sets the post-logout redirection endpoint that
        /// will be used for the sign-out demand, if applicable.
        /// </summary>
        [StringSyntax(StringSyntaxAttribute.Uri)]
        public string? PostLogoutRedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the optional identity token hint that will
        /// be sent to the authorization server, if applicable.
        /// </summary>
        public string? IdentityTokenHint { get; set; }

        /// <summary>
        /// Gets or sets the optional login hint that will be sent to the authorization server, if applicable.
        /// </summary>
        public string? LoginHint { get; set; }

        /// <summary>
        /// Gets or sets the optional target link URI that will be stored in the state token, if applicable.
        /// </summary>
        public string? TargetLinkUri { get; set; }

        /// <summary>
        /// Gets or sets the nonce that will be used for the sign-out demand, if applicable.
        /// Note: this value MUST NOT be user-defined or extracted from any request and MUST be random
        /// (generated by a random number generator suitable for cryptographic operations).
        /// </summary>
        public string? Nonce { get; set; }

        /// <summary>
        /// Gets or sets the request forgery protection that will be stored in the state token, if applicable.
        /// Note: this value MUST NOT be user-defined or extracted from any request and MUST be random
        /// (generated by a random number generator suitable for cryptographic operations).
        /// </summary>
        public string? RequestForgeryProtection { get; set; }

        /// <summary>
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets a boolean indicating whether a state token
        /// should be generated (and optionally included in the request).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateStateToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated
        /// state token should be included as part of the request.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeStateToken { get; set; }

        /// <summary>
        /// Gets or sets the generated state token, if applicable.
        /// The state token will only be returned if
        /// <see cref="IncludeStateToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? StateToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the state token, if applicable.
        /// </summary>
        public ClaimsPrincipal? StateTokenPrincipal { get; set; }
    }
}

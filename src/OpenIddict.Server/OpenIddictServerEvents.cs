/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.ComponentModel;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace OpenIddict.Server;

public static partial class OpenIddictServerEvents
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
        protected BaseContext(OpenIddictServerTransaction transaction)
            => Transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));

        /// <summary>
        /// Gets the environment associated with the current request being processed.
        /// </summary>
        public OpenIddictServerTransaction Transaction { get; }

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
        public OpenIddictServerEndpointType EndpointType
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
        /// Gets the OpenIddict server options.
        /// </summary>
        public OpenIddictServerOptions Options => Transaction.Options;
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
        protected BaseRequestContext(OpenIddictServerTransaction transaction)
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
    public abstract class BaseValidatingClientContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="BaseValidatingClientContext"/> class.
        /// </summary>
        protected BaseValidatingClientContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets the "client_id" parameter for the current request.
        /// The authorization server application is responsible for
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string? ClientId => Transaction.Request?.ClientId;

        /// <summary>
        /// Gets the "client_secret" parameter for the current request.
        /// The authorization server application is responsible for
        /// validating this value to ensure it identifies a registered client.
        /// </summary>
        public string? ClientSecret => Transaction.Request?.ClientSecret;
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
        protected BaseValidatingContext(OpenIddictServerTransaction transaction)
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
        protected BaseValidatingTicketContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the security principal.
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }

        /// <summary>
        /// Gets the client identifier, or <see langword="null"/> if the client application is unknown.
        /// </summary>
        public string? ClientId => Transaction.Request?.ClientId;
    }

    /// <summary>
    /// Represents an event called when processing an incoming request.
    /// </summary>
    public sealed class ProcessRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessRequestContext"/> class.
        /// </summary>
        public ProcessRequestContext(OpenIddictServerTransaction transaction)
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
        public ProcessErrorContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request or <see langword="null"/> if it couldn't be extracted.
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
    public sealed class ProcessAuthenticationContext : BaseValidatingClientContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessAuthenticationContext"/> class.
        /// </summary>
        public ProcessAuthenticationContext(OpenIddictServerTransaction transaction)
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
        /// Gets or sets a boolean indicating whether an access
        /// token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an authorization
        /// code should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a client assertion
        /// token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a device
        /// code should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a generic
        /// token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractGenericToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an identity
        /// token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a refresh
        /// token should be extracted from the current context.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ExtractRefreshToken { get; set; }

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
        /// Gets or sets a boolean indicating whether an access token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an authorization code
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a client assertion
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a device code
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a generic token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireGenericToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an identity token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a refresh token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a request token
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a user code
        /// must be resolved for the authentication to be considered valid.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RequireUserCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the access
        /// token extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the authorization
        /// code extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the client assertion
        /// token extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the device
        /// code extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generic
        /// token extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateGenericToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the identity
        /// token extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the refresh
        /// token extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the request token
        /// extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the user
        /// code extracted from the current request should be validated.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool ValidateUserCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid access token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid authorization code
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid client assertion
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid device code
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid generic token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectGenericToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid identity token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid refresh token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid request token
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an invalid user code
        /// will cause the authentication demand to be rejected or will be ignored.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool RejectUserCode { get; set; }

        /// <summary>
        /// Gets or sets the access token to validate, if applicable.
        /// </summary>
        public string? AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the access token, if applicable.
        /// </summary>
        public ClaimsPrincipal? AccessTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the authorization code to validate, if applicable.
        /// </summary>
        public string? AuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the authorization code, if applicable.
        /// </summary>
        public ClaimsPrincipal? AuthorizationCodePrincipal { get; set; }

        /// <summary>
        /// Gets or sets the client assertion to validate, if applicable.
        /// </summary>
        public string? ClientAssertion { get; set; }

        /// <summary>
        /// Gets or sets the type of the client assertion to validate, if applicable.
        /// </summary>
        public string? ClientAssertionType { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the client assertion, if applicable.
        /// </summary>
        public ClaimsPrincipal? ClientAssertionPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the device code to validate, if applicable.
        /// </summary>
        public string? DeviceCode { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the device code, if applicable.
        /// </summary>
        public ClaimsPrincipal? DeviceCodePrincipal { get; set; }

        /// <summary>
        /// Gets or sets the generic token to validate, if applicable.
        /// </summary>
        public string? GenericToken { get; set; }

        /// <summary>
        /// Gets or sets the optional hint indicating the type of the generic token, if applicable.
        /// </summary>
        public string? GenericTokenTypeHint { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the generic token, if applicable.
        /// </summary>
        public ClaimsPrincipal? GenericTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the identity token to validate, if applicable.
        /// </summary>
        public string? IdentityToken { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the identity token, if applicable.
        /// </summary>
        public ClaimsPrincipal? IdentityTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the refresh token to validate, if applicable.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the refresh token, if applicable.
        /// </summary>
        public ClaimsPrincipal? RefreshTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the request token to validate, if applicable.
        /// </summary>
        public string? RequestToken { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the request token, if applicable.
        /// </summary>
        public ClaimsPrincipal? RequestTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the user code to validate, if applicable.
        /// </summary>
        public string? UserCode { get; set; }

        /// <summary>
        /// Gets or sets the principal extracted from the user code, if applicable.
        /// </summary>
        public ClaimsPrincipal? UserCodePrincipal { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing a challenge operation.
    /// </summary>
    public sealed class ProcessChallengeContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessChallengeContext"/> class.
        /// </summary>
        public ProcessChallengeContext(OpenIddictServerTransaction transaction)
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
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// Represents an event called when processing a sign-in response.
    /// </summary>
    public sealed class ProcessSignInContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessSignInContext"/> class.
        /// </summary>
        public ProcessSignInContext(OpenIddictServerTransaction transaction)
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
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets a boolean indicating whether an access token
        /// should be generated (and optionally returned to the client).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an authorization code
        /// should be generated (and optionally returned to the client).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a device code
        /// should be generated (and optionally returned to the client).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether an identity token
        /// should be generated (and optionally returned to the client).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a refresh token
        /// should be generated (and optionally returned to the client).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a request token
        /// should be generated (and optionally returned to the client).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether a user code
        /// should be generated (and optionally returned to the client).
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool GenerateUserCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated access token
        /// should be returned to the client application as part of the response.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeAccessToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated authorization code
        /// should be returned to the client application as part of the response.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeAuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated device code
        /// should be returned to the client application as part of the response.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeDeviceCode { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated identity token
        /// should be returned to the client application as part of the response.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeIdentityToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated refresh token
        /// should be returned to the client application as part of the response.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeRefreshToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated request token
        /// should be returned to the client application as part of the response.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeRequestToken { get; set; }

        /// <summary>
        /// Gets or sets a boolean indicating whether the generated user code
        /// should be returned to the client application as part of the response.
        /// </summary>
        /// <remarks>
        /// Note: overriding the value of this property is generally not recommended.
        /// </remarks>
        public bool IncludeUserCode { get; set; }

        /// <summary>
        /// Gets or sets the generated access token, if applicable.
        /// The access token will only be returned if
        /// <see cref="IncludeAccessToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? AccessToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the access token, if applicable.
        /// </summary>
        public ClaimsPrincipal? AccessTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the generated authorization code, if applicable.
        /// The authorization code will only be returned if
        /// <see cref="IncludeAuthorizationCode"/> is set to <see langword="true"/>.
        /// </summary>
        public string? AuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the authorization code, if applicable.
        /// </summary>
        public ClaimsPrincipal? AuthorizationCodePrincipal { get; set; }

        /// <summary>
        /// Gets or sets the generated device code, if applicable.
        /// The device code will only be returned if
        /// <see cref="IncludeDeviceCode"/> is set to <see langword="true"/>.
        /// </summary>
        public string? DeviceCode { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the device code, if applicable.
        /// </summary>
        public ClaimsPrincipal? DeviceCodePrincipal { get; set; }

        /// <summary>
        /// Gets or sets the generated identity token, if applicable.
        /// The identity token will only be returned if
        /// <see cref="IncludeIdentityToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? IdentityToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the identity token, if applicable.
        /// </summary>
        public ClaimsPrincipal? IdentityTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the generated refresh token, if applicable.
        /// The refresh token will only be returned if
        /// <see cref="IncludeRefreshToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? RefreshToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the refresh token, if applicable.
        /// </summary>
        public ClaimsPrincipal? RefreshTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the generated request token, if applicable.
        /// The request token will only be returned if
        /// <see cref="IncludeRequestToken"/> is set to <see langword="true"/>.
        /// </summary>
        public string? RequestToken { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that will be used
        /// to create the request token, if applicable.
        /// </summary>
        public ClaimsPrincipal? RequestTokenPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the generated user code, if applicable.
        /// The user code will only be returned if
        /// <see cref="IncludeUserCode"/> is set to <see langword="true"/>.
        /// </summary>
        public string? UserCode { get; set; }

        /// <summary>
        /// Gets or sets the principal containing the claims that
        /// will be used to create the user code, if applicable.
        /// </summary>
        public ClaimsPrincipal? UserCodePrincipal { get; set; }
    }

    /// <summary>
    /// Represents an event called when processing a sign-out response.
    /// </summary>
    public sealed class ProcessSignOutContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcessSignOutContext"/> class.
        /// </summary>
        public ProcessSignOutContext(OpenIddictServerTransaction transaction)
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
        /// Gets the additional parameters returned to the caller.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; } = new(StringComparer.Ordinal);
    }
}

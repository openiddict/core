/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;

namespace OpenIddict.Client;

public static partial class OpenIddictClientEvents
{
    /// <summary>
    /// Represents an event called for each request to the authorization endpoint to give the user code
    /// a chance to manually update the authorization request before it is sent to the identity provider.
    /// </summary>
    public sealed class PrepareAuthorizationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareAuthorizationRequestContext"/> class.
        /// </summary>
        public PrepareAuthorizationRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the principal containing the claims stored in the state object.
        /// </summary>
        public ClaimsPrincipal StatePrincipal { get; set; } = new ClaimsPrincipal(new ClaimsIdentity());
    }

    /// <summary>
    /// Represents an event called for each request to the authorization endpoint
    /// to give the user code a chance to manually send the authorization request.
    /// </summary>
    public sealed class ApplyAuthorizationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PrepareAuthorizationRequestContext"/> class.
        /// </summary>
        public ApplyAuthorizationRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the nonce that is used as the unique identifier of the operation, if available.
        /// </summary>
        public string? Nonce { get; set; }

        /// <summary>
        /// Gets or sets the redirect URI that was selected during the challenge, if available.
        /// </summary>
        public string? RedirectUri { get; set; }

        /// <summary>
        /// Gets or sets the URI of the remote authorization endpoint.
        /// </summary>
        public string AuthorizationEndpoint { get; set; } = null!;
    }

    /// <summary>
    /// Represents an event called for each request to the pushed authorization endpoint request
    /// to give the user code a chance to add parameters to the pushed authorization request.
    /// </summary>
    public sealed class PreparePushedAuthorizationRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="PreparePushedAuthorizationRequestContext"/> class.
        /// </summary>
        public PreparePushedAuthorizationRequestContext(OpenIddictClientTransaction transaction)
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
    }

    /// <summary>
    /// Represents an event called for each request to the pushed authorization endpoint request
    /// to send the pushed authorization request to the remote authorization server.
    /// </summary>
    public sealed class ApplyPushedAuthorizationRequestContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyPushedAuthorizationRequestContext"/> class.
        /// </summary>
        public ApplyPushedAuthorizationRequestContext(OpenIddictClientTransaction transaction)
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
    }

    /// <summary>
    /// Represents an event called for each pushed authorization response
    /// to extract the response parameters from the server response.
    /// </summary>
    public sealed class ExtractPushedAuthorizationResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractPushedAuthorizationResponseContext"/> class.
        /// </summary>
        public ExtractPushedAuthorizationResponseContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the response, or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictResponse? Response
        {
            get => Transaction.Response;
            set => Transaction.Response = value;
        }
    }

    /// <summary>
    /// Represents an event called for each pushed authorization response.
    /// </summary>
    public sealed class HandlePushedAuthorizationResponseContext : BaseExternalContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandlePushedAuthorizationResponseContext"/> class.
        /// </summary>
        public HandlePushedAuthorizationResponseContext(OpenIddictClientTransaction transaction)
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
    }

    /// <summary>
    /// Represents an event called for each request to the redirection endpoint to give the user code
    /// a chance to manually extract the redirection request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractRedirectionRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractRedirectionRequestContext"/> class.
        /// </summary>
        public ExtractRedirectionRequestContext(OpenIddictClientTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request or <see langword="null"/> if it was extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the redirection endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateRedirectionRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateRedirectionRequestContext"/> class.
        /// </summary>
        public ValidateRedirectionRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets or sets the security principal extracted from the identity token,
        /// if applicable to the current redirection request. If no identity token
        /// is available at the validation stage, a token request will typically be
        /// sent to retrieve a complete set of tokens (e.g authorization code flow).
        /// </summary>
        public ClaimsPrincipal? Principal { get; set; }

        /// <summary>
        /// Gets or sets the security principal extracted from the state token.
        /// </summary>
        public ClaimsPrincipal? StateTokenPrincipal { get; set; }
    }

    /// <summary>
    /// Represents an event called for each validated redirection request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public sealed class HandleRedirectionRequestContext : BaseValidatingTicketContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleRedirectionRequestContext"/> class.
        /// </summary>
        public HandleRedirectionRequestContext(OpenIddictClientTransaction transaction)
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
        /// Gets the additional parameters returned to the client application.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; private set; }
            = new(StringComparer.Ordinal);
    }

    /// <summary>
    /// Represents an event called before the redirection response is returned to the caller.
    /// </summary>
    public sealed class ApplyRedirectionResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyRedirectionResponseContext"/> class.
        /// </summary>
        public ApplyRedirectionResponseContext(OpenIddictClientTransaction transaction)
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
    }
}

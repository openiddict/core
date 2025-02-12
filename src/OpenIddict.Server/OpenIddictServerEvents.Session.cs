/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

namespace OpenIddict.Server;

public static partial class OpenIddictServerEvents
{
    /// <summary>
    /// Represents an event called for each request to the end session endpoint to give the user code
    /// a chance to manually extract the end session request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractEndSessionRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractEndSessionRequestContext"/> class.
        /// </summary>
        public ExtractEndSessionRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if wasn't extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the end session endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateEndSessionRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateEndSessionRequestContext"/> class.
        /// </summary>
        public ValidateEndSessionRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
            // Infer the post_logout_redirect_uri from the value specified by the client application.
            => PostLogoutRedirectUri = Request?.PostLogoutRedirectUri;

        /// <summary>
        /// Gets or sets the request.
        /// </summary>
        public OpenIddictRequest Request
        {
            get => Transaction.Request!;
            set => Transaction.Request = value;
        }

        /// <summary>
        /// Gets the client_id specified by the client application, if available.
        /// </summary>
        public string? ClientId => Request?.ClientId;

        /// <summary>
        /// Gets the post_logout_redirect_uri specified by the client application.
        /// </summary>
        [StringSyntax(StringSyntaxAttribute.Uri)]
        public string? PostLogoutRedirectUri { get; internal set; }

        /// <summary>
        /// Gets or sets the security principal extracted
        /// from the identity token hint, if applicable.
        /// </summary>
        public ClaimsPrincipal? IdentityTokenHintPrincipal { get; set; }

        /// <summary>
        /// Gets or sets the security principal extracted from the
        /// request token, if applicable.
        /// </summary>
        public ClaimsPrincipal? RequestTokenPrincipal { get; set; }

        /// <summary>
        /// Populates the <see cref="PostLogoutRedirectUri"/> property with the specified redirect_uri.
        /// </summary>
        /// <param name="uri">The post_logout_redirect_uri to use when redirecting the user agent.</param>
        public void SetPostLogoutRedirectUri([StringSyntax(StringSyntaxAttribute.Uri)] string uri)
        {
            if (string.IsNullOrEmpty(uri))
            {
                throw new ArgumentException(SR.GetResourceString(SR.ID0102), nameof(uri));
            }

            // Don't allow validation to alter the post_logout_redirect_uri parameter extracted
            // from the request if the URI was explicitly provided by the client application.
            if (!string.IsNullOrEmpty(Request?.PostLogoutRedirectUri) &&
                !string.Equals(Request.PostLogoutRedirectUri, uri, StringComparison.Ordinal))
            {
                throw new InvalidOperationException(SR.GetResourceString(SR.ID0103));
            }

            PostLogoutRedirectUri = uri;
        }
    }

    /// <summary>
    /// Represents an event called for each validated end session request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public sealed class HandleEndSessionRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleEndSessionRequestContext"/> class.
        /// </summary>
        public HandleEndSessionRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets or sets the security principal extracted
        /// from the identity token hint, if applicable.
        /// </summary>
        public ClaimsPrincipal? IdentityTokenHintPrincipal { get; set; }

        /// <summary>
        /// Gets a boolean indicating whether a sign-out should be triggered.
        /// </summary>
        public bool IsSignOutTriggered { get; private set; }

        /// <summary>
        /// Gets the additional parameters returned to the client application.
        /// </summary>
        public Dictionary<string, OpenIddictParameter> Parameters { get; private set; }
            = new(StringComparer.Ordinal);

        /// <summary>
        /// Allows OpenIddict to return a sign-out response.
        /// </summary>
        public void SignOut() => IsSignOutTriggered = true;

        /// <summary>
        /// Allows OpenIddict to return a sign-out response.
        /// </summary>
        /// <param name="parameters">The additional parameters returned to the client application.</param>
        public void SignOut(IDictionary<string, OpenIddictParameter> parameters)
        {
            IsSignOutTriggered = true;
            Parameters = new(parameters, StringComparer.Ordinal);
        }
    }

    /// <summary>
    /// Represents an event called before the end session response is returned to the caller.
    /// </summary>
    public sealed class ApplyEndSessionResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyEndSessionResponseContext"/> class.
        /// </summary>
        public ApplyEndSessionResponseContext(OpenIddictServerTransaction transaction)
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
        /// Gets the error code returned to the client application.
        /// When the response indicates a successful response,
        /// this property returns <see langword="null"/>.
        /// </summary>
        public string? Error => Response.Error;

        /// <summary>
        /// Gets or sets the post-logout redirect URI the user agent will be redirected to, if applicable.
        /// Note: manually changing the value of this property is generally not recommended
        /// and extreme caution must be taken to ensure the user agent is not redirected to
        /// an untrusted URI, which would result in an "open redirection" vulnerability.
        /// </summary>
        public string? PostLogoutRedirectUri { get; set; }
    }
}

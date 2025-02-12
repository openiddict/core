/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using Microsoft.IdentityModel.Tokens;

namespace OpenIddict.Server;

public static partial class OpenIddictServerEvents
{
    /// <summary>
    /// Represents an event called for each request to the configuration endpoint to give the user code
    /// a chance to manually extract the configuration request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractConfigurationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractConfigurationRequestContext"/> class.
        /// </summary>
        public ExtractConfigurationRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it wasn't extracted yet.
        /// </summary>
        public OpenIddictRequest? Request
        {
            get => Transaction.Request;
            set => Transaction.Request = value;
        }
    }

    /// <summary>
    /// Represents an event called for each request to the configuration endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateConfigurationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateConfigurationRequestContext"/> class.
        /// </summary>
        public ValidateConfigurationRequestContext(OpenIddictServerTransaction transaction)
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
    /// Represents an event called for each validated configuration request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public sealed class HandleConfigurationRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleConfigurationRequestContext"/> class.
        /// </summary>
        public HandleConfigurationRequestContext(OpenIddictServerTransaction transaction)
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
        public Dictionary<string, OpenIddictParameter> Metadata { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets the issuer URI.
        /// </summary>
        public Uri? Issuer { get; set; }

        /// <summary>
        /// Gets or sets the authorization endpoint URI.
        /// </summary>
        public Uri? AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the JSON Web Key Set endpoint URI.
        /// </summary>
        public Uri? JsonWebKeySetEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the device authorization endpoint URI.
        /// </summary>
        public Uri? DeviceAuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the end session endpoint URI.
        /// </summary>
        public Uri? EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the introspection endpoint URI.
        /// </summary>
        public Uri? IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the pushed authorization endpoint URI.
        /// </summary>
        public Uri? PushedAuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the revocation endpoint URI.
        /// </summary>
        public Uri? RevocationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the token endpoint URI.
        /// </summary>
        public Uri? TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the userinfo endpoint URI.
        /// </summary>
        public Uri? UserInfoEndpoint { get; set; }

        /// <summary>
        /// Gets the list of claims supported by the authorization server.
        /// </summary>
        public HashSet<string> Claims { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of the code challenge methods
        /// supported by the authorization server.
        /// </summary>
        public HashSet<string> CodeChallengeMethods { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of client authentication methods supported by
        /// the device authorization endpoint provided by the authorization server.
        /// </summary>
        public HashSet<string> DeviceAuthorizationEndpointAuthenticationMethods { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of grant types
        /// supported by the authorization server.
        /// </summary>
        public HashSet<string> GrantTypes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of signing algorithms supported by the
        /// authorization server for signing the identity tokens.
        /// </summary>
        public HashSet<string> IdTokenSigningAlgorithms { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of client authentication methods supported by
        /// the introspection endpoint provided by the authorization server.
        /// </summary>
        public HashSet<string> IntrospectionEndpointAuthenticationMethods { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of prompt values supported by the authorization server.
        /// </summary>
        public HashSet<string> PromptValues { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of client authentication methods supported by the pushed
        /// authorization endpoint provided by the authorization server.
        /// </summary>
        public HashSet<string> PushedAuthorizationEndpointAuthenticationMethods { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of response modes
        /// supported by the authorization server.
        /// </summary>
        public HashSet<string> ResponseModes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of response types
        /// supported by the authorization server.
        /// </summary>
        public HashSet<string> ResponseTypes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of client authentication methods supported by
        /// the revocation endpoint provided by the authorization server.
        /// </summary>
        public HashSet<string> RevocationEndpointAuthenticationMethods { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of scope values
        /// supported by the authorization server.
        /// </summary>
        public HashSet<string> Scopes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets the list of subject types
        /// supported by the authorization server.
        /// </summary>
        public HashSet<string> SubjectTypes { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets a list of client authentication methods supported by
        /// the token endpoint provided by the authorization server.
        /// </summary>
        public HashSet<string> TokenEndpointAuthenticationMethods { get; } = new(StringComparer.Ordinal);

        /// <summary>
        /// Gets or sets a boolean indicating whether pushed authorization requests are required.
        /// </summary>
        public bool RequirePushedAuthorizationRequests { get; set; }
    }

    /// <summary>
    /// Represents an event called before the configuration response is returned to the caller.
    /// </summary>
    public sealed class ApplyConfigurationResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyConfigurationResponseContext"/> class.
        /// </summary>
        public ApplyConfigurationResponseContext(OpenIddictServerTransaction transaction)
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
    }

    /// <summary>
    /// Represents an event called for each request to the JSON Web Key Set endpoint to give the user code
    /// a chance to manually extract the JSON Web Key Set request from the ambient HTTP context.
    /// </summary>
    public sealed class ExtractJsonWebKeySetRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ExtractJsonWebKeySetRequestContext"/> class.
        /// </summary>
        public ExtractJsonWebKeySetRequestContext(OpenIddictServerTransaction transaction)
            : base(transaction)
        {
        }

        /// <summary>
        /// Gets or sets the request, or <see langword="null"/> if it wasn't extracted yet.
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

    /// <summary>
    /// Represents an event called for each request to the JSON Web Key Set endpoint
    /// to determine if the request is valid and should continue to be processed.
    /// </summary>
    public sealed class ValidateJsonWebKeySetRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ValidateJsonWebKeySetRequestContext"/> class.
        /// </summary>
        public ValidateJsonWebKeySetRequestContext(OpenIddictServerTransaction transaction)
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
    /// Represents an event called for each validated JSON Web Key Set request
    /// to allow the user code to decide how the request should be handled.
    /// </summary>
    public sealed class HandleJsonWebKeySetRequestContext : BaseValidatingContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HandleJsonWebKeySetRequestContext"/> class.
        /// </summary>
        public HandleJsonWebKeySetRequestContext(OpenIddictServerTransaction transaction)
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
        /// Gets the list of JSON Web Keys exposed by the JSON Web Key Set endpoint.
        /// </summary>
        public List<JsonWebKey> Keys { get; } = [];
    }

    /// <summary>
    /// Represents an event called before the JSON Web Key Set response is returned to the caller.
    /// </summary>
    public sealed class ApplyJsonWebKeySetResponseContext : BaseRequestContext
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ApplyJsonWebKeySetResponseContext"/> class.
        /// </summary>
        public ApplyJsonWebKeySetResponseContext(OpenIddictServerTransaction transaction)
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
    }
}

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Specialized;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Primitives;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents a generic OpenIddict request.
/// </summary>
/// <remarks>
/// Security notice: developers instantiating this type are responsible for ensuring that the
/// imported parameters are safe and won't cause the resulting message to grow abnormally,
/// which may result in an excessive memory consumption and a potential denial of service.
/// </remarks>
[DebuggerDisplay("Parameters: {Parameters.Count}")]
[JsonConverter(typeof(OpenIddictConverter))]
public class OpenIddictRequest : OpenIddictMessage
{
    /// <summary>
    /// Initializes a new OpenIddict request.
    /// </summary>
    public OpenIddictRequest()
        : base()
    {
    }

    /// <summary>
    /// Initializes a new OpenIddict request.
    /// </summary>
    /// <param name="parameters">The request parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictRequest(JsonElement parameters)
        : base(parameters)
    {
    }

#if SUPPORTS_JSON_NODES
    /// <summary>
    /// Initializes a new OpenIddict request.
    /// </summary>
    /// <param name="parameters">The request parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictRequest(JsonObject parameters)
        : base(parameters)
    {
    }
#endif

    /// <summary>
    /// Initializes a new OpenIddict request.
    /// </summary>
    /// <param name="parameters">The request parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictRequest(IEnumerable<KeyValuePair<string, OpenIddictParameter>> parameters)
        : base(parameters)
    {
    }

    /// <summary>
    /// Initializes a new OpenIddict request.
    /// </summary>
    /// <param name="parameters">The request parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictRequest(IEnumerable<KeyValuePair<string, string?>> parameters)
        : base(parameters)
    {
    }

    /// <summary>
    /// Initializes a new OpenIddict request.
    /// </summary>
    /// <param name="parameters">The request parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictRequest(IEnumerable<KeyValuePair<string, string?[]?>> parameters)
        : base(parameters)
    {
    }

    /// <summary>
    /// Initializes a new OpenIddict request.
    /// </summary>
    /// <param name="parameters">The request parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictRequest(IEnumerable<KeyValuePair<string, StringValues>> parameters)
        : base(parameters)
    {
    }

    /// <summary>
    /// Initializes a new OpenIddict request.
    /// </summary>
    /// <param name="parameters">The request parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictRequest(NameValueCollection parameters)
        : base(parameters)
    {
    }

    /// <summary>
    /// Gets or sets the "access_token" parameter.
    /// </summary>
    public string? AccessToken
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.AccessToken);
        set => SetParameter(OpenIddictConstants.Parameters.AccessToken, value);
    }

    /// <summary>
    /// Gets or sets the "acr_values" parameter.
    /// </summary>
    public string? AcrValues
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.AcrValues);
        set => SetParameter(OpenIddictConstants.Parameters.AcrValues, value);
    }

    /// <summary>
    /// Gets or sets the "assertion" parameter.
    /// </summary>
    public string? Assertion
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Assertion);
        set => SetParameter(OpenIddictConstants.Parameters.Assertion, value);
    }

    /// <summary>
    /// Gets or sets the "audience" parameters.
    /// </summary>
    public string?[]? Audiences
    {
        get => (string?[]?) GetParameter(OpenIddictConstants.Parameters.Audience);
        set => SetParameter(OpenIddictConstants.Parameters.Audience, value);
    }

    /// <summary>
    /// Gets or sets the "claims" parameter.
    /// </summary>
    public JsonElement Claims
    {
        get => (JsonElement) GetParameter(OpenIddictConstants.Parameters.Claims);
        set => SetParameter(OpenIddictConstants.Parameters.Claims, value);
    }

    /// <summary>
    /// Gets or sets the "claims_locales" parameter.
    /// </summary>
    public string? ClaimsLocales
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.ClaimsLocales);
        set => SetParameter(OpenIddictConstants.Parameters.ClaimsLocales, value);
    }

    /// <summary>
    /// Gets or sets the "client_assertion" parameter.
    /// </summary>
    public string? ClientAssertion
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.ClientAssertion);
        set => SetParameter(OpenIddictConstants.Parameters.ClientAssertion, value);
    }

    /// <summary>
    /// Gets or sets the "client_assertion_type" parameter.
    /// </summary>
    public string? ClientAssertionType
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.ClientAssertionType);
        set => SetParameter(OpenIddictConstants.Parameters.ClientAssertionType, value);
    }

    /// <summary>
    /// Gets or sets the "client_id" parameter.
    /// </summary>
    public string? ClientId
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.ClientId);
        set => SetParameter(OpenIddictConstants.Parameters.ClientId, value);
    }

    /// <summary>
    /// Gets or sets the "client_secret" parameter.
    /// </summary>
    public string? ClientSecret
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.ClientSecret);
        set => SetParameter(OpenIddictConstants.Parameters.ClientSecret, value);
    }

    /// <summary>
    /// Gets or sets the "code" parameter.
    /// </summary>
    public string? Code
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Code);
        set => SetParameter(OpenIddictConstants.Parameters.Code, value);
    }

    /// <summary>
    /// Gets or sets the "code_challenge" parameter.
    /// </summary>
    public string? CodeChallenge
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.CodeChallenge);
        set => SetParameter(OpenIddictConstants.Parameters.CodeChallenge, value);
    }

    /// <summary>
    /// Gets or sets the "code_challenge_method" parameter.
    /// </summary>
    public string? CodeChallengeMethod
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.CodeChallengeMethod);
        set => SetParameter(OpenIddictConstants.Parameters.CodeChallengeMethod, value);
    }

    /// <summary>
    /// Gets or sets the "code_verifier" parameter.
    /// </summary>
    public string? CodeVerifier
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.CodeVerifier);
        set => SetParameter(OpenIddictConstants.Parameters.CodeVerifier, value);
    }

    /// <summary>
    /// Gets or sets the "device_code" parameter.
    /// </summary>
    public string? DeviceCode
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.DeviceCode);
        set => SetParameter(OpenIddictConstants.Parameters.DeviceCode, value);
    }

    /// <summary>
    /// Gets or sets the "display" parameter.
    /// </summary>
    public string? Display
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Display);
        set => SetParameter(OpenIddictConstants.Parameters.Display, value);
    }

    /// <summary>
    /// Gets or sets the "grant_type" parameter.
    /// </summary>
    public string? GrantType
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.GrantType);
        set => SetParameter(OpenIddictConstants.Parameters.GrantType, value);
    }

    /// <summary>
    /// Gets or sets the "identity_provider" parameter.
    /// </summary>
    public string? IdentityProvider
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.IdentityProvider);
        set => SetParameter(OpenIddictConstants.Parameters.IdentityProvider, value);
    }

    /// <summary>
    /// Gets or sets the "id_token" parameter.
    /// </summary>
    public string? IdToken
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.IdToken);
        set => SetParameter(OpenIddictConstants.Parameters.IdToken, value);
    }

    /// <summary>
    /// Gets or sets the "id_token_hint" parameter.
    /// </summary>
    public string? IdTokenHint
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.IdTokenHint);
        set => SetParameter(OpenIddictConstants.Parameters.IdTokenHint, value);
    }

    /// <summary>
    /// Gets or sets the "login_hint" parameter.
    /// </summary>
    public string? LoginHint
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.LoginHint);
        set => SetParameter(OpenIddictConstants.Parameters.LoginHint, value);
    }

    /// <summary>
    /// Gets or sets the "max_age" parameter.
    /// </summary>
    public long? MaxAge
    {
        get => (long?) GetParameter(OpenIddictConstants.Parameters.MaxAge);
        set => SetParameter(OpenIddictConstants.Parameters.MaxAge, value);
    }

    /// <summary>
    /// Gets or sets the "nonce" parameter.
    /// </summary>
    public string? Nonce
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Nonce);
        set => SetParameter(OpenIddictConstants.Parameters.Nonce, value);
    }

    /// <summary>
    /// Gets or sets the "password" parameter.
    /// </summary>
    public string? Password
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Password);
        set => SetParameter(OpenIddictConstants.Parameters.Password, value);
    }

    /// <summary>
    /// Gets or sets the "post_logout_redirect_uri" parameter.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Uri)]
    public string? PostLogoutRedirectUri
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.PostLogoutRedirectUri);
        set => SetParameter(OpenIddictConstants.Parameters.PostLogoutRedirectUri, value);
    }

    /// <summary>
    /// Gets or sets the "prompt" parameter.
    /// </summary>
    public string? Prompt
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Prompt);
        set => SetParameter(OpenIddictConstants.Parameters.Prompt, value);
    }

    /// <summary>
    /// Gets or sets the "redirect_uri" parameter.
    /// </summary>
    [StringSyntax(StringSyntaxAttribute.Uri)]
    public string? RedirectUri
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.RedirectUri);
        set => SetParameter(OpenIddictConstants.Parameters.RedirectUri, value);
    }

    /// <summary>
    /// Gets or sets the "refresh_token" parameter.
    /// </summary>
    public string? RefreshToken
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.RefreshToken);
        set => SetParameter(OpenIddictConstants.Parameters.RefreshToken, value);
    }

    /// <summary>
    /// Gets or sets the "request" parameter.
    /// </summary>
    public string? Request
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Request);
        set => SetParameter(OpenIddictConstants.Parameters.Request, value);
    }

    /// <summary>
    /// Gets or sets the "request_id" parameter.
    /// </summary>
    [Obsolete("This property is obsolete and will be removed in a future version.")]
    public string? RequestId
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.RequestId);
        set => SetParameter(OpenIddictConstants.Parameters.RequestId, value);
    }

    /// <summary>
    /// Gets or sets the "request_uri" parameter.
    /// </summary>
    public string? RequestUri
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.RequestUri);
        set => SetParameter(OpenIddictConstants.Parameters.RequestUri, value);
    }

    /// <summary>
    /// Gets or sets the "resource" parameters.
    /// </summary>
    public string?[]? Resources
    {
        get => (string?[]?) GetParameter(OpenIddictConstants.Parameters.Resource);
        set => SetParameter(OpenIddictConstants.Parameters.Resource, value);
    }

    /// <summary>
    /// Gets or sets the "response_mode" parameter.
    /// </summary>
    public string? ResponseMode
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.ResponseMode);
        set => SetParameter(OpenIddictConstants.Parameters.ResponseMode, value);
    }

    /// <summary>
    /// Gets or sets the "response_type" parameter.
    /// </summary>
    public string? ResponseType
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.ResponseType);
        set => SetParameter(OpenIddictConstants.Parameters.ResponseType, value);
    }

    /// <summary>
    /// Gets or sets the "scope" parameter.
    /// </summary>
    public string? Scope
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Scope);
        set => SetParameter(OpenIddictConstants.Parameters.Scope, value);
    }

    /// <summary>
    /// Gets or sets the "state" parameter.
    /// </summary>
    public string? State
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.State);
        set => SetParameter(OpenIddictConstants.Parameters.State, value);
    }

    /// <summary>
    /// Gets or sets the "token" parameter.
    /// </summary>
    public string? Token
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Token);
        set => SetParameter(OpenIddictConstants.Parameters.Token, value);
    }

    /// <summary>
    /// Gets or sets the "token_type_hint" parameter.
    /// </summary>
    public string? TokenTypeHint
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.TokenTypeHint);
        set => SetParameter(OpenIddictConstants.Parameters.TokenTypeHint, value);
    }

    /// <summary>
    /// Gets or sets the "registration" parameter.
    /// </summary>
    public JsonElement Registration
    {
        get => (JsonElement) GetParameter(OpenIddictConstants.Parameters.Registration);
        set => SetParameter(OpenIddictConstants.Parameters.Registration, value);
    }

    /// <summary>
    /// Gets or sets the "ui_locales" parameter.
    /// </summary>
    public string? UiLocales
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.UiLocales);
        set => SetParameter(OpenIddictConstants.Parameters.UiLocales, value);
    }

    /// <summary>
    /// Gets or sets the "user_code" parameter.
    /// </summary>
    public string? UserCode
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.UserCode);
        set => SetParameter(OpenIddictConstants.Parameters.UserCode, value);
    }

    /// <summary>
    /// Gets or sets the "username" parameter.
    /// </summary>
    public string? Username
    {
        get => (string?) GetParameter(OpenIddictConstants.Parameters.Username);
        set => SetParameter(OpenIddictConstants.Parameters.Username, value);
    }
}

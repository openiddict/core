/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Net.Http;
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Theory]
    [InlineData(nameof(HttpMethod.Delete))]
    [InlineData(nameof(HttpMethod.Head))]
    [InlineData(nameof(HttpMethod.Options))]
    [InlineData(nameof(HttpMethod.Put))]
    [InlineData(nameof(HttpMethod.Trace))]
    public async Task ExtractAuthorizationRequest_UnexpectedMethodReturnsAnError(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendAsync(method, "/connect/authorize", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2084), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2084), response.ErrorUri);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ExtractAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/authorize");

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ExtractAuthorizationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/authorize");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ExtractAuthorizationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/connect/authorize");

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_UnsupportedRequestParameterIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            Request = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vd3d3LmZhYnJpa2FtLmNvbSIsImF1ZCI6Imh0" +
                      "dHA6Ly93d3cuY29udG9zby5jb20iLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6" +
                      "IkZhYnJpa2FtIiwicmVkaXJlY3RfdXJpIjoiaHR0cDovL3d3dy5mYWJyaWthbS5jb20vcGF0aCJ9.",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.RequestNotSupported, response.Error);
        Assert.Equal(SR.FormatID2028(Parameters.Request), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2028), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_UnsupportedRequestUriIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            RequestUri = "http://www.fabrikam.com/request/GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.RequestUriNotSupported, response.Error);
        Assert.Equal(SR.FormatID2028(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2028), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_MissingRequestUriCausesAnErrorWhenPushedAuthorizationRequestsAreRequired()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.RequirePushedAuthorizationRequests();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = null,
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_ValidRequestUriDoesNotCauseAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.RequirePushedAuthorizationRequests();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("6esc_11ACC5bwc014ltc14eY22c", context.Token);
                    Assert.Equal([TokenTypeHints.Private.RequestToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.Private.RequestToken)
                        .SetClaim(Claims.Private.RequestTokenType, RequestTokenTypes.Private.PushedAuthorizationRequest)
                        .SetClaim(Claims.Private.RequestParameters, $$"""
                        {
                          "client_id": "Fabrikam",
                          "redirect_uri": "http://www.fabrikam.com/path",
                          "response_type": "code",
                          "scope": "openid"
                        }
                        """);

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = RequestUris.Prefixes.Generic + "6esc_11ACC5bwc014ltc14eY22c"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.Code);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_MissingClientIdCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = null
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_MissingRedirectUriCausesAnErrorForOpenIdRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = null,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Theory]
    [InlineData("/path", SR.ID2030)]
    [InlineData("/tmp/file.xml", SR.ID2030)]
    [InlineData("C:\\tmp\\file.xml", SR.ID2030)]
    [InlineData("http://www.fabrikam.com/path#param=value", SR.ID2031)]
    public async Task ValidateAuthorizationRequest_InvalidRedirectUriCausesAnError(string uri, string message)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = uri,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(string.Format(SR.GetResourceString(message), Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(message), response.ErrorUri);
    }

    [Theory]
    [InlineData("http://www.fabrikam.com/path?iss")]
    [InlineData("http://www.fabrikam.com/path?iss=value")]
    [InlineData("http://www.fabrikam.com/path?;iss")]
    [InlineData("http://www.fabrikam.com/path?;iss=value")]
    [InlineData("http://www.fabrikam.com/path?&iss")]
    [InlineData("http://www.fabrikam.com/path?&iss=value")]
    [InlineData("http://www.fabrikam.com/path?state;iss")]
    [InlineData("http://www.fabrikam.com/path?state;iss=value")]
    [InlineData("http://www.fabrikam.com/path?state&iss")]
    [InlineData("http://www.fabrikam.com/path?state&iss=value")]
    [InlineData("http://www.fabrikam.com/path?state=abc;iss")]
    [InlineData("http://www.fabrikam.com/path?state=abc;iss=value")]
    [InlineData("http://www.fabrikam.com/path?state=abc&iss")]
    [InlineData("http://www.fabrikam.com/path?state=abc&iss=value")]
    public async Task ValidateAuthorizationRequest_RedirectUriWithIssuerParameterCausesAnError(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = uri,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2135(Parameters.RedirectUri, Parameters.Iss), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2135), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_MissingResponseTypeCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = null,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token", ResponseModes.Query)]
    [InlineData("code id_token token", ResponseModes.Query)]
    [InlineData("code token", ResponseModes.Query)]
    [InlineData("id_token", ResponseModes.Query)]
    [InlineData("id_token token", ResponseModes.Query)]
    [InlineData("token", ResponseModes.Query)]
    public async Task ValidateAuthorizationRequest_UnsafeResponseModeCausesAnError(string type, string mode)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = mode,
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2033(Parameters.ResponseType, Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2033), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ValidateAuthorizationRequest_MissingNonceCausesAnErrorForOpenIdRequests(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.Nonce), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    public async Task ValidateAuthorizationRequest_MissingOpenIdScopeCausesAnErrorForOpenIdRequests(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2034(Scopes.OpenId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2034), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_UnsupportedPromptCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.PromptValues.Remove(PromptValues.SelectAccount));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            Prompt = PromptValues.SelectAccount,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = "code id_token token",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.Prompt), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("consent")]
    [InlineData("login")]
    [InlineData("select_account")]
    [InlineData("consent login")]
    [InlineData("consent select_account")]
    [InlineData("login select_account")]
    [InlineData("consent login select_account")]
    public async Task ValidateAuthorizationRequest_ValidPromptDoesNotCauseAnError(string prompt)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            Prompt = prompt,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = "code id_token token",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.AccessToken);
        Assert.NotNull(response.Code);
        Assert.NotNull(response.IdToken);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenPkceIsRequiredAndCodeChallengeIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.RequireProofKeyForCodeExchange();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.CodeChallenge), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenPkceIsNotRequiredAndCodeChallengeIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.Code);
    }

    [Theory]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ValidateAuthorizationRequest_MissingCodeResponseTypeCausesAnErrorWhenCodeChallengeIsUsed(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2040(Parameters.CodeChallenge, Parameters.CodeChallengeMethod, ResponseTypes.Code), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2040), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_MissingCodeChallengeCausesAnErrorWhenCodeChallengeMethodIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2037(Parameters.CodeChallengeMethod, Parameters.CodeChallenge), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2037), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_InvalidCodeChallengeMethodCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = "invalid_code_challenge_method",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.CodeChallengeMethod), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_UnknownResponseTypeParameterIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = "unknown_response_type"
        });

        // Assert
        Assert.Equal(Errors.UnsupportedResponseType, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData(GrantTypes.AuthorizationCode, "code")]
    [InlineData(GrantTypes.AuthorizationCode, "code id_token")]
    [InlineData(GrantTypes.AuthorizationCode, "code id_token token")]
    [InlineData(GrantTypes.AuthorizationCode, "code token")]
    [InlineData(GrantTypes.Implicit, "code id_token")]
    [InlineData(GrantTypes.Implicit, "code id_token token")]
    [InlineData(GrantTypes.Implicit, "code token")]
    [InlineData(GrantTypes.Implicit, "id_token")]
    [InlineData(GrantTypes.Implicit, "id_token token")]
    [InlineData(GrantTypes.Implicit, "token")]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenGrantTypeIsDisabled(string flow, string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.GrantTypes.Remove(flow));
            options.Configure(options => options.ResponseTypes.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnsupportedResponseType, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData("code")]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("none")]
    [InlineData("token")]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenResponseTypeIsDisabled(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.ResponseTypes.Remove(type));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnsupportedResponseType, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData("none code")]
    [InlineData("none code id_token")]
    [InlineData("none code id_token token")]
    [InlineData("none code token")]
    [InlineData("none id_token")]
    [InlineData("none id_token token")]
    [InlineData("none token")]
    public async Task ValidateAuthorizationRequest_InvalidResponseTypeParameterIsRejected(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_UnsupportedResponseModeCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = "unsupported_response_mode",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenUnregisteredScopeIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                var application = new OpenIddictApplication();

                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.Services.AddSingleton(CreateScopeManager(mock =>
            {
                mock.Setup(manager => manager.FindByNamesAsync(
                    It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "unregistered_scope"),
                    It.IsAny<CancellationToken>()))
                    .Returns(AsyncEnumerable.Empty<OpenIddictScope>());
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = "unregistered_scope"
        });

        // Assert
        Assert.Equal(Errors.InvalidScope, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.Scope), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenScopeRegisteredInOptionsIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.RegisterScopes("registered_scope");

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token,
            Scope = "registered_scope"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenRegisteredScopeIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            var scope = new OpenIddictScope();

            options.RegisterScopes("scope_registered_in_options");
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                var application = new OpenIddictApplication();

                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableDictionary.Create<string, string>());
            }));

            options.Services.AddSingleton(CreateScopeManager(mock =>
            {
                mock.Setup(manager => manager.FindByNamesAsync(
                    It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "scope_registered_in_database"),
                    It.IsAny<CancellationToken>()))
                    .Returns(new[] { scope }.ToAsyncEnumerable());

                mock.Setup(manager => manager.GetNameAsync(scope, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("scope_registered_in_database");
            }));

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token,
            Scope = "scope_registered_in_database scope_registered_in_options"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenFlowIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.GrantTypes.Remove(GrantTypes.RefreshToken));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OfflineAccess
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2035(Scopes.OfflineAccess), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2035), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_UnknownResponseModeParameterIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = "unknown_response_mode",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCodeChallengeMethodIsMissingAndPlainIsNotSupported()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.Services.PostConfigure<OpenIddictServerOptions>(options =>
                options.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.CodeChallengeMethod), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCodeChallengeMethodIsNotEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.Services.PostConfigure<OpenIddictServerOptions>(options =>
                options.CodeChallengeMethods.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.CodeChallengeMethod), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData(CodeChallengeMethods.Plain)]
    [InlineData(CodeChallengeMethods.Sha256)]
    [InlineData("custom_code_challenge_method")]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenCodeChallengeMethodIsRegistered(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.Configure(options => options.CodeChallengeMethods.Clear());
            options.Configure(options => options.CodeChallengeMethods.Add(method));

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = method,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.Code);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenRedirectUriIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = null,
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_MissingRedirectUriCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = null,
                ResponseType = ResponseTypes.Code
            });
        });

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID0028), exception.Message);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_InvalidRedirectUriCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SetRedirectUri("http://www.contoso.com/path");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/authorize", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code
            });
        });

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID0101), exception.Message);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenClientCannotBeFound()
    {
        // Arrange
        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(value: null);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    public async Task ValidateAuthorizationRequest_PkceRequestWithSensitiveResponseTypeIsRejectedWhenDegradedModeIsEnabled(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.FormatID2041(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2041), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    public async Task ValidateAuthorizationRequest_PkceRequestWithSensitiveResponseTypeIsRejectedWhenPermissionsAreIgnored(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.FormatID2041(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2041), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    public async Task ValidateAuthorizationRequest_PkceRequestWithSensitiveResponseTypeIsValidatedWhenPermissionsAreEnforced(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableArray.Create("rst:" + type));

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Configure(options => options.IgnoreResponseTypePermissions = false);

            options.Services.AddSingleton(manager);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.Code);
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ValidateAuthorizationRequest_AnAccessTokenIsNotReturnedWhenClientIsConfidential(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableArray<string>.Empty);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.FormatID2043(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2043), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Endpoints.Authorization, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreEndpointPermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2046), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2046), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Endpoints.Authorization, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData(
        "code",
        new[] { Permissions.GrantTypes.AuthorizationCode },
        SR.ID2047)]
    [InlineData(
        "code id_token",
        new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
        SR.ID2049)]
    [InlineData(
        "code id_token token",
        new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
        SR.ID2049)]
    [InlineData(
        "code token",
        new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
        SR.ID2049)]
    [InlineData(
        "id_token",
        new[] { Permissions.GrantTypes.Implicit },
        SR.ID2048)]
    [InlineData(
        "id_token token",
        new[] { Permissions.GrantTypes.Implicit },
        SR.ID2048)]
    [InlineData(
        "token",
        new[] { Permissions.GrantTypes.Implicit },
        SR.ID2048)]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenGrantTypePermissionIsNotGranted(
        string type, string[] permissions, string description)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            foreach (var permission in permissions)
            {
                mock.Setup(manager => manager.HasPermissionAsync(application, permission, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            }
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreGrantTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.GetResourceString(description), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(description), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application, permissions[0], It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData("code")]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("none")]
    [InlineData("token")]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenResponseTypePermissionIsNotGranted(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableArray<string>.Empty);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreResponseTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.FormatID2043(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2043), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenExplicitPermissionIsGranted(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableArray.Create("rst:" + type));

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Configure(options => options.IgnoreResponseTypePermissions = false);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.AccessToken);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenPermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.AuthorizationCode, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreGrantTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OfflineAccess
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2065(Scopes.OfflineAccess), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2065), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenRedirectUriIsInvalid()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2043(Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2043), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenScopePermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.Profile, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.Email, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
            options.RegisterScopes(Scopes.Email, Scopes.Profile);
            options.Configure(options => options.IgnoreScopePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = "openid offline_access profile email"
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2051), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2051), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.OpenId, It.IsAny<CancellationToken>()), Times.Never());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess, It.IsAny<CancellationToken>()), Times.Never());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.Profile, It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.Email, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsRejectedWhenCodeChallengeIsMissingWithPkceFeatureEnforced()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = null,
            CodeChallengeMethod = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2054(Parameters.CodeChallenge), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2054), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenCodeChallengeIsMissingWithPkceFeatureNotEnforced()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(manager);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = null,
            CodeChallengeMethod = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.NotNull(response.Code);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenCodeChallengeIsPresentWithPkceFeatureEnforced()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(manager);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.NotNull(response.Code);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenCodeIsNotRequestedWithPkceFeatureEnforced()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(manager);

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Null(response.Code);
        Assert.NotNull(response.AccessToken);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_InvalidIdentityTokenHintDoesNotCauseAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Null(context.IdentityTokenHintPrincipal);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Null(response.Code);
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_InvalidIdentityTokenHintCausesAnErrorWhenRejectionIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.RejectIdentityToken = true;

                    return default;
                });

                builder.SetOrder(EvaluateValidatedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2009), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2009), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_IdentityTokenHintCausesAnErrorWhenCallerIsNotAuthorized()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.Configure(options => options.IgnoreEndpointPermissions = false);

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("id_token", context.Token);
                    Assert.Equal([TokenTypeHints.IdToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.IdToken)
                        .SetPresenters("Contoso")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2141), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2141), response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_RequestIsValidatedWhenIdentityTokenHintIsExpired()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Endpoints.Authorization, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Configure(options => options.IgnoreEndpointPermissions = false);

            options.Services.AddSingleton(manager);

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("id_token", context.Token);
                    Assert.Equal([TokenTypeHints.IdToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.IdToken)
                        .SetPresenters("Fabrikam")
                        .SetExpirationDate(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero))
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("Bob le Bricoleur", context.IdentityTokenHintPrincipal
                        ?.FindFirst(Claims.Subject)?.Value);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Null(response.Code);
        Assert.NotNull(response.AccessToken);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application, Permissions.Endpoints.Authorization, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ValidateAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ValidateAuthorizationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task HandleAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task HandleAuthorizationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleAuthorizationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleAuthorizationRequest_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    context.Parameters["custom_parameter"] = "custom_value";
                    context.Parameters["parameter_with_multiple_values"] = new[]
                    {
                        "custom_value_1",
                        "custom_value_2"
                    };

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.AccessToken);
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
        Assert.Equal(["custom_value_1", "custom_value_2"], (string[]?) response["parameter_with_multiple_values"]);
    }

    [Theory]
    [InlineData("code", ResponseModes.Query)]
    [InlineData("code id_token", ResponseModes.Fragment)]
    [InlineData("code id_token token", ResponseModes.Fragment)]
    [InlineData("code token", ResponseModes.Fragment)]
    [InlineData("id_token", ResponseModes.Fragment)]
    [InlineData("id_token token", ResponseModes.Fragment)]
    [InlineData("token", ResponseModes.Fragment)]
    public async Task ApplyAuthorizationResponse_ResponseModeIsAutomaticallyInferred(string type, string mode)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response["inferred_response_mode"] = context.ResponseMode;

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(mode, (string?) response["inferred_response_mode"]);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response["custom_parameter"] = "custom_value";
                    context.Response["parameter_with_multiple_values"] = new[]
                    {
                        "custom_value_1",
                        "custom_value_2"
                    };

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
        Assert.Equal(["custom_value_1", "custom_value_2"], (string[]?) response["parameter_with_multiple_values"]);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_ThrowsAnExceptionWhenRequestIsMissing()
    {
        // Note: an exception is only thrown if the request was not properly extracted
        // AND if the developer decided to override the error to return a custom response.
        // To emulate this behavior, the error property is manually set to null.

        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response.Error = null;

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.SendAsync(HttpMethod.Put, "/connect/authorize", new OpenIddictRequest());
        });

        Assert.Equal(SR.GetResourceString(SR.ID0030), exception.Message);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_DoesNotSetStateWhenUserIsNotRedirected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ResponseType = ResponseTypes.Code,
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.Null(response.State);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_FlowsStateWhenRedirectUriIsUsed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.Equal("af0ifjsldkj", response.State);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_DoesNotOverrideStateSetByApplicationCode()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response.State = "custom_state";

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.Equal("custom_state", response.State);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("http://www.fabrikam.com/")]
    public async Task ApplyAuthorizationResponse_SetsIssuerParameter(string? issuer)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            if (!string.IsNullOrEmpty(issuer))
            {
                options.SetIssuer(new Uri(issuer, UriKind.Absolute));
            }

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.Equal(!string.IsNullOrEmpty(issuer) ? issuer : "http://localhost/", response.Iss);
    }

    [Fact]
    public async Task ApplyAuthorizationResponse_DoesNotOverrideIssuerSetByApplicationCode()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetIssuer(new Uri("http://www.fabrikam.com/", UriKind.Absolute));

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ApplyAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response.Iss = "http://www.contoso.com/";

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.Equal("http://www.contoso.com/", response.Iss);
    }

    [Theory]
    [InlineData(nameof(HttpMethod.Delete))]
    [InlineData(nameof(HttpMethod.Get))]
    [InlineData(nameof(HttpMethod.Head))]
    [InlineData(nameof(HttpMethod.Options))]
    [InlineData(nameof(HttpMethod.Put))]
    [InlineData(nameof(HttpMethod.Trace))]
    public async Task ExtractPushedAuthorizationRequest_UnexpectedMethodReturnsAnError(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendAsync(method, "/connect/par", new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2084), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2084), response.ErrorUri);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ExtractPushedAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractPushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest());

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ExtractPushedAuthorizationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractPushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ExtractPushedAuthorizationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractPushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task ExtractPushedAuthorizationRequest_UnsupportedRequestParameterIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            Request = "eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwOi8vd3d3LmZhYnJpa2FtLmNvbSIsImF1ZCI6Imh0" +
                      "dHA6Ly93d3cuY29udG9zby5jb20iLCJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6" +
                      "IkZhYnJpa2FtIiwicmVkaXJlY3RfdXJpIjoiaHR0cDovL3d3dy5mYWJyaWthbS5jb20vcGF0aCJ9.",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.RequestNotSupported, response.Error);
        Assert.Equal(SR.FormatID2028(Parameters.Request), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2028), response.ErrorUri);
    }

    [Fact]
    public async Task ExtractPushedAuthorizationRequest_ForbiddenRequestUriParameterIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            RequestUri = "http://www.fabrikam.com/request/GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2074(Parameters.RequestUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2074), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_MissingClientIdCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = null
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_MissingRedirectUriCausesAnErrorForOpenIdRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = null,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Theory]
    [InlineData("/path", SR.ID2030)]
    [InlineData("/tmp/file.xml", SR.ID2030)]
    [InlineData("C:\\tmp\\file.xml", SR.ID2030)]
    [InlineData("http://www.fabrikam.com/path#param=value", SR.ID2031)]
    public async Task ValidatePushedAuthorizationRequest_InvalidRedirectUriCausesAnError(string uri, string message)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = uri,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(string.Format(SR.GetResourceString(message), Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(message), response.ErrorUri);
    }

    [Theory]
    [InlineData("http://www.fabrikam.com/path?iss")]
    [InlineData("http://www.fabrikam.com/path?iss=value")]
    [InlineData("http://www.fabrikam.com/path?;iss")]
    [InlineData("http://www.fabrikam.com/path?;iss=value")]
    [InlineData("http://www.fabrikam.com/path?&iss")]
    [InlineData("http://www.fabrikam.com/path?&iss=value")]
    [InlineData("http://www.fabrikam.com/path?state;iss")]
    [InlineData("http://www.fabrikam.com/path?state;iss=value")]
    [InlineData("http://www.fabrikam.com/path?state&iss")]
    [InlineData("http://www.fabrikam.com/path?state&iss=value")]
    [InlineData("http://www.fabrikam.com/path?state=abc;iss")]
    [InlineData("http://www.fabrikam.com/path?state=abc;iss=value")]
    [InlineData("http://www.fabrikam.com/path?state=abc&iss")]
    [InlineData("http://www.fabrikam.com/path?state=abc&iss=value")]
    public async Task ValidatePushedAuthorizationRequest_RedirectUriWithIssuerParameterCausesAnError(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = uri,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2135(Parameters.RedirectUri, Parameters.Iss), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2135), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_MissingResponseTypeCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = null,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token", ResponseModes.Query)]
    [InlineData("code id_token token", ResponseModes.Query)]
    [InlineData("code token", ResponseModes.Query)]
    [InlineData("id_token", ResponseModes.Query)]
    [InlineData("id_token token", ResponseModes.Query)]
    [InlineData("token", ResponseModes.Query)]
    public async Task ValidatePushedAuthorizationRequest_UnsafeResponseModeCausesAnError(string type, string mode)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = mode,
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2033(Parameters.ResponseType, Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2033), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ValidatePushedAuthorizationRequest_MissingNonceCausesAnErrorForOpenIdRequests(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.Nonce), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    public async Task ValidatePushedAuthorizationRequest_MissingOpenIdScopeCausesAnErrorForOpenIdRequests(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2034(Scopes.OpenId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2034), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_UnsupportedPromptCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.PromptValues.Remove(PromptValues.SelectAccount));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            Prompt = PromptValues.SelectAccount,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = "code id_token token",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.Prompt), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData("none")]
    [InlineData("consent")]
    [InlineData("login")]
    [InlineData("select_account")]
    [InlineData("consent login")]
    [InlineData("consent select_account")]
    [InlineData("login select_account")]
    [InlineData("consent login select_account")]
    public async Task ValidatePushedAuthorizationRequest_ValidPromptDoesNotCauseAnError(string prompt)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            Prompt = prompt,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = "code id_token token",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.RequestUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenPkceIsRequiredAndCodeChallengeIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.RequireProofKeyForCodeExchange();
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.CodeChallenge), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenPkceIsNotRequiredAndCodeChallengeIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.RequestUri);
    }

    [Theory]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ValidatePushedAuthorizationRequest_MissingCodeResponseTypeCausesAnErrorWhenCodeChallengeIsUsed(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2040(Parameters.CodeChallenge, Parameters.CodeChallengeMethod, ResponseTypes.Code), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2040), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_MissingCodeChallengeCausesAnErrorWhenCodeChallengeMethodIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2037(Parameters.CodeChallengeMethod, Parameters.CodeChallenge), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2037), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_InvalidCodeChallengeMethodCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = "invalid_code_challenge_method",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.CodeChallengeMethod), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_UnknownResponseTypeParameterIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = "unknown_response_type"
        });

        // Assert
        Assert.Equal(Errors.UnsupportedResponseType, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData(GrantTypes.AuthorizationCode, "code")]
    [InlineData(GrantTypes.AuthorizationCode, "code id_token")]
    [InlineData(GrantTypes.AuthorizationCode, "code id_token token")]
    [InlineData(GrantTypes.AuthorizationCode, "code token")]
    [InlineData(GrantTypes.Implicit, "code id_token")]
    [InlineData(GrantTypes.Implicit, "code id_token token")]
    [InlineData(GrantTypes.Implicit, "code token")]
    [InlineData(GrantTypes.Implicit, "id_token")]
    [InlineData(GrantTypes.Implicit, "id_token token")]
    [InlineData(GrantTypes.Implicit, "token")]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenGrantTypeIsDisabled(string flow, string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.GrantTypes.Remove(flow));
            options.Configure(options => options.ResponseTypes.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnsupportedResponseType, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData("code")]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("none")]
    [InlineData("token")]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenResponseTypeIsDisabled(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.ResponseTypes.Remove(type));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnsupportedResponseType, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData("none code")]
    [InlineData("none code id_token")]
    [InlineData("none code id_token token")]
    [InlineData("none code token")]
    [InlineData("none id_token")]
    [InlineData("none id_token token")]
    [InlineData("none token")]
    public async Task ValidatePushedAuthorizationRequest_InvalidResponseTypeParameterIsRejected(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_UnsupportedResponseModeCausesAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = "unsupported_response_mode",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenUnregisteredScopeIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                var application = new OpenIddictApplication();

                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);
            }));

            options.Services.AddSingleton(CreateScopeManager(mock =>
            {
                mock.Setup(manager => manager.FindByNamesAsync(
                    It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "unregistered_scope"),
                    It.IsAny<CancellationToken>()))
                    .Returns(AsyncEnumerable.Empty<OpenIddictScope>());
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = "unregistered_scope"
        });

        // Assert
        Assert.Equal(Errors.InvalidScope, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.Scope), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenScopeRegisteredInOptionsIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.RegisterScopes("registered_scope");
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token,
            Scope = "registered_scope"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.RequestUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenRegisteredScopeIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            var scope = new OpenIddictScope();

            options.RegisterScopes("scope_registered_in_options");
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                var application = new OpenIddictApplication();

                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableDictionary.Create<string, string>());
            }));

            options.Services.AddSingleton(CreateScopeManager(mock =>
            {
                mock.Setup(manager => manager.FindByNamesAsync(
                    It.Is<ImmutableArray<string>>(scopes => scopes.Length == 1 && scopes[0] == "scope_registered_in_database"),
                    It.IsAny<CancellationToken>()))
                    .Returns(new[] { scope }.ToAsyncEnumerable());

                mock.Setup(manager => manager.GetNameAsync(scope, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("scope_registered_in_database");
            }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token,
            Scope = "scope_registered_in_database scope_registered_in_options"
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.RequestUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenFlowIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.Configure(options => options.GrantTypes.Remove(GrantTypes.RefreshToken));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OfflineAccess
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2035(Scopes.OfflineAccess), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2035), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_UnknownResponseModeParameterIsRejected()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseMode = "unknown_response_mode",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.ResponseMode), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenCodeChallengeMethodIsMissingAndPlainIsNotSupported()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.Services.PostConfigure<OpenIddictServerOptions>(options =>
                options.CodeChallengeMethods.Remove(CodeChallengeMethods.Plain));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.CodeChallengeMethod), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenCodeChallengeMethodIsNotEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.Services.PostConfigure<OpenIddictServerOptions>(options =>
                options.CodeChallengeMethods.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2032(Parameters.CodeChallengeMethod), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2032), response.ErrorUri);
    }

    [Theory]
    [InlineData(CodeChallengeMethods.Plain)]
    [InlineData(CodeChallengeMethods.Sha256)]
    [InlineData("custom_code_challenge_method")]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenCodeChallengeMethodIsRegistered(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.Configure(options => options.CodeChallengeMethods.Clear());
            options.Configure(options => options.CodeChallengeMethods.Add(method));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = method,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.RequestUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenRedirectUriIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = null,
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2029(Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2029), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_MissingRedirectUriCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/par", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = null,
                ResponseType = ResponseTypes.Code
            });
        });

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID0028), exception.Message);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_InvalidRedirectUriCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidatePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SetRedirectUri("http://www.contoso.com/path");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/par", new OpenIddictRequest
            {
                ClientId = "Fabrikam",
                RedirectUri = "http://www.fabrikam.com/path",
                ResponseType = ResponseTypes.Code
            });
        });

        // Assert
        Assert.Equal(SR.GetResourceString(SR.ID0101), exception.Message);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenClientCannotBeFound()
    {
        // Arrange
        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(value: null);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2052(Parameters.ClientId), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2052), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    public async Task ValidatePushedAuthorizationRequest_PkceRequestWithSensitiveResponseTypeIsRejectedWhenDegradedModeIsEnabled(string type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.FormatID2041(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2041), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    public async Task ValidatePushedAuthorizationRequest_PkceRequestWithSensitiveResponseTypeIsRejectedWhenPermissionsAreIgnored(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options => options.Services.AddSingleton(manager));
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.FormatID2041(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2041), response.ErrorUri);
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    public async Task ValidatePushedAuthorizationRequest_PkceRequestWithSensitiveResponseTypeIsValidatedWhenPermissionsAreEnforced(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableArray.Create("rst:" + type));

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Configure(options => options.IgnoreResponseTypePermissions = false);

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.RequestUri);
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ValidatePushedAuthorizationRequest_AnAccessTokenIsNotReturnedWhenClientIsConfidential(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableArray<string>.Empty);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.FormatID2043(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2043), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasClientTypeAsync(application, ClientTypes.Confidential, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenEndpointPermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Endpoints.PushedAuthorization, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreEndpointPermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2183), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2183), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Endpoints.PushedAuthorization, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData(
        "code",
        new[] { Permissions.GrantTypes.AuthorizationCode },
        SR.ID2047)]
    [InlineData(
        "code id_token",
        new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
        SR.ID2049)]
    [InlineData(
        "code id_token token",
        new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
        SR.ID2049)]
    [InlineData(
        "code token",
        new[] { Permissions.GrantTypes.AuthorizationCode, Permissions.GrantTypes.Implicit },
        SR.ID2049)]
    [InlineData(
        "id_token",
        new[] { Permissions.GrantTypes.Implicit },
        SR.ID2048)]
    [InlineData(
        "id_token token",
        new[] { Permissions.GrantTypes.Implicit },
        SR.ID2048)]
    [InlineData(
        "token",
        new[] { Permissions.GrantTypes.Implicit },
        SR.ID2048)]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenGrantTypePermissionIsNotGranted(
        string type, string[] permissions, string description)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            foreach (var permission in permissions)
            {
                mock.Setup(manager => manager.HasPermissionAsync(application, permission, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(false);
            }
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreGrantTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.GetResourceString(description), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(description), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application, permissions[0], It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData("code")]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    [InlineData("none")]
    [InlineData("token")]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenResponseTypePermissionIsNotGranted(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableArray<string>.Empty);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreResponseTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.UnauthorizedClient, response.Error);
        Assert.Equal(SR.FormatID2043(Parameters.ResponseType), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2043), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenExplicitPermissionIsGranted(string type)
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableArray.Create("rst:" + type));

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Configure(options => options.IgnoreResponseTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = type,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.RequestUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.GetPermissionsAsync(application, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestWithOfflineAccessScopeIsRejectedWhenRefreshTokenPermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.AuthorizationCode, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);

            options.Configure(options => options.IgnoreGrantTypePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OfflineAccess
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2065(Scopes.OfflineAccess), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2065), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.GrantTypes.RefreshToken, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenRedirectUriIsInvalid()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2043(Parameters.RedirectUri), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2043), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenScopePermissionIsNotGranted()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.Profile, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Prefixes.Scope + Scopes.Email, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
            options.RegisterScopes(Scopes.Email, Scopes.Profile);
            options.Configure(options => options.IgnoreScopePermissions = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = "openid offline_access profile email"
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2051), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2051), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.OpenId, It.IsAny<CancellationToken>()), Times.Never());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.OfflineAccess, It.IsAny<CancellationToken>()), Times.Never());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.Profile, It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application,
            Permissions.Prefixes.Scope + Scopes.Email, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsRejectedWhenCodeChallengeIsMissingWithPkceFeatureEnforced()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = null,
            CodeChallengeMethod = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.FormatID2054(Parameters.CodeChallenge), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2054), response.ErrorUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenCodeChallengeIsMissingWithPkceFeatureNotEnforced()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = null,
            CodeChallengeMethod = null,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.NotNull(response.RequestUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenCodeChallengeIsPresentWithPkceFeatureEnforced()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            CodeChallengeMethod = CodeChallengeMethods.Sha256,
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code
        });

        // Assert
        Assert.NotNull(response.RequestUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenCodeIsNotRequestedWithPkceFeatureEnforced()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasRequirementAsync(application,
                Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Null(response.Code);
        Assert.NotNull(response.RequestUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.HasRequirementAsync(application,
            Requirements.Features.ProofKeyForCodeExchange, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_InvalidIdentityTokenHintDoesNotCauseAnError()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandlePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Null(context.IdentityTokenHintPrincipal);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Null(response.Code);
        Assert.NotNull(response.RequestUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_InvalidIdentityTokenHintCausesAnErrorWhenRejectionIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.RejectIdentityToken = true;

                    return default;
                });

                builder.SetOrder(EvaluateValidatedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Equal(Errors.InvalidToken, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2009), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2009), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_IdentityTokenHintCausesAnErrorWhenCallerIsNotAuthorized()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.Configure(options => options.IgnoreEndpointPermissions = false);

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("id_token", context.Token);
                    Assert.Equal([TokenTypeHints.IdToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.IdToken)
                        .SetPresenters("Contoso")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2141), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2141), response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_RequestIsValidatedWhenIdentityTokenHintIsExpired()
    {
        // Arrange
        var application = new OpenIddictApplication();

        var manager = CreateApplicationManager(mock =>
        {
            mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                .ReturnsAsync(application);

            mock.Setup(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.HasPermissionAsync(application,
                Permissions.Endpoints.PushedAuthorization, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                .ReturnsAsync(ImmutableDictionary.Create<string, string>());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.DisableAuthorizationStorage();
            options.DisableTokenStorage();
            options.DisableSlidingRefreshTokenExpiration();

            options.Configure(options => options.IgnoreEndpointPermissions = false);

            options.Services.AddSingleton(manager);

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("id_token", context.Token);
                    Assert.Equal([TokenTypeHints.IdToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.IdToken)
                        .SetPresenters("Fabrikam")
                        .SetExpirationDate(new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero))
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<HandlePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("Bob le Bricoleur", context.IdentityTokenHintPrincipal
                        ?.FindFirst(Claims.Subject)?.Value);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Null(response.Code);
        Assert.NotNull(response.RequestUri);

        Mock.Get(manager).Verify(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.ValidateRedirectUriAsync(application, "http://www.fabrikam.com/path", It.IsAny<CancellationToken>()), Times.Once());
        Mock.Get(manager).Verify(manager => manager.HasPermissionAsync(application, Permissions.Endpoints.PushedAuthorization, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ValidatePushedAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidatePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidatePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ValidatePushedAuthorizationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidatePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task HandlePushedAuthorizationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandlePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task HandlePushedAuthorizationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandlePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task HandlePushedAuthorizationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandlePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task HandlePushedAuthorizationRequest_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandlePushedAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Parameters["custom_parameter"] = "custom_value";
                    context.Parameters["parameter_with_multiple_values"] = new[]
                    {
                        "custom_value_1",
                        "custom_value_2"
                    };

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Token
        });

        // Assert
        Assert.Null(response.Error);
        Assert.Null(response.ErrorDescription);
        Assert.Null(response.ErrorUri);
        Assert.NotNull(response.RequestUri);
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
        Assert.Equal(["custom_value_1", "custom_value_2"], (string[]?) response["parameter_with_multiple_values"]);
    }

    [Fact]
    public async Task ApplyPushedAuthorizationResponse_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ApplyPushedAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Transaction.SetProperty("custom_response", new
                    {
                        name = "Bob le Bricoleur"
                    });

                    context.HandleRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ApplyPushedAuthorizationResponse_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ApplyPushedAuthorizationResponseContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Response["custom_parameter"] = "custom_value";
                    context.Response["parameter_with_multiple_values"] = new[]
                    {
                        "custom_value_1",
                        "custom_value_2"
                    };

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/par", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
        Assert.Equal(["custom_value_1", "custom_value_2"], (string[]?) response["parameter_with_multiple_values"]);
    }
}

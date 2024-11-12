/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenIddict.Server.IntegrationTests;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Server.AspNetCore.IntegrationTests;

public partial class OpenIddictServerAspNetCoreIntegrationTests : OpenIddictServerIntegrationTests
{
    public OpenIddictServerAspNetCoreIntegrationTests(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task ProcessAuthentication_CreationDateIsMappedToIssuedUtc()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate/properties");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeHints.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetCreationDate(new DateTimeOffset(2020, 01, 01, 00, 00, 00, TimeSpan.Zero));

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate/properties", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        var properties = new AuthenticationProperties(response.GetParameters()
            .ToDictionary(parameter => parameter.Key, parameter => (string?) parameter.Value));

        Assert.Equal(new DateTimeOffset(2020, 01, 01, 00, 00, 00, TimeSpan.Zero), properties.IssuedUtc);
    }

    [Fact]
    public async Task ProcessAuthentication_ExpirationDateIsMappedToIssuedUtc()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate/properties");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("access_token", context.Token);
                    Assert.Equal([TokenTypeHints.AccessToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AccessToken)
                        .SetExpirationDate(new DateTimeOffset(2120, 01, 01, 00, 00, 00, TimeSpan.Zero));

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate/properties", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        var properties = new AuthenticationProperties(response.GetParameters()
            .ToDictionary(parameter => parameter.Key, parameter => (string?) parameter.Value));

        Assert.Equal(new DateTimeOffset(2120, 01, 01, 00, 00, 00, TimeSpan.Zero), properties.ExpiresUtc);
    }

    [Fact]
    public async Task ProcessAuthentication_CustomPropertiesAreAddedForErroredAuthenticationResults()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetAuthorizationEndpointUris("/authenticate/properties");

            options.UseAspNetCore()
                   .EnableErrorPassthrough()
                   .EnableAuthorizationEndpointPassthrough();

            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.RejectIdentityToken = true;

                    context.Properties["custom_property"] = "value";

                    return default;
                });

                builder.SetOrder(EvaluateValidatedTokens.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate/properties", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            IdTokenHint = "id_token_hint",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = "id_token",
            Scope = Scopes.OpenId
        });

        // Assert
        var properties = new AuthenticationProperties(response.GetParameters()
            .ToDictionary(parameter => parameter.Key, parameter => (string?) parameter.Value));

        Assert.Equal("value", properties.Items["custom_property"]);
    }

    [Fact]
    public async Task ProcessChallenge_ImportsAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessChallengeContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("value", context.Properties["custom_property"]);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotNull(response.Error);
        Assert.NotNull(response.ErrorDescription);
        Assert.NotNull(response.ErrorUri);
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsParametersFromAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.True((bool) response["boolean_parameter"]);
        Assert.Equal(JsonValueKind.True, ((JsonElement) response["boolean_parameter"]).ValueKind);
        Assert.Equal(42, (long) response["integer_parameter"]);
        Assert.Equal(JsonValueKind.Number, ((JsonElement) response["integer_parameter"]).ValueKind);
        Assert.Equal("Bob l'Eponge", (string?) response["string_parameter"]);
        Assert.Equal(JsonValueKind.String, ((JsonElement) response["string_parameter"]).ValueKind);
        Assert.Equal(["Contoso", "Fabrikam"], (string[]?) response["array_parameter"]);
        Assert.Equal(JsonValueKind.Array, ((JsonElement) response["array_parameter"]).ValueKind);
        Assert.Equal("value", (string?) response["object_parameter"]?["parameter"]);
        Assert.Equal(JsonValueKind.Object, ((JsonElement) response["object_parameter"]).ValueKind);

#if SUPPORTS_JSON_NODES
        Assert.Equal(["Contoso", "Fabrikam"], (string[]?) response["node_array_parameter"]);
        Assert.IsType<JsonArray>((JsonNode?) response["node_array_parameter"]);
        Assert.Equal("value", (string?) response["node_object_parameter"]?["parameter"]);
        Assert.IsType<JsonObject>((JsonNode?) response["node_object_parameter"]);
#endif
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsErrorFromAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal("custom_error", response.Error);
        Assert.Equal("custom_error_description", response.ErrorDescription);
        Assert.Equal("custom_error_uri", response.ErrorUri);
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/connect/authorize")]
    [InlineData("/connect/device")]
    [InlineData("/connect/introspect")]
    [InlineData("/connect/endsession")]
    [InlineData("/connect/revoke")]
    [InlineData("/connect/token")]
    [InlineData("/connect/userinfo")]
    [InlineData("/connect/verification")]
    public async Task ProcessRequest_RejectsInsecureHttpRequests(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.UseAspNetCore()
                   .Configure(options => options.DisableTransportSecurityRequirement = false);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync(uri, new OpenIddictRequest());

        // Assert
        Assert.Equal(Errors.InvalidRequest, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2083), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2083), response.ErrorUri);
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/custom")]
    [InlineData("/connect/authorize")]
    [InlineData("/connect/device")]
    [InlineData("/connect/introspect")]
    [InlineData("/connect/endsession")]
    [InlineData("/connect/revoke")]
    [InlineData("/connect/token")]
    [InlineData("/connect/userinfo")]
    [InlineData("/connect/verification")]
    public async Task ProcessRequest_AllowsHandlingResponse(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessRequestContext>(builder =>
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
        var response = await client.PostAsync(uri, new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    [InlineData("/custom")]
    [InlineData("/connect/authorize")]
    [InlineData("/connect/device")]
    [InlineData("/connect/introspect")]
    [InlineData("/connect/endsession")]
    [InlineData("/connect/revoke")]
    [InlineData("/connect/token")]
    [InlineData("/connect/userinfo")]
    [InlineData("/connect/verification")]
    public async Task ProcessRequest_AllowsSkippingHandler(string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync(uri, new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task ProcessSignIn_ImportsAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/signin/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("value", context.Properties["custom_property"]);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/signin/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_ReturnsParametersFromAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/signin/custom");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/signin/custom", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.True((bool) response["boolean_parameter"]);
        Assert.Equal(JsonValueKind.True, ((JsonElement) response["boolean_parameter"]).ValueKind);
        Assert.Equal(42, (long) response["integer_parameter"]);
        Assert.Equal(JsonValueKind.Number, ((JsonElement) response["integer_parameter"]).ValueKind);
        Assert.Equal("Bob l'Eponge", (string?) response["string_parameter"]);
        Assert.Equal(JsonValueKind.String, ((JsonElement) response["string_parameter"]).ValueKind);
        Assert.Equal(["Contoso", "Fabrikam"], (string[]?) response["array_parameter"]);
        Assert.Equal(JsonValueKind.Array, ((JsonElement) response["array_parameter"]).ValueKind);
        Assert.Equal("value", (string?) response["object_parameter"]?["parameter"]);
        Assert.Equal(JsonValueKind.Object, ((JsonElement) response["object_parameter"]).ValueKind);

#if SUPPORTS_JSON_NODES
        Assert.Equal(["Contoso", "Fabrikam"], (string[]?) response["node_array_parameter"]);
        Assert.IsType<JsonArray>((JsonNode?) response["node_array_parameter"]);
        Assert.Equal("value", (string?) response["node_object_parameter"]?["parameter"]);
        Assert.IsType<JsonObject>((JsonNode?) response["node_object_parameter"]);
#endif
    }

    [Fact]
    public async Task ProcessSignOut_ImportsAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetEndSessionEndpointUris("/signout/custom");

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessSignOutContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("value", context.Properties["custom_property"]);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/signout/custom", new OpenIddictRequest
        {
            PostLogoutRedirectUri = "http://www.fabrikam.com/path",
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.NotNull(response.State);
    }

    [Fact]
    public async Task ProcessSignOut_ReturnsParametersFromAuthenticationProperties()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetEndSessionEndpointUris("/signout/custom");

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/signout/custom", new OpenIddictRequest
        {
            PostLogoutRedirectUri = "http://www.fabrikam.com/path",
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.True((bool) response["boolean_parameter"]);
        Assert.Equal(42, (long) response["integer_parameter"]);
        Assert.Equal("Bob l'Eponge", (string?) response["string_parameter"]);
    }

    protected override
#if SUPPORTS_WEB_INTEGRATION_IN_GENERIC_HOST
        async
#endif
        ValueTask<OpenIddictServerIntegrationTestServer> CreateServerAsync(Action<OpenIddictServerBuilder>? configuration = null)
    {
#if SUPPORTS_WEB_INTEGRATION_IN_GENERIC_HOST
        var builder = new HostBuilder();
#else
        var builder = new WebHostBuilder();
#endif
        builder.UseEnvironment("Testing");

        builder.ConfigureLogging(options => options.AddXUnit(OutputHelper));

        builder.ConfigureServices(ConfigureServices);
        builder.ConfigureServices(services =>
        {
            services.AddOpenIddict()
                .AddServer(options =>
                {
                    // Disable the transport security requirement during testing.
                    options.UseAspNetCore()
                           .DisableTransportSecurityRequirement();

                    configuration?.Invoke(options);
                });
        });

#if SUPPORTS_WEB_INTEGRATION_IN_GENERIC_HOST
        builder.ConfigureWebHost(options =>
        {
            options.UseTestServer();
            options.Configure(ConfigurePipeline);
        });
#else
        builder.Configure(ConfigurePipeline);
#endif

#if SUPPORTS_WEB_INTEGRATION_IN_GENERIC_HOST
        var host = await builder.StartAsync();

        return new OpenIddictServerAspNetCoreIntegrationTestServer(host);
#else
        var server = new TestServer(builder);

        return new(new OpenIddictServerAspNetCoreIntegrationTestServer(server));
#endif

        void ConfigurePipeline(IApplicationBuilder app)
        {
            app.Use(next => async context =>
            {
                await next(context);

                var feature = context.Features.Get<OpenIddictServerAspNetCoreFeature>();
                var response = feature?.Transaction?.GetProperty<object>("custom_response");
                if (response is not null)
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                }
            });

            app.UseAuthentication();

            app.Use(next => async context =>
            {
                if (context.Request.Path == "/signin")
                {
                    var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    identity.AddClaim(Claims.Subject, "Bob le Bricoleur");

                    var principal = new ClaimsPrincipal(identity);

                    await context.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal);
                    return;
                }

                else if (context.Request.Path == "/signin/custom")
                {
                    var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    identity.AddClaim(Claims.Subject, "Bob le Bricoleur");

                    var principal = new ClaimsPrincipal(identity);

                    var properties = new AuthenticationProperties(
                        items: new Dictionary<string, string?>
                        {
                            ["custom_property"] = "value"
                        },
                        parameters: new Dictionary<string, object?>
                        {
                            ["boolean_parameter"] = true,
                            ["integer_parameter"] = 42,
                            ["string_parameter"] = "Bob l'Eponge",
                            ["array_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]"),
                            ["object_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"),
#if SUPPORTS_JSON_NODES
                            ["node_array_parameter"] = new JsonArray("Contoso", "Fabrikam"),
                            ["node_object_parameter"] = new JsonObject { ["parameter"] = "value" }
#endif
                        });

                    await context.SignInAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, principal, properties);
                    return;
                }

                else if (context.Request.Path == "/signout")
                {
                    await context.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    return;
                }

                else if (context.Request.Path == "/signout/custom")
                {
                    var properties = new AuthenticationProperties(
                        items: new Dictionary<string, string?>
                        {
                            ["custom_property"] = "value"
                        },
                        parameters: new Dictionary<string, object?>
                        {
                            ["boolean_parameter"] = true,
                            ["integer_parameter"] = 42,
                            ["string_parameter"] = "Bob l'Eponge"
                        });

                    await context.SignOutAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties);
                    return;
                }

                else if (context.Request.Path == "/challenge")
                {
                    await context.ChallengeAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    return;
                }

                else if (context.Request.Path == "/challenge/custom")
                {
                    var properties = new AuthenticationProperties(
                        items: new Dictionary<string, string?>
                        {
                            [OpenIddictServerAspNetCoreConstants.Properties.Error] = "custom_error",
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "custom_error_description",
                            [OpenIddictServerAspNetCoreConstants.Properties.ErrorUri] = "custom_error_uri",

                            ["custom_property"] = "value"
                        },
                        parameters: new Dictionary<string, object?>
                        {
                            ["boolean_parameter"] = true,
                            ["integer_parameter"] = 42,
                            ["string_parameter"] = "Bob l'Eponge",
                            ["array_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]"),
                            ["object_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}"),
#if SUPPORTS_JSON_NODES
                            ["node_array_parameter"] = new JsonArray("Contoso", "Fabrikam"),
                            ["node_object_parameter"] = new JsonObject { ["parameter"] = "value" }
#endif
                        });

                    await context.ChallengeAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme, properties);
                    return;
                }

                else if (context.Request.Path == "/authenticate")
                {
                    var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    if (result?.Principal is null)
                    {
                        return;
                    }

                    var claims = result.Principal.Claims.GroupBy(claim => claim.Type)
                        .Select(group => new KeyValuePair<string, string?[]?>(
                            group.Key, group.Select(claim => claim.Value).ToArray()));

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new OpenIddictResponse(claims)));
                    return;
                }

                else if (context.Request.Path == "/authenticate/properties")
                {
                    var result = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                    if (result?.Properties is null)
                    {
                        return;
                    }

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new OpenIddictResponse(result.Properties.Items)));
                    return;
                }

                await next(context);
            });

            app.Run(context =>
            {
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    name = "Bob le Magnifique"
                }));
            });
        }
    }
}

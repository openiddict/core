/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Testing;
using OpenIddict.Server.IntegrationTests;
using Owin;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

namespace OpenIddict.Server.Owin.IntegrationTests;

public partial class OpenIddictServerOwinIntegrationTests : OpenIddictServerIntegrationTests
{
    public OpenIddictServerOwinIntegrationTests(ITestOutputHelper outputHelper)
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

            options.UseOwin()
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

        Assert.Equal("value", properties.Dictionary["custom_property"]);
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
        Assert.NotEmpty(response.Error);
        Assert.NotEmpty(response.ErrorDescription);
        Assert.NotEmpty(response.ErrorUri);
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
        Assert.Equal(["Contoso", "Fabrikam"], (string[]?) response["json_parameter"]);
        Assert.Equal(JsonValueKind.Array, ((JsonElement) response["json_parameter"]).ValueKind);
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

            options.UseOwin()
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
        Assert.NotEmpty(response.AccessToken);
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
        Assert.Equal(["Contoso", "Fabrikam"], (string[]?) response["json_parameter"]);
        Assert.Equal(JsonValueKind.Array, ((JsonElement) response["json_parameter"]).ValueKind);
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
        Assert.NotEmpty(response.State);
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

    protected override ValueTask<OpenIddictServerIntegrationTestServer> CreateServerAsync(Action<OpenIddictServerBuilder>? configuration = null)
    {
        var services = new ServiceCollection();
        ConfigureServices(services);

        services.AddLogging(options => options.AddXUnit(OutputHelper));

        services.AddOpenIddict()
            .AddServer(options =>
            {
                // Disable the transport security requirement during testing.
                options.UseOwin()
                       .DisableTransportSecurityRequirement();

                configuration?.Invoke(options);
            });

        var provider = services.BuildServiceProvider();

        var server = TestServer.Create(app =>
        {
            app.Use(async (context, next) =>
            {
                using var scope = provider.CreateScope();

                context.Set(typeof(IServiceProvider).FullName, scope.ServiceProvider);

                try
                {
                    await next();
                }

                finally
                {
                    context.Environment.Remove(typeof(IServiceProvider).FullName);
                }
            });

            app.Use(async (context, next) =>
            {
                await next();

                var transaction = context.Get<OpenIddictServerTransaction>(typeof(OpenIddictServerTransaction).FullName);
                var response = transaction?.GetProperty<object>("custom_response");
                if (response is not null)
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                }
            });

            app.UseOpenIddictServer();

            app.Use(async (context, next) =>
            {
                if (context.Request.Path == new PathString("/signin"))
                {
                    var identity = new ClaimsIdentity(OpenIddictServerOwinDefaults.AuthenticationType);
                    identity.AddClaim(Claims.Subject, "Bob le Bricoleur");

                    context.Authentication.SignIn(identity);
                    return;
                }

                else if (context.Request.Path == new PathString("/signin/custom"))
                {
                    var identity = new ClaimsIdentity(OpenIddictServerOwinDefaults.AuthenticationType);
                    identity.AddClaim(Claims.Subject, "Bob le Bricoleur");

                    var principal = new ClaimsPrincipal(identity);

                    var properties = new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        ["custom_property"] = "value",

                        ["boolean_parameter#boolean"] = "true",
                        ["integer_parameter#integer"] = "42",
                        ["string_parameter#string"] = "Bob l'Eponge",
                        ["json_parameter#json"] = @"[""Contoso"",""Fabrikam""]"
                    });

                    context.Authentication.SignIn(properties, identity);
                    return;
                }

                else if (context.Request.Path == new PathString("/signout"))
                {
                    context.Authentication.SignOut(OpenIddictServerOwinDefaults.AuthenticationType);
                    return;
                }

                else if (context.Request.Path == new PathString("/signout/custom"))
                {

                    var properties = new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        ["custom_property"] = "value",

                        ["boolean_parameter#boolean"] = "true",
                        ["integer_parameter#integer"] = "42",
                        ["string_parameter#string"] = "Bob l'Eponge"
                    });

                    context.Authentication.SignOut(properties, OpenIddictServerOwinDefaults.AuthenticationType);
                    return;
                }

                else if (context.Request.Path == new PathString("/challenge"))
                {
                    context.Authentication.Challenge(OpenIddictServerOwinDefaults.AuthenticationType);
                    return;
                }

                else if (context.Request.Path == new PathString("/challenge/custom"))
                {
                    var properties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        [OpenIddictServerOwinConstants.Properties.Error] = "custom_error",
                        [OpenIddictServerOwinConstants.Properties.ErrorDescription] = "custom_error_description",
                        [OpenIddictServerOwinConstants.Properties.ErrorUri] = "custom_error_uri",

                        ["custom_property"] = "value",

                        ["boolean_parameter#boolean"] = "true",
                        ["integer_parameter#integer"] = "42",
                        ["string_parameter#string"] = "Bob l'Eponge",
                        ["json_parameter#json"] = @"[""Contoso"",""Fabrikam""]"
                    });

                    context.Authentication.Challenge(properties, OpenIddictServerOwinDefaults.AuthenticationType);
                    return;
                }

                else if (context.Request.Path == new PathString("/authenticate"))
                {
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictServerOwinDefaults.AuthenticationType);
                    if (result?.Identity is not { IsAuthenticated: true })
                    {
                        return;
                    }

                    var claims = result.Identity.Claims.GroupBy(claim => claim.Type)
                        .Select(group => new KeyValuePair<string, string?[]?>(
                            group.Key, group.Select(claim => claim.Value).ToArray()));

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new OpenIddictResponse(claims)));
                    return;
                }

                else if (context.Request.Path == new PathString("/authenticate/properties"))
                {
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictServerOwinDefaults.AuthenticationType);
                    if (result?.Properties is null)
                    {
                        return;
                    }

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new OpenIddictResponse(result.Properties.Dictionary)));
                    return;
                }

                await next();
            });

            app.Run(context =>
            {
                context.Response.ContentType = "application/json";
                return context.Response.WriteAsync(JsonSerializer.Serialize(new
                {
                    name = "Bob le Magnifique"
                }));
            });
        });

        return new(new OpenIddictServerOwinIntegrationTestServer(server));
    }
}

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
using OpenIddict.Validation.IntegrationTests;
using Owin;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Validation.OpenIddictValidationEvents;
using static OpenIddict.Validation.OpenIddictValidationHandlers.Protection;

namespace OpenIddict.Validation.Owin.IntegrationTests;

public partial class OpenIddictValidationOwinIntegrationTests : OpenIddictValidationIntegrationTests
{
    public OpenIddictValidationOwinIntegrationTests(ITestOutputHelper outputHelper)
        : base(outputHelper)
    {
    }

    [Fact]
    public async Task ProcessAuthentication_CreationDateIsMappedToIssuedUtc()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
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

    protected override ValueTask<OpenIddictValidationIntegrationTestServer> CreateServerAsync(Action<OpenIddictValidationBuilder>? configuration = null)
    {
        var services = new ServiceCollection();
        ConfigureServices(services);

        services.AddLogging(options => options.AddXUnit(OutputHelper));

        services.AddOpenIddict()
            .AddValidation(options =>
            {
                options.UseOwin();

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

                var transaction = context.Get<OpenIddictValidationTransaction>(typeof(OpenIddictValidationTransaction).FullName);
                var response = transaction?.GetProperty<object>("custom_response");
                if (response is not null)
                {
                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(response));
                }
            });

            app.UseOpenIddictValidation();

            app.Use(async (context, next) =>
            {
                if (context.Request.Path == new PathString("/authenticate"))
                {
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictValidationOwinDefaults.AuthenticationType);
                    if (result?.Identity is not { IsAuthenticated: true })
                    {
                        context.Authentication.Challenge(OpenIddictValidationOwinDefaults.AuthenticationType);
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
                    var result = await context.Authentication.AuthenticateAsync(OpenIddictValidationOwinDefaults.AuthenticationType);
                    if (result?.Properties is null)
                    {
                        return;
                    }

                    context.Response.ContentType = "application/json";
                    await context.Response.WriteAsync(JsonSerializer.Serialize(new OpenIddictResponse(result.Properties.Dictionary)));
                    return;
                }

                else if (context.Request.Path == new PathString("/challenge"))
                {
                    context.Authentication.Challenge(OpenIddictValidationOwinDefaults.AuthenticationType);
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

        return new(new OpenIddictValidationOwinIntegrationTestValidation(server));
    }
}

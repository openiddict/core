/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers.Discovery;

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    [Theory]
    [InlineData(nameof(HttpMethod.Delete))]
    [InlineData(nameof(HttpMethod.Head))]
    [InlineData(nameof(HttpMethod.Options))]
    [InlineData(nameof(HttpMethod.Post))]
    [InlineData(nameof(HttpMethod.Put))]
    [InlineData(nameof(HttpMethod.Trace))]
    public async Task ExtractConfigurationRequest_UnexpectedMethodReturnsAnError(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendAsync(method, "/.well-known/openid-configuration", new OpenIddictRequest());

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
    public async Task ExtractConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ExtractConfigurationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractConfigurationRequestContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ExtractConfigurationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

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
    public async Task ValidateConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ValidateConfigurationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateConfigurationRequestContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ValidateConfigurationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_IssuerIsAutomaticallyInferred()
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(client.HttpClient.BaseAddress!.AbsoluteUri, (string?) response[Metadata.Issuer]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_RegisteredIssuerIsAlwaysPreferred()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetIssuer(new Uri("https://www.fabrikam.com/"));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("https://www.fabrikam.com/", (string?) response[Metadata.Issuer]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_AbsoluteEndpointsAreCorrectlyExposed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetAuthorizationEndpointUris("https://www.fabrikam.com/path/authorization_endpoint")
                   .SetJsonWebKeySetEndpointUris("https://www.fabrikam.com/path/cryptography_endpoint")
                   .SetDeviceAuthorizationEndpointUris("https://www.fabrikam.com/path/device_endpoint")
                   .SetIntrospectionEndpointUris("https://www.fabrikam.com/path/introspection_endpoint")
                   .SetEndSessionEndpointUris("https://www.fabrikam.com/path/logout_endpoint")
                   .SetRevocationEndpointUris("https://www.fabrikam.com/path/revocation_endpoint")
                   .SetTokenEndpointUris("https://www.fabrikam.com/path/token_endpoint")
                   .SetUserInfoEndpointUris("https://www.fabrikam.com/path/userinfo_endpoint");
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("https://www.fabrikam.com/path/authorization_endpoint",
            (string?) response[Metadata.AuthorizationEndpoint]);

        Assert.Equal("https://www.fabrikam.com/path/cryptography_endpoint",
            (string?) response[Metadata.JwksUri]);

        Assert.Equal("https://www.fabrikam.com/path/authorization_endpoint",
            (string?) response[Metadata.AuthorizationEndpoint]);

        Assert.Equal("https://www.fabrikam.com/path/device_endpoint",
            (string?) response[Metadata.DeviceAuthorizationEndpoint]);

        Assert.Equal("https://www.fabrikam.com/path/introspection_endpoint",
            (string?) response[Metadata.IntrospectionEndpoint]);

        Assert.Equal("https://www.fabrikam.com/path/logout_endpoint",
            (string?) response[Metadata.EndSessionEndpoint]);

        Assert.Equal("https://www.fabrikam.com/path/revocation_endpoint",
            (string?) response[Metadata.RevocationEndpoint]);

        Assert.Equal("https://www.fabrikam.com/path/token_endpoint",
            (string?) response[Metadata.TokenEndpoint]);

        Assert.Equal("https://www.fabrikam.com/path/userinfo_endpoint",
            (string?) response[Metadata.UserInfoEndpoint]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_RelativeEndpointsAreCorrectlyComputed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetAuthorizationEndpointUris("path/authorization_endpoint")
                   .SetJsonWebKeySetEndpointUris("path/cryptography_endpoint")
                   .SetDeviceAuthorizationEndpointUris("path/device_endpoint")
                   .SetIntrospectionEndpointUris("path/introspection_endpoint")
                   .SetEndSessionEndpointUris("path/logout_endpoint")
                   .SetPushedAuthorizationEndpointUris("path/pushed_authorization_endpoint")
                   .SetRevocationEndpointUris("path/revocation_endpoint")
                   .SetTokenEndpointUris("path/token_endpoint")
                   .SetUserInfoEndpointUris("path/userinfo_endpoint");
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("http://localhost/path/authorization_endpoint", (string?) response[Metadata.AuthorizationEndpoint]);
        Assert.Equal("http://localhost/path/cryptography_endpoint", (string?) response[Metadata.JwksUri]);
        Assert.Equal("http://localhost/path/device_endpoint", (string?) response[Metadata.DeviceAuthorizationEndpoint]);
        Assert.Equal("http://localhost/path/introspection_endpoint", (string?) response[Metadata.IntrospectionEndpoint]);
        Assert.Equal("http://localhost/path/logout_endpoint", (string?) response[Metadata.EndSessionEndpoint]);
        Assert.Equal("http://localhost/path/pushed_authorization_endpoint", (string?) response[Metadata.PushedAuthorizationRequestEndpoint]);
        Assert.Equal("http://localhost/path/revocation_endpoint", (string?) response[Metadata.RevocationEndpoint]);
        Assert.Equal("http://localhost/path/token_endpoint", (string?) response[Metadata.TokenEndpoint]);
        Assert.Equal("http://localhost/path/userinfo_endpoint", (string?) response[Metadata.UserInfoEndpoint]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_RelativeEndpointsWithSpecificBaseUriAreCorrectlyComputed()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetAuthorizationEndpointUris("path/authorization_endpoint")
                   .SetJsonWebKeySetEndpointUris("path/cryptography_endpoint")
                   .SetDeviceAuthorizationEndpointUris("path/device_endpoint")
                   .SetIntrospectionEndpointUris("path/introspection_endpoint")
                   .SetEndSessionEndpointUris("path/logout_endpoint")
                   .SetPushedAuthorizationEndpointUris("path/pushed_authorization_endpoint")
                   .SetRevocationEndpointUris("path/revocation_endpoint")
                   .SetTokenEndpointUris("path/token_endpoint")
                   .SetUserInfoEndpointUris("path/userinfo_endpoint");

            options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.BaseUri = new Uri("https://contoso.com/issuer");

                    return default;
                });

                builder.SetOrder(AttachEndpoints.Descriptor.Order - 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("https://contoso.com/issuer/path/authorization_endpoint", (string?) response[Metadata.AuthorizationEndpoint]);
        Assert.Equal("https://contoso.com/issuer/path/cryptography_endpoint", (string?) response[Metadata.JwksUri]);
        Assert.Equal("https://contoso.com/issuer/path/device_endpoint", (string?) response[Metadata.DeviceAuthorizationEndpoint]);
        Assert.Equal("https://contoso.com/issuer/path/introspection_endpoint", (string?) response[Metadata.IntrospectionEndpoint]);
        Assert.Equal("https://contoso.com/issuer/path/logout_endpoint", (string?) response[Metadata.EndSessionEndpoint]);
        Assert.Equal("https://contoso.com/issuer/path/pushed_authorization_endpoint", (string?) response[Metadata.PushedAuthorizationRequestEndpoint]);
        Assert.Equal("https://contoso.com/issuer/path/revocation_endpoint", (string?) response[Metadata.RevocationEndpoint]);
        Assert.Equal("https://contoso.com/issuer/path/token_endpoint", (string?) response[Metadata.TokenEndpoint]);
        Assert.Equal("https://contoso.com/issuer/path/userinfo_endpoint", (string?) response[Metadata.UserInfoEndpoint]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoClientAuthenticationMethodIsIncludedWhenTokenEndpointIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.GrantTypes.Clear());
            options.Configure(options => options.GrantTypes.Add(GrantTypes.Implicit));
            options.Configure(options => options.ResponseTypes.Clear());
            options.Configure(options => options.DeviceAuthorizationEndpointUris.Clear());
            options.Configure(options => options.EndUserVerificationEndpointUris.Clear());
            options.SetTokenEndpointUris(Array.Empty<Uri>());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.TokenEndpointAuthMethodsSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_SupportedClientAuthenticationMethodsAreIncludedWhenTokenEndpointIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Configure(options =>
        {
            options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretBasic);
            options.ClientAuthenticationMethods.Add("custom");
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var methods = (string[]?) response[Metadata.TokenEndpointAuthMethodsSupported];

        // Assert
        Assert.NotNull(methods);
        Assert.Equal(3, methods.Length);
        Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        Assert.Contains(ClientAuthenticationMethods.PrivateKeyJwt, methods);
        Assert.Contains("custom", methods);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoClientAuthenticationMethodIsIncludedWhenIntrospectionEndpointIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetIntrospectionEndpointUris(Array.Empty<Uri>());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.IntrospectionEndpointAuthMethodsSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_SupportedClientAuthenticationMethodsAreIncludedWhenIntrospectionEndpointIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Configure(options =>
        {
            options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretBasic);
            options.ClientAuthenticationMethods.Add("custom");
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var methods = (string[]?) response[Metadata.IntrospectionEndpointAuthMethodsSupported];

        // Assert
        Assert.NotNull(methods);
        Assert.Equal(3, methods.Length);
        Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        Assert.Contains(ClientAuthenticationMethods.PrivateKeyJwt, methods);
        Assert.Contains("custom", methods);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoClientAuthenticationMethodIsIncludedWhenRevocationEndpointIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetRevocationEndpointUris(Array.Empty<Uri>());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.RevocationEndpointAuthMethodsSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_SupportedClientAuthenticationMethodsAreIncludedWhenRevocationEndpointIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Configure(options =>
        {
            options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretBasic);
            options.ClientAuthenticationMethods.Add("custom");
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var methods = (string[]?) response[Metadata.RevocationEndpointAuthMethodsSupported];

        // Assert
        Assert.NotNull(methods);
        Assert.Equal(3, methods.Length);
        Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        Assert.Contains(ClientAuthenticationMethods.PrivateKeyJwt, methods);
        Assert.Contains("custom", methods);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoClientAuthenticationMethodIsIncludedWhenDeviceAuthorizationEndpointIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.GrantTypes.Remove(GrantTypes.DeviceCode));
            options.SetDeviceAuthorizationEndpointUris(Array.Empty<Uri>());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.DeviceAuthorizationEndpointAuthMethodsSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_SupportedClientAuthenticationMethodsAreIncludedWhenDeviceAuthorizationEndpointIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Configure(options =>
        {
            options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretBasic);
            options.ClientAuthenticationMethods.Add("custom");
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var methods = (string[]?) response[Metadata.DeviceAuthorizationEndpointAuthMethodsSupported];

        // Assert
        Assert.NotNull(methods);
        Assert.Equal(3, methods.Length);
        Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        Assert.Contains(ClientAuthenticationMethods.PrivateKeyJwt, methods);
        Assert.Contains("custom", methods);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoClientAuthenticationMethodIsIncludedWhenPushedAuthorizationEndpointIsDisabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.SetPushedAuthorizationEndpointUris(Array.Empty<Uri>());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.PushedAuthorizationRequestEndpointAuthMethodsSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_SupportedClientAuthenticationMethodsAreIncludedWhenPushedAuthorizationEndpointIsEnabled()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Configure(options =>
        {
            options.ClientAuthenticationMethods.Remove(ClientAuthenticationMethods.ClientSecretBasic);
            options.ClientAuthenticationMethods.Add("custom");
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var methods = (string[]?) response[Metadata.PushedAuthorizationRequestEndpointAuthMethodsSupported];

        // Assert
        Assert.NotNull(methods);
        Assert.Equal(3, methods.Length);
        Assert.Contains(ClientAuthenticationMethods.ClientSecretPost, methods);
        Assert.Contains(ClientAuthenticationMethods.PrivateKeyJwt, methods);
        Assert.Contains("custom", methods);
    }

    [Fact]
    public async Task HandleConfigurationRequest_ConfiguredGrantTypesAreReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
        {
            options.GrantTypes.Clear();
            options.GrantTypes.Add(GrantTypes.AuthorizationCode);
            options.GrantTypes.Add(GrantTypes.Password);
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var types = (string[]?) response[Metadata.GrantTypesSupported];

        // Assert
        Assert.NotNull(types);
        Assert.Equal(2, types.Length);
        Assert.Contains(GrantTypes.AuthorizationCode, types);
        Assert.Contains(GrantTypes.Password, types);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoSupportedCodeChallengeMethodsPropertyIsReturnedWhenNoMethodIsConfigured()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Services.PostConfigure<OpenIddictServerOptions>(options => options.CodeChallengeMethods.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.CodeChallengeMethodsSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_ConfiguredCodeChallengeMethodsAreReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
        {
            options.CodeChallengeMethods.Clear();
            options.CodeChallengeMethods.Add(CodeChallengeMethods.Sha256);
            options.CodeChallengeMethods.Add(CodeChallengeMethods.Plain);
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var methods = (string[]?) response[Metadata.CodeChallengeMethodsSupported];

        // Assert
        Assert.NotNull(methods);
        Assert.Equal(2, methods.Length);
        Assert.Contains(CodeChallengeMethods.Sha256, methods);
        Assert.Contains(CodeChallengeMethods.Plain, methods);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoSupportedResponseModesPropertyIsReturnedWhenNoResponseModeIsConfigured()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Services.PostConfigure<OpenIddictServerOptions>(options => options.ResponseModes.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.ResponseModesSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_ConfiguredResponseModesAreReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
        {
            options.ResponseModes.Clear();
            options.ResponseModes.Add(ResponseModes.FormPost);
            options.ResponseModes.Add(ResponseModes.Fragment);
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var modes = (string[]?) response[Metadata.ResponseModesSupported];

        // Assert
        Assert.NotNull(modes);
        Assert.Equal(2, modes.Length);
        Assert.Contains(ResponseModes.FormPost, modes);
        Assert.Contains(ResponseModes.Fragment, modes);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoSupportedResponseTypesPropertyIsReturnedWhenNoResponseTypeIsConfigured()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Services.PostConfigure<OpenIddictServerOptions>(options => options.ResponseTypes.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.ResponseTypesSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_ConfiguredResponseTypesAreReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
        {
            options.ResponseTypes.Clear();
            options.ResponseTypes.Add(ResponseTypes.Code);
            options.ResponseTypes.Add(ResponseTypes.Code + ' ' + ResponseTypes.IdToken);
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var types = (string[]?) response[Metadata.ResponseTypesSupported];

        // Assert
        Assert.NotNull(types);
        Assert.Equal(2, types.Length);
        Assert.Contains(ResponseTypes.Code, types);
        Assert.Contains(ResponseTypes.Code + ' ' + ResponseTypes.IdToken, types);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoSupportedScopesPropertyIsReturnedWhenNoScopeIsConfigured()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Services.PostConfigure<OpenIddictServerOptions>(options => options.Scopes.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.ScopesSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_ConfiguredScopesAreReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
        {
            options.Scopes.Clear();
            options.Scopes.Add(Scopes.OpenId);
            options.Scopes.Add("custom_scope");
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var scopes = (string[]?) response[Metadata.ScopesSupported];

        // Assert
        Assert.NotNull(scopes);
        Assert.Equal(2, scopes.Length);
        Assert.Contains(Scopes.OpenId, scopes);
        Assert.Contains("custom_scope", scopes);
    }

    [Fact]
    public async Task HandleConfigurationRequest_NoSupportedClaimsPropertyIsReturnedWhenNoClaimIsConfigured()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Services.PostConfigure<OpenIddictServerOptions>(options => options.Claims.Clear());
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False(response.HasParameter(Metadata.ClaimsSupported));
    }

    [Fact]
    public async Task HandleConfigurationRequest_ConfiguredClaimsAreReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Services.PostConfigure<OpenIddictServerOptions>(options =>
        {
            options.Claims.Clear();
            options.Claims.Add(Claims.Profile);
            options.Claims.Add("custom_claim");
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var claims = (string[]?) response[Metadata.ClaimsSupported];

        // Assert
        Assert.NotNull(claims);
        Assert.Equal(2, claims.Length);
        Assert.Contains(Claims.Profile, claims);
        Assert.Contains("custom_claim", claims);
    }

    [Fact]
    public async Task HandleConfigurationRequest_SupportedSubjectTypesAreCorrectlyReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.SubjectTypes.Remove(SubjectTypes.Public));
            options.Configure(options => options.SubjectTypes.Add("custom"));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var types = (string[]?) response[Metadata.SubjectTypesSupported];

        // Assert
        Assert.NotNull(types);
        Assert.Equal("custom", Assert.Single(types));
    }

    [Fact]
    public async Task HandleConfigurationRequest_SupportedPromptValuesAreCorrectlyReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.PromptValues.Remove(PromptValues.Consent));
            options.Configure(options => options.PromptValues.Remove(PromptValues.Login));
            options.Configure(options => options.PromptValues.Remove(PromptValues.None));
            options.Configure(options => options.PromptValues.Remove(PromptValues.SelectAccount));
            options.Configure(options => options.PromptValues.Add("custom"));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var types = (string[]?) response[Metadata.PromptValuesSupported];

        // Assert
        Assert.NotNull(types);
        Assert.Equal("custom", Assert.Single(types));
    }

    [Theory]
    [InlineData(Algorithms.RsaSha256)]
    [InlineData(Algorithms.RsaSha384)]
    [InlineData(Algorithms.RsaSha512)]
#if SUPPORTS_ECDSA
    [InlineData(Algorithms.EcdsaSha256)]
    [InlineData(Algorithms.EcdsaSha384)]
    [InlineData(Algorithms.EcdsaSha512)]
#endif
    public async Task HandleConfigurationRequest_SigningAlgorithmsAreCorrectlyReturned(string algorithm)
    {
        // Arrange
        var credentials = new SigningCredentials(Mock.Of<AsymmetricSecurityKey>(), algorithm);

        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.SigningCredentials.Clear());
            options.AddSigningCredentials(credentials);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var algorithms = (string[]?) response[Metadata.IdTokenSigningAlgValuesSupported];

        // Assert
        Assert.NotNull(algorithms);
        Assert.Contains(algorithm, algorithms);
    }

    [Fact]
    public async Task HandleConfigurationRequest_SymmetricSigningKeysAreIgnored()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.SigningCredentials.Clear());
            options.AddSigningKey(new SymmetricSecurityKey(new byte[256 / 8]));
            options.AddSigningCredentials(new SigningCredentials(Mock.Of<AsymmetricSecurityKey>(), Algorithms.RsaSha256));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var algorithms = (string[]?) response[Metadata.IdTokenSigningAlgValuesSupported];

        // Assert
        Assert.NotNull(algorithms);
        Assert.Single(algorithms);
        Assert.Contains(Algorithms.RsaSha256, algorithms);
    }

    [Fact]
    public async Task HandleConfigurationRequest_DuplicateSigningAlgorithmsAreIgnored()
    {
        // Arrange
        var credentials = new SigningCredentials(Mock.Of<AsymmetricSecurityKey>(), SecurityAlgorithms.RsaSha256Signature);

        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.SigningCredentials.Clear());
            options.AddSigningCredentials(credentials);
            options.AddSigningCredentials(credentials);
            options.AddSigningCredentials(credentials);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");
        var algorithms = (string[]?) response[Metadata.IdTokenSigningAlgValuesSupported];

        // Assert
        Assert.NotNull(algorithms);
        Assert.Single(algorithms);
    }

    [Fact]
    public async Task HandleConfigurationRequest_SupportedParametersAreReturned()
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.False((bool?) response[Metadata.ClaimsParameterSupported]);
        Assert.False((bool?) response[Metadata.RequestParameterSupported]);
        Assert.False((bool?) response[Metadata.RequestUriParameterSupported]);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task HandleConfigurationRequest_PushedAuthorizationRequestsRequirementIsReflected(bool value)
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.Configure(options =>
        {
            options.RequirePushedAuthorizationRequests = value;
        }));

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(value, (bool?) response[Metadata.RequirePushedAuthorizationRequests]);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task HandleConfigurationRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task HandleConfigurationRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleConfigurationRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task ApplyConfigurationResponse_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ApplyConfigurationResponseContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ApplyConfigurationResponse_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ApplyConfigurationResponseContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/openid-configuration");

        // Assert
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
    }

    [Theory]
    [InlineData(nameof(HttpMethod.Delete))]
    [InlineData(nameof(HttpMethod.Head))]
    [InlineData(nameof(HttpMethod.Options))]
    [InlineData(nameof(HttpMethod.Post))]
    [InlineData(nameof(HttpMethod.Put))]
    [InlineData(nameof(HttpMethod.Trace))]
    public async Task ExtractJsonWebKeySetRequest_UnexpectedMethodReturnsAnError(string method)
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.SendAsync(method, "/.well-known/jwks", new OpenIddictRequest());

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
    public async Task ExtractJsonWebKeySetRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractJsonWebKeySetRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ExtractJsonWebKeySetRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractJsonWebKeySetRequestContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ExtractJsonWebKeySetRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ExtractJsonWebKeySetRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");

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
    public async Task ValidateJsonWebKeySetRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateJsonWebKeySetRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ValidateJsonWebKeySetRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateJsonWebKeySetRequestContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ValidateJsonWebKeySetRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateJsonWebKeySetRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Theory]
    [InlineData(SecurityAlgorithms.HmacSha256Signature)]
    [InlineData(SecurityAlgorithms.HmacSha384Signature)]
    [InlineData(SecurityAlgorithms.HmacSha512Signature)]
#if !SUPPORTS_ECDSA
    [InlineData(SecurityAlgorithms.EcdsaSha256Signature)]
    [InlineData(SecurityAlgorithms.EcdsaSha384Signature)]
    [InlineData(SecurityAlgorithms.EcdsaSha512Signature)]
#endif
    public async Task HandleJsonWebKeySetRequest_UnsupportedSecurityKeysAreIgnored(string algorithm)
    {
        // Arrange
        var key = Mock.Of<SecurityKey>(mock => !mock.IsSupportedAlgorithm(algorithm));

        await using var server = await CreateServerAsync(options =>
        {
            options.AddSigningCredentials(new SigningCredentials(key, algorithm));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");
        var keys = (JsonElement) response[Parameters.Keys];

        // Assert
        Assert.Equal(1, keys.GetArrayLength());
        Assert.Equal(Algorithms.RsaSha256, keys[0].GetProperty(JsonWebKeyParameterNames.Alg).GetString());
    }

    [Fact]
    public async Task HandleJsonWebKeySetRequest_RsaSecurityKeysAreCorrectlyExposed()
    {
        // Arrange
        var parameters = new RSAParameters
        {
            D = Convert.FromBase64String("Uj6NrYBnyddhlJefYEP2nleCntAKlWyIttJC4cJnNxNN+OT2fQXhpTXRwW4R5YIS3HDqK/Fg2yoYm+OTVntAAgRFKveRx/WKwFo6UpnJc5u3lElhFa7IfosO9qXjErpX9ruAVqipekDLwQ++KmVVdgH4PK/o//nEx5zklGCdlEJURZYJPs9/7g1cx3UwvPp8jM7LgZL5OZRNyI3Jz4efrwiI2/vd8P28lAbpv/Ao4NwUDq/WKEnZ8JYSjLEKnZCfbX1ZEwf0Ic48jEKHmi1WEwpru1fMPoYfakrsY/VEfatPiDs8a5HABP/KaXcM4AZsr7HbzqAaNycV2xgdZimGcQ=="),
            DP = Convert.FromBase64String("hi1e+0eQ/iYrfT4zpZVbx3dyfA7Ch/aujMt6nGMF+1LGaut86vDHM2JI0Gc2BKc+uPEu2bNAorhSmuSyGpfGYl0MYFQoVF/jyiGpzYPmhYpL5yLuN9jWAqNwjfstuRDLU9zTEfZnr3OSN85rZcgT7NUxlY8im1Y2TWYxGiEXw9E="),
            DQ = Convert.FromBase64String("laVNkWIbnSuGo7nAxyUSdL2sXU3GZWwItwzTG0IK/0woFjArtCxGgNXW+V+GhxT7iHGAVJJSBvJ65TXrUYuBmoWj2CsoUs2mzK8ax4zg3CXrU61esCsGUoS2owR4FXlhYPmoVnglGu89bH72eXKixZsuF7vKW19nG703BXYEaEU="),
            Exponent = Convert.FromBase64String("AQAB"),
            InverseQ = Convert.FromBase64String("dhzLDS4F5WYHX+vH4+uL3Ei/K5lxw2A/dBHGtbS2X54gm7vARl+FrptOFFwIjjmsLuTjttAq9K1EP/XZIq8bjW6dXJ/IytnobIPSFkclEeQlMi4/2VDMG5915J0DwnKO9M+B8F3JViUyMv0pvb+ub+HHDVFkIr7zooCmY25i77Q="),
            Modulus = Convert.FromBase64String("kXv7Pxf6mSf7mu6mPAOAoKAXl5kU7Q3h9zevC5i4Mm5bMk17XCh7ZvVxDzGA+1JmyxOX6sw3gMUl31FtIFlDhis8VnXKAPn8i1zrmebq+7QKzpE2GpoIpXjXbkPaHG/DbC67M1bux7/dE7lSUSifHRRLsbMUC2D4UahJ6miH2iPFNFyoa6CLtwosD8tIJKwmZ9r9zfqc9BrVGu24lZySjTSRttpLaTkgkBjxHmYhinKNEtj9wUfi1S1wPJUvf+roc6o+7jeBBV3EXJCsb6XCCXI7/e3umWp19odeRShXLQNQbNuuVC7yre4iidUDrWJ1jiaB06svUG+fVEi4FCMvEQ=="),
            P = Convert.FromBase64String("xQGczmp4qD7Sez/ZqgW+O4cciTHvSqJqJUSdDd2l1Pd/szQ8avvzorrbSWOIULyv6eJb32+HuyLgy6rTSJ6THFobAnUv4ZTR7EGK26AJmP/BhD+3G+n21+4fzfbAxpHihkCYmO8aEl8fm/r4qPVXmCzFoXDZLMNIxFsdEXiFRS0="),
            Q = Convert.FromBase64String("vQy5C++AzF+TRh6qwbKzOqt87ZHEHidIAh6ivRNewjzIgCWXpseVl7DimY1YdViOnw1VI7xY+EyiyTanq5caTqqB3KcDm2t40bJfrZuUcn/5puRIh1bKNDwIMLsuNCrjHmDlNbocqpYMOh0Pgw7ARNbqrnPjWsYGJPuMNFpax/U=")
        };

        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.SigningCredentials.Clear());
            options.AddSigningKey(new RsaSecurityKey(parameters));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");
        var key = response[Parameters.Keys]?[0];

        // Assert
        Assert.Null(key?[JsonWebKeyParameterNames.D]);
        Assert.Null(key?[JsonWebKeyParameterNames.DP]);
        Assert.Null(key?[JsonWebKeyParameterNames.DQ]);
        Assert.Null(key?[JsonWebKeyParameterNames.P]);
        Assert.Null(key?[JsonWebKeyParameterNames.Q]);

        Assert.Equal(parameters.Exponent, Base64UrlEncoder.DecodeBytes((string?) key?[JsonWebKeyParameterNames.E]));
        Assert.Equal(parameters.Modulus, Base64UrlEncoder.DecodeBytes((string?) key?[JsonWebKeyParameterNames.N]));
    }

#if SUPPORTS_ECDSA
    [Theory]
    [InlineData(
        /* oid: */ "1.2.840.10045.3.1.7", // P-256
        /* d: */ "C0vacBwq1FnQ1N0FHXuuwTlw7Or0neOm2r3AdIKLDKI=",
        /* x: */ "7eu+fVtuma+LVD4eH6CxrBX8366cnhPpvgeoeYL7oqw=",
        /* y: */ "4qRkITJZ4p5alm0VpLPd+I11wq8vMUHUhbJm1Crx+Zs=")]
    [InlineData(
        /* oid: */ "1.3.132.0.34", // P-384
        /* d: */ "B2JSdvTbRD/T5Sv7QsGBHPX9yGo2zn3Et5OWrjNauQ2kl+jFkXg5Iy2Vfak7W0ZQ",
        /* x: */ "qqsUwddWjXhCWiaUCOUORJIzvp6QDXv1vroHPR4N0C3UqSKkJ5hNiBHaYdRYCnvC",
        /* y: */ "QpbQFKBOXgeAKQQub/9QWZPvzNEjXq7aJjHlw4hiY+9QhGPn4qHUaeeI0qlaJ/t2")]
    [InlineData(
        /* oid: */ "1.3.132.0.35", // P-521
        /* d: */ "ALong1stsWvTLufObn3SPfM8s9VsTG73nXv4mkzGFUmB1r7rda+cpYXU99rFV/kX6zBkFl7Y9TZ2ZyZLFnyUpE4j",
        /* x: */ "AS+aCMpMbSO4ga/hUsVIIidqmcQiiT+N9o/5hJ9UVA/vHAKDvWTjuKz+JZfOiR9J+GDUcDZS56UbGG83IosMJMM6",
        /* y: */ "AcYkfsb/kTKpcPhYsRPAYV7ibwTN/CdiAM8QuCElAV6wBGfuX1LUmK6ldDVJjytpSz1EmGvzR0T7UCcZcgITqWc2")]
    public async Task HandleJsonWebKeySetRequest_EcdsaSecurityKeysAreCorrectlyExposed(string oid, string d, string x, string y)
    {
        // Arrange
        var parameters = new ECParameters
        {
            Curve = ECCurve.CreateFromValue(oid),
            D = Convert.FromBase64String(d),
            Q = new ECPoint
            {
                X = Convert.FromBase64String(x),
                Y = Convert.FromBase64String(y)
            }
        };

        using var algorithm = ECDsa.Create(parameters);

        await using var server = await CreateServerAsync(options =>
        {
            options.Configure(options => options.SigningCredentials.Clear());
            options.AddSigningKey(new ECDsaSecurityKey(algorithm));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");
        var key = response[Parameters.Keys]?[0];

        // Assert
        Assert.Null(key?[JsonWebKeyParameterNames.D]);

        Assert.Equal(parameters.Q.X, Base64UrlEncoder.DecodeBytes((string?) key?[JsonWebKeyParameterNames.X]));
        Assert.Equal(parameters.Q.Y, Base64UrlEncoder.DecodeBytes((string?) key?[JsonWebKeyParameterNames.Y]));
    }
#endif

    [Fact]
    public async Task HandleJsonWebKeySetRequest_X509CertificatesAreCorrectlyExposed()
    {
        // Arrange
        await using var server = await CreateServerAsync();
        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");
        var key = response[Parameters.Keys]?[0];

        // Assert
        Assert.Equal("BSxeQhXNDB4VBeCOavOtvvv9eCI", (string?) key?[JsonWebKeyParameterNames.X5t]);
        Assert.Equal("MIIDPjCCAiqgAwIBAgIQlLEp+P+WKYtEAemhSKSUTTAJBgUrDgMCHQUAMC0xKzApBgNVBAMTIk93aW4uU2VjdXJpdHkuT3BlbklkQ29ubmVjdC5TZXJ2ZXIwHhcNOTkxMjMxMjIwMDAwWhcNNDkxMjMxMjIwMDAwWjAtMSswKQYDVQQDEyJPd2luLlNlY3VyaXR5Lk9wZW5JZENvbm5lY3QuU2VydmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwD/4uMNSIu+JlPRrtFR8Tm2LAwSOmglvJai6edFrdvDvk6xWzxYkMoIt4v13lFiIAUfI1vyZ1M0hWQfrifyweuzZu06DyWTUZkp9ervhTxK27HFN7XTuaRxHaXLR4KnhA+Nk8bBXN895OZh9g9Hf5+zsHpe17zgikwcyZtF+9OEG16oz7lKRgXGCIeeVZuSZ5Qf4yePwKMZqsx+lTOiZJ3JMs+gytvIpdZ1NWzcMX0XTcVTgvnBeU0O3NR6DQ41+SrGsojk11bd6kP6mVmDkA0K9kc2eh7q1wyJOeTNuCKRqLthwJ5m46/KRsxgY7ND6qHc1L60SqsFlYCJNEy7EdwIDAQABo2IwYDBeBgNVHQEEVzBVgBDQX+HKPiztLNvT3jQeBXqToS8wLTErMCkGA1UEAxMiT3dpbi5TZWN1cml0eS5PcGVuSWRDb25uZWN0LlNlcnZlcoIQlLEp+P+WKYtEAemhSKSUTTAJBgUrDgMCHQUAA4IBAQCxbCF5thB+ypGpudLAjv+l3M2VhNITJeR9j7jMlCSMVHvW7iMOL5W++zKvHMMAWuITLgPXTZ4ktsjeVQxWdnS2IcU7SwB9SeLbOMk4lLizoUevkiNaf6v+Hskm5LiH6+k8Zsl0INHyIjF9XlALTh91EqQ820cotDXaQIhHabQy892+dBmGWhSE1kP56IvOPzlLdSTkrcfcOu9gzwPVfuTDWH8Hrmo3FXz/fADmE7ea+yE1ZBeKhaN8kaFTs5zrprJ1BnmegnrjDY3RFgqcTTetahv0VBS0/jHSTIsAXflEPGW7LbHimzcgMytFU4fFtPVbek5eunakhu/JdENbbVmT", (string?) key?[JsonWebKeyParameterNames.X5c]?[0]);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task HandleJsonWebKeySetRequest_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleJsonWebKeySetRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task HandleJsonWebKeySetRequest_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleJsonWebKeySetRequestContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task HandleJsonWebKeySetRequest_AllowsSkippingHandler()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleJsonWebKeySetRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response["name"]);
    }

    [Fact]
    public async Task ApplyJsonWebKeySetResponse_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ApplyJsonWebKeySetResponseContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ApplyJsonWebKeySetResponse_ResponseContainsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ApplyJsonWebKeySetResponseContext>(builder =>
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
        var response = await client.GetAsync("/.well-known/jwks");

        // Assert
        Assert.Equal("custom_value", (string?) response["custom_parameter"]);
        Assert.Equal(["custom_value_1", "custom_value_2"], (string[]?) response["parameter_with_multiple_values"]);
    }
}

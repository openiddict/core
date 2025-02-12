

/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.Immutable;
using System.Globalization;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Moq;
using OpenIddict.Core;
using Xunit;
using Xunit.Abstractions;
using static OpenIddict.Server.OpenIddictServerEvents;
using static OpenIddict.Server.OpenIddictServerHandlers;
using static OpenIddict.Server.OpenIddictServerHandlers.Protection;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Server.IntegrationTests;

public abstract partial class OpenIddictServerIntegrationTests
{
    protected OpenIddictServerIntegrationTests(ITestOutputHelper outputHelper)
    {
        OutputHelper = outputHelper;
    }

    protected ITestOutputHelper OutputHelper { get; }

    [Theory]
    [InlineData("/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/authorize", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/connect/authorize/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/connect/authorize/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/AUTHORIZE/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/authorize/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/AUTHORIZE/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/.well-known/openid-configuration/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/.well-known/openid-configuration/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.WELL-KNOWN/OPENID-CONFIGURATION/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.well-known/openid-configuration/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.WELL-KNOWN/OPENID-CONFIGURATION/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/device", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("/CONNECT/DEVICE", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("/connect/device/", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("/CONNECT/DEVICE/", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("/connect/device/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/DEVICE/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/device/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/DEVICE/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/endsession", OpenIddictServerEndpointType.EndSession)]
    [InlineData("/CONNECT/ENDSESSION", OpenIddictServerEndpointType.EndSession)]
    [InlineData("/connect/endsession/", OpenIddictServerEndpointType.EndSession)]
    [InlineData("/CONNECT/ENDSESSION/", OpenIddictServerEndpointType.EndSession)]
    [InlineData("/connect/endsession/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/ENDSESSION/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/endsession/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/ENDSESSION/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/verification", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("/CONNECT/VERIFICATION", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("/connect/verification/", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("/connect/verification/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/VERIFICATION/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/verification/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/VERIFICATION/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/introspect", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/connect/introspect/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/connect/introspect/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/INTROSPECT/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/introspect/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/INTROSPECT/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.well-known/jwks", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("/.well-known/jwks/", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("/.well-known/jwks/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.WELL-KNOWN/JWKS/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.well-known/jwks/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/.WELL-KNOWN/JWKS/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/par", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("/CONNECT/PAR", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("/connect/par/", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("/CONNECT/PAR/", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("/connect/par/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/PAR/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/par/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/PAR/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/revoke", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/CONNECT/REVOKE", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/connect/revoke/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/CONNECT/REVOKE/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/connect/revoke/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/REVOKE/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/revoke/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/REVOKE/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/token", OpenIddictServerEndpointType.Token)]
    [InlineData("/CONNECT/TOKEN", OpenIddictServerEndpointType.Token)]
    [InlineData("/connect/token/", OpenIddictServerEndpointType.Token)]
    [InlineData("/CONNECT/TOKEN/", OpenIddictServerEndpointType.Token)]
    [InlineData("/connect/token/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/TOKEN/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/token/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/TOKEN/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/userinfo", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("/CONNECT/USERINFO", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("/connect/userinfo/", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("/CONNECT/USERINFO/", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("/connect/userinfo/subpath", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/USERINFO/SUBPATH", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/connect/userinfo/subpath/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/CONNECT/USERINFO/SUBPATH/", OpenIddictServerEndpointType.Unknown)]
    public async Task ProcessRequest_MatchesCorrespondingRelativeEndpoint(string path, OpenIddictServerEndpointType type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<HandleEndUserVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.Equal(type, context.EndpointType);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync(path, new OpenIddictRequest());
    }

    [Theory]
    [InlineData("https://localhost/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:443/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST/CONNECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:443/connect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:443/connect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/authorize", OpenIddictServerEndpointType.Authorization)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Authorization)]
    [InlineData("https://localhost/connect/authorize/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("https://localhost:443/connect/authorize", OpenIddictServerEndpointType.Authorization)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Authorization)]
    [InlineData("https://localhost:443/connect/authorize/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Authorization)]
    [InlineData("https://fabrikam.com/connect/authorize", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/authorize/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/authorize", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/AUTHORIZE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/authorize/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/AUTHORIZE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
    [InlineData("HTTPS://LOCALHOST/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Configuration)]
    [InlineData("https://localhost/.well-known/openid-configuration/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("HTTPS://LOCALHOST/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("https://localhost:443/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
    [InlineData("HTTPS://LOCALHOST:443/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Configuration)]
    [InlineData("https://localhost:443/.well-known/openid-configuration/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("HTTPS://LOCALHOST:443/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Configuration)]
    [InlineData("https://fabrikam.com/.well-known/openid-configuration", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/.well-known/openid-configuration/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/.well-known/openid-configuration", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/.WELL-KNOWN/OPENID-CONFIGURATION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/.well-known/openid-configuration/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/.WELL-KNOWN/OPENID-CONFIGURATION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/device", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/DEVICE", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("https://localhost/connect/device/", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/DEVICE/", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("https://localhost:443/connect/device", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/DEVICE", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("https://localhost:443/connect/device/", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/DEVICE/", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("https://fabrikam.com/connect/device", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/DEVICE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/device/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/DEVICE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/device", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/DEVICE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/device/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/DEVICE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/endsession", OpenIddictServerEndpointType.EndSession)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/ENDSESSION", OpenIddictServerEndpointType.EndSession)]
    [InlineData("https://localhost/connect/endsession/", OpenIddictServerEndpointType.EndSession)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/ENDSESSION/", OpenIddictServerEndpointType.EndSession)]
    [InlineData("https://localhost:443/connect/endsession", OpenIddictServerEndpointType.EndSession)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/ENDSESSION", OpenIddictServerEndpointType.EndSession)]
    [InlineData("https://localhost:443/connect/endsession/", OpenIddictServerEndpointType.EndSession)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/ENDSESSION/", OpenIddictServerEndpointType.EndSession)]
    [InlineData("https://fabrikam.com/connect/endsession", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/ENDSESSION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/endsession/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/ENDSESSION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/endsession", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/ENDSESSION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/endsession/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/ENDSESSION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/verification", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/VERIFICATION", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("https://localhost/connect/verification/", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("https://localhost:443/connect/verification", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/VERIFICATION", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("https://localhost:443/connect/verification/", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.EndUserVerification)]
    [InlineData("https://fabrikam.com/connect/verification", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/VERIFICATION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/verification/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/verification", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/VERIFICATION", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/verification/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/VERIFICATION/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/introspect", OpenIddictServerEndpointType.Introspection)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Introspection)]
    [InlineData("https://localhost/connect/introspect/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("https://localhost:443/connect/introspect", OpenIddictServerEndpointType.Introspection)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Introspection)]
    [InlineData("https://localhost:443/connect/introspect/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Introspection)]
    [InlineData("https://fabrikam.com/connect/introspect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/introspect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/introspect", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/INTROSPECT", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/introspect/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/INTROSPECT/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/.well-known/jwks", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("HTTPS://LOCALHOST/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("https://localhost/.well-known/jwks/", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("HTTPS://LOCALHOST/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("https://localhost:443/.well-known/jwks", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("HTTPS://LOCALHOST:443/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("https://localhost:443/.well-known/jwks/", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("HTTPS://LOCALHOST:443/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("https://fabrikam.com/.well-known/jwks", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/.well-known/jwks/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/.well-known/jwks", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/.WELL-KNOWN/JWKS", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/.well-known/jwks/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/.WELL-KNOWN/JWKS/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/par", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/PAR", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("https://localhost/connect/par/", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/PAR/", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("https://localhost:443/connect/par", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/PAR", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("https://localhost:443/connect/par/", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/PAR/", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("https://fabrikam.com/connect/par", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/PAR", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/par/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/PAR/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/par", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/PAR", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/par/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/PAR/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/revoke", OpenIddictServerEndpointType.Revocation)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/REVOKE", OpenIddictServerEndpointType.Revocation)]
    [InlineData("https://localhost/connect/revoke/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/REVOKE/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("https://localhost:443/connect/revoke", OpenIddictServerEndpointType.Revocation)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/REVOKE", OpenIddictServerEndpointType.Revocation)]
    [InlineData("https://localhost:443/connect/revoke/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/REVOKE/", OpenIddictServerEndpointType.Revocation)]
    [InlineData("https://fabrikam.com/connect/revoke", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/REVOKE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/revoke/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/REVOKE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/revoke", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/REVOKE", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/revoke/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/REVOKE/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/token", OpenIddictServerEndpointType.Token)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/TOKEN", OpenIddictServerEndpointType.Token)]
    [InlineData("https://localhost/connect/token/", OpenIddictServerEndpointType.Token)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/TOKEN/", OpenIddictServerEndpointType.Token)]
    [InlineData("https://localhost:443/connect/token", OpenIddictServerEndpointType.Token)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/TOKEN", OpenIddictServerEndpointType.Token)]
    [InlineData("https://localhost:443/connect/token/", OpenIddictServerEndpointType.Token)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/TOKEN/", OpenIddictServerEndpointType.Token)]
    [InlineData("https://fabrikam.com/connect/token", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/TOKEN", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/token/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/TOKEN/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/token", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/TOKEN", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/token/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/TOKEN/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost/connect/userinfo", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/USERINFO", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("https://localhost/connect/userinfo/", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("HTTPS://LOCALHOST/CONNECT/USERINFO/", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("https://localhost:443/connect/userinfo", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/USERINFO", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("https://localhost:443/connect/userinfo/", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("HTTPS://LOCALHOST:443/CONNECT/USERINFO/", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("https://fabrikam.com/connect/userinfo", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/USERINFO", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://fabrikam.com/connect/userinfo/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://FABRIKAM.COM/CONNECT/USERINFO/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/userinfo", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/USERINFO", OpenIddictServerEndpointType.Unknown)]
    [InlineData("https://localhost:8888/connect/userinfo/", OpenIddictServerEndpointType.Unknown)]
    [InlineData("HTTPS://LOCALHOST:8888/CONNECT/USERINFO/", OpenIddictServerEndpointType.Unknown)]
    public async Task ProcessRequest_MatchesCorrespondingAbsoluteEndpoint(string path, OpenIddictServerEndpointType type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.SetAuthorizationEndpointUris("https://localhost/connect/authorize")
                   .SetConfigurationEndpointUris("https://localhost/.well-known/openid-configuration")
                   .SetJsonWebKeySetEndpointUris("https://localhost/.well-known/jwks")
                   .SetDeviceAuthorizationEndpointUris("https://localhost/connect/device")
                   .SetIntrospectionEndpointUris("https://localhost/connect/introspect")
                   .SetEndSessionEndpointUris("https://localhost/connect/endsession")
                   .SetPushedAuthorizationEndpointUris("https://localhost/connect/par")
                   .SetRevocationEndpointUris("https://localhost/connect/revoke")
                   .SetTokenEndpointUris("https://localhost/connect/token")
                   .SetUserInfoEndpointUris("https://localhost/connect/userinfo")
                   .SetEndUserVerificationEndpointUris("https://localhost/connect/verification");

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<HandleEndUserVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.Equal(type, context.EndpointType);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync(path, new OpenIddictRequest());
    }

    [Theory]
    [InlineData("/custom/connect/authorize", OpenIddictServerEndpointType.Authorization)]
    [InlineData("/custom/.well-known/openid-configuration", OpenIddictServerEndpointType.Configuration)]
    [InlineData("/custom/.well-known/jwks", OpenIddictServerEndpointType.JsonWebKeySet)]
    [InlineData("/custom/connect/device", OpenIddictServerEndpointType.DeviceAuthorization)]
    [InlineData("/custom/connect/custom", OpenIddictServerEndpointType.Unknown)]
    [InlineData("/custom/connect/introspect", OpenIddictServerEndpointType.Introspection)]
    [InlineData("/custom/connect/endsession", OpenIddictServerEndpointType.EndSession)]
    [InlineData("/custom/connect/par", OpenIddictServerEndpointType.PushedAuthorization)]
    [InlineData("/custom/connect/revoke", OpenIddictServerEndpointType.Revocation)]
    [InlineData("/custom/connect/token", OpenIddictServerEndpointType.Token)]
    [InlineData("/custom/connect/userinfo", OpenIddictServerEndpointType.UserInfo)]
    [InlineData("/custom/connect/verification", OpenIddictServerEndpointType.EndUserVerification)]
    public async Task ProcessRequest_AllowsOverridingEndpoint(string uri, OpenIddictServerEndpointType type)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<HandleEndUserVerificationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    // Act
                    context.EndpointType = type;

                    // Assert
                    Assert.Equal(type, context.EndpointType);

                    return default;
                });

                builder.SetOrder(InferEndpointType.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync(uri, new OpenIddictRequest());
    }

    [Fact]
    public async Task ProcessAuthentication_UnknownEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/authenticate", new OpenIddictRequest());
        });

        Assert.Equal(SR.GetResourceString(SR.ID0002), exception.Message);
    }

    [Fact]
    public async Task ProcessAuthentication_InvalidEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetConfigurationEndpointUris("/authenticate");

            options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.GetAsync("/authenticate");
        });

        Assert.Equal(SR.GetResourceString(SR.ID0002), exception.Message);
    }

    [Fact]
    public async Task ProcessAuthentication_MissingAccessTokenReturnsNull()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = null
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_InvalidAccessTokenReturnsNull()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate");

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "38323A4B-6CB2-41B8-B457-1951987CB383"
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_ValidAccessTokenReturnsExpectedIdentity()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/authenticate");

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
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            AccessToken = "access_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_MissingIdTokenHintReturnsNull()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetEndSessionEndpointUris("/authenticate");

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            IdTokenHint = null
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_InvalidIdTokenHintReturnsNull()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetEndSessionEndpointUris("/authenticate");

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            IdTokenHint = "38323A4B-6CB2-41B8-B457-1951987CB383"
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_ValidIdTokenHintReturnsExpectedIdentity()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetEndSessionEndpointUris("/authenticate");

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("id_token", context.Token);
                    Assert.Equal([TokenTypeHints.IdToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.IdToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.GetAsync("/authenticate", new OpenIddictRequest
        {
            IdTokenHint = "id_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_MissingAuthorizationCodeReturnsNull()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/authenticate");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Code = null,
            GrantType = GrantTypes.AuthorizationCode
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_InvalidAuthorizationCodeReturnsNull()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/authenticate");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Code = "38323A4B-6CB2-41B8-B457-1951987CB383",
            GrantType = GrantTypes.AuthorizationCode
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_ValidAuthorizationCodeReturnsExpectedIdentity()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/authenticate");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("authorization_code", context.Token);
                    Assert.Equal([TokenTypeHints.AuthorizationCode], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AuthorizationCode)
                        .SetClaim(Claims.Subject, "Bob le Magnifique")
                        .SetPresenters("Fabrikam");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Code = "authorization_code",
            GrantType = GrantTypes.AuthorizationCode
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_RequestTokenPrincipalIsNotPopulatedWhenRequestTokenIsMissing()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetAuthorizationEndpointUris("/authenticate");

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.Null(context.RequestTokenPrincipal);

                    return default;
                });

                builder.SetOrder(int.MaxValue);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });
    }

    [Fact]
    public async Task ProcessAuthentication_RequestTokenPrincipalIsNotPopulatedWhenRequestTokenIsInvalid()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetAuthorizationEndpointUris("/authenticate");

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.Null(context.RequestTokenPrincipal);

                    return default;
                });

                builder.SetOrder(int.MaxValue);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = RequestUris.Prefixes.Generic + "request_token"
        });
    }

    [Fact]
    public async Task ProcessAuthentication_RequestTokenPrincipalIsPopulatedWhenRequestTokenTypeIsInvalid()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetAuthorizationEndpointUris("/authenticate");

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("request_token", context.Token);
                    Assert.Equal([TokenTypeHints.Private.RequestToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.Private.RequestToken)
                        .SetClaim(Claims.Private.RequestTokenType, RequestTokenTypes.Private.CachedEndSessionRequest);

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.NotNull(context.RequestTokenPrincipal);
                    Assert.NotNull(context.RequestTokenPrincipal.GetClaim(Claims.Private.RequestParameters));

                    return default;
                });

                builder.SetOrder(int.MaxValue);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = RequestUris.Prefixes.Generic + "request_token"
        });
    }

    [Fact]
    public async Task ProcessAuthentication_RequestTokenPrincipalIsPopulatedWhenRequestTokenIsValid()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetAuthorizationEndpointUris("/authenticate");

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("request_token", context.Token);
                    Assert.Equal([TokenTypeHints.Private.RequestToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.Private.RequestToken)
                        .SetClaim(Claims.Private.RequestTokenType, RequestTokenTypes.Private.PushedAuthorizationRequest)
                        .SetClaim(Claims.Private.RequestParameters, "{}");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessAuthenticationContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    // Assert
                    Assert.NotNull(context.RequestTokenPrincipal);
                    Assert.NotNull(context.RequestTokenPrincipal.GetClaim(Claims.Private.RequestParameters));

                    return default;
                });

                builder.SetOrder(ValidateRequestTokenType.Descriptor.Order + 1);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            RequestUri = RequestUris.Prefixes.Generic + "request_token"
        });
    }

    [Fact]
    public async Task ProcessAuthentication_MissingRefreshTokenReturnsNull()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/authenticate");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = null
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_InvalidRefreshTokenReturnsNull()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/authenticate");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "38323A4B-6CB2-41B8-B457-1951987CB383"
        });

        // Assert
        Assert.Null((string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessAuthentication_ValidRefreshTokenReturnsExpectedIdentity()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/authenticate");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("refresh_token", context.Token);
                    Assert.Equal([TokenTypeHints.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.RefreshToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/authenticate", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "refresh_token"
        });

        // Assert
        Assert.Equal("Bob le Magnifique", (string?) response[Claims.Subject]);
    }

    [Fact]
    public async Task ProcessChallenge_UnknownEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/challenge", new OpenIddictRequest());
        });

        Assert.Equal(SR.GetResourceString(SR.ID0006), exception.Message);
    }

    [Fact]
    public async Task ProcessChallenge_InvalidEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetConfigurationEndpointUris("/challenge");

            options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.GetAsync("/challenge");
        });

        Assert.Equal(SR.GetResourceString(SR.ID0006), exception.Message);
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsDefaultErrorForAuthorizationRequestsWhenNoneIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetAuthorizationEndpointUris("/challenge");

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.Code,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Equal(Errors.AccessDenied, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2015), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2015), response.ErrorUri);
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsDefaultErrorForTokenRequestsWhenNoneIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal(Errors.InvalidGrant, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2024), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2024), response.ErrorUri);
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsDefaultErrorForUserInfoRequestsWhenNoneIsSpecified()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetUserInfoEndpointUris("/challenge");

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("SlAV32hkKG", context.Token);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AccessToken)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<HandleUserInfoRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge", new OpenIddictRequest
        {
            AccessToken = "SlAV32hkKG"
        });

        // Assert
        Assert.Equal(Errors.InsufficientAccess, response.Error);
        Assert.Equal(SR.GetResourceString(SR.ID2025), response.ErrorDescription);
        Assert.Equal(SR.FormatID8000(SR.ID2025), response.ErrorUri);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ProcessChallenge_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessChallengeContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ProcessChallenge_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessChallengeContext>(builder =>
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
        var response = await client.PostAsync("/challenge", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ProcessChallenge_ReturnsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetTokenEndpointUris("/challenge");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));

            options.AddEventHandler<ProcessChallengeContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Parameters["boolean_parameter"] = true;
                    context.Parameters["integer_parameter"] = 42;
                    context.Parameters["string_parameter"] = "Bob l'Eponge";
                    context.Parameters["array_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]");
                    context.Parameters["object_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}");
#if SUPPORTS_JSON_NODES
                    context.Parameters["node_array_parameter"] = new JsonArray("Contoso", "Fabrikam");
                    context.Parameters["node_object_parameter"] = new JsonObject { ["parameter"] = "value" };
#endif
                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/challenge", new OpenIddictRequest
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
    public async Task ProcessSignIn_UnknownEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/signin", new OpenIddictRequest());
        });

        Assert.Equal(SR.GetResourceString(SR.ID0010), exception.Message);
    }

    [Fact]
    public async Task ProcessSignIn_InvalidEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetConfigurationEndpointUris("/signin");

            options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.GetAsync("/signin");
        });

        Assert.Equal(SR.GetResourceString(SR.ID0010), exception.Message);
    }

    [Fact]
    public async Task ProcessSignIn_NullIdentityCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });
        });

        Assert.Equal(SR.GetResourceString(SR.ID0011), exception.Message);
    }

    [Fact]
    public async Task ProcessSignIn_NullAuthenticationTypeCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/token", new OpenIddictRequest
            {
                GrantType = GrantTypes.Password,
                Username = "johndoe",
                Password = "A3ddj3w"
            });
        });

        Assert.Equal(SR.GetResourceString(SR.ID0014), exception.Message);
    }

    [Fact]
    public async Task ProcessSignIn_AuthenticatedIdentityFromDeviceAuthorizationEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleDeviceAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Test"));

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/device", new OpenIddictRequest
            {
                ClientId = "Fabrikam"
            });
        });

        Assert.Equal(SR.GetResourceString(SR.ID0012), exception.Message);
    }

    [Fact]
    public async Task ProcessSignIn_MissingSubjectCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"));

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

        Assert.Equal(SR.GetResourceString(SR.ID0015), exception.Message);
    }

    [Fact]
    public async Task ProcessSignIn_NonNullSubjectFromDeviceAuthorizationEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleDeviceAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity())
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/connect/device", new OpenIddictRequest
            {
                ClientId = "Fabrikam"
            });
        });

        Assert.Equal(SR.GetResourceString(SR.ID0013), exception.Message);
    }

    [Fact]
    public async Task ProcessSignIn_InvalidClaimValueTypeCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, 42);

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

        Assert.Equal(SR.FormatID0424(Claims.Subject), exception.Message);
    }

    [Fact]
    public async Task ProcessSignIn_ValidClaimValueTypeDoesNotCauseAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    var identity = new ClaimsIdentity("Bearer")
                        .SetTokenType(TokenTypeHints.AuthorizationCode)
                        .SetPresenters("Fabrikam")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    identity.AddClaim(new Claim(Claims.AuthenticationMethodReference,
                        """["value"]""", JsonClaimValueTypes.JsonArray));

                    context.Principal = new ClaimsPrincipal(identity);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_ScopeDefaultsToOpenId()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal([Scopes.OpenId], context.Principal!.GetScopes(), StringComparer.Ordinal);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_ResourcesAreInferredFromAudiences()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetAudiences("http://www.fabrikam.com/")
                        .SetScopes(Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal(["http://www.fabrikam.com/"], context.Principal!.GetResources(), StringComparer.Ordinal);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotNull(response.AccessToken);
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_AllowsOverridingDefaultTokensSelection()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.GenerateAccessToken = context.IncludeAccessToken = false;
                    context.GenerateAuthorizationCode = context.IncludeAuthorizationCode = true;
                    context.GenerateDeviceCode = context.IncludeDeviceCode = true;
                    context.GenerateIdentityToken = context.IncludeIdentityToken = true;
                    context.GenerateRefreshToken = context.IncludeRefreshToken = true;
                    context.GenerateUserCode = context.IncludeUserCode = true;

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Null(response.AccessToken);
        Assert.NotNull(response.Code);
        Assert.NotNull(response.DeviceCode);
        Assert.NotNull(response.IdToken);
        Assert.NotNull(response.RefreshToken);
        Assert.NotNull(response.UserCode);
    }

    [Fact]
    public async Task ProcessSignIn_NoTokenIsReturnedForNoneFlowRequests()
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

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.False(context.GenerateAccessToken);
                    Assert.False(context.GenerateAuthorizationCode);
                    Assert.False(context.GenerateDeviceCode);
                    Assert.False(context.GenerateIdentityToken);
                    Assert.False(context.GenerateRefreshToken);
                    Assert.False(context.GenerateUserCode);
                    Assert.False(context.IncludeAccessToken);
                    Assert.False(context.IncludeAuthorizationCode);
                    Assert.False(context.IncludeDeviceCode);
                    Assert.False(context.IncludeIdentityToken);
                    Assert.False(context.IncludeRefreshToken);
                    Assert.False(context.IncludeUserCode);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/authorize", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Nonce = "n-0S6_WzA2Mj",
            RedirectUri = "http://www.fabrikam.com/path",
            ResponseType = ResponseTypes.None,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.Null(response.AccessToken);
        Assert.Null(response.Code);
        Assert.Null(response.DeviceCode);
        Assert.Null(response.IdToken);
        Assert.Null(response.RefreshToken);
        Assert.Null(response.UserCode);
    }

    [Theory]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    [InlineData("id_token token")]
    [InlineData("token")]
    public async Task ProcessSignIn_AnAccessTokenIsReturnedForImplicitAndHybridFlowRequests(string type)
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

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateAccessToken);
                    Assert.True(context.IncludeAccessToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
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
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnAccessTokenIsReturnedForCodeGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                    Assert.Equal([TokenTypeHints.AuthorizationCode], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AuthorizationCode)
                        .SetPresenters("Fabrikam")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateAccessToken);
                    Assert.True(context.IncludeAccessToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Code = "SplxlOBeZQQYbYS6WxSbIA",
            GrantType = GrantTypes.AuthorizationCode
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnAccessTokenIsReturnedForDeviceGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", context.Token);
                    Assert.Equal([TokenTypeHints.DeviceCode], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity())
                        .SetTokenType(TokenTypeHints.DeviceCode)
                        .SetPresenters("Fabrikam");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateAccessToken);
                    Assert.True(context.IncludeAccessToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            DeviceCode = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            GrantType = GrantTypes.DeviceCode
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnAccessTokenIsReturnedForRefreshTokenGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeHints.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.RefreshToken)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateAccessToken);
                    Assert.True(context.IncludeAccessToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnAccessTokenIsReturnedForPasswordGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateAccessToken);
                    Assert.True(context.IncludeAccessToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnAccessTokenIsReturnedForClientCredentialsGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateAccessToken);
                    Assert.True(context.IncludeAccessToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
            GrantType = GrantTypes.ClientCredentials,
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnAccessTokenIsReturnedForCustomGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateAccessToken);
                    Assert.True(context.IncludeAccessToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = "urn:ietf:params:oauth:grant-type:custom_grant"
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Theory]
    [InlineData("code")]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("code token")]
    public async Task ProcessSignIn_AnAuthorizationCodeIsReturnedForCodeAndHybridFlowRequests(string type)
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

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateAuthorizationCode);
                    Assert.True(context.IncludeAuthorizationCode);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
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
        Assert.NotNull(response.Code);
    }

    [Fact]
    public async Task ProcessSignIn_ADeviceCodeIsReturnedForDeviceAuthorizationRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateDeviceCode);
                    Assert.True(context.IncludeDeviceCode);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.NotNull(response.DeviceCode);
    }

    [Fact]
    public async Task ProcessSignIn_ScopesCanBeOverriddenForRefreshTokenRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.RegisterScopes(Scopes.Profile);

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeHints.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.RefreshToken)
                        .SetScopes(Scopes.Profile, Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal([Scopes.Profile], context.AccessTokenPrincipal!.GetScopes(), StringComparer.Ordinal);

                    return default;
                });

                builder.SetOrder(PrepareAccessTokenPrincipal.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8",
            Scope = Scopes.Profile
        });

        // Assert
        Assert.NotNull(response.AccessToken);
    }

    [Fact]
    public async Task ProcessSignIn_NoRefreshTokenIsReturnedWhenOfflineAccessScopeIsNotGranted()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.False(context.GenerateRefreshToken);
                    Assert.False(context.IncludeRefreshToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Null(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_ARefreshTokenIsReturnedForCodeGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                    Assert.Equal([TokenTypeHints.AuthorizationCode], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AuthorizationCode)
                        .SetPresenters("Fabrikam")
                        .SetScopes(Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateRefreshToken);
                    Assert.True(context.IncludeRefreshToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Code = "SplxlOBeZQQYbYS6WxSbIA",
            GrantType = GrantTypes.AuthorizationCode
        });

        // Assert
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_ARefreshTokenIsReturnedForDeviceGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", context.Token);
                    Assert.Equal([TokenTypeHints.DeviceCode], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity())
                        .SetTokenType(TokenTypeHints.DeviceCode)
                        .SetPresenters("Fabrikam");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetScopes(Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateRefreshToken);
                    Assert.True(context.IncludeRefreshToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            DeviceCode = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            GrantType = GrantTypes.DeviceCode
        });

        // Assert
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_ARefreshTokenIsReturnedForRefreshTokenGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeHints.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.RefreshToken)
                        .SetScopes(Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateRefreshToken);
                    Assert.True(context.IncludeRefreshToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_ARefreshTokenIsReturnedForPasswordGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateRefreshToken);
                    Assert.True(context.IncludeRefreshToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetScopes(Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_ARefreshTokenIsReturnedForClientCredentialsGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateRefreshToken);
                    Assert.True(context.IncludeRefreshToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetScopes(Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
            GrantType = GrantTypes.ClientCredentials,
        });

        // Assert
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_ARefreshTokenIsReturnedForCustomGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateRefreshToken);
                    Assert.True(context.IncludeRefreshToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetScopes(Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = "urn:ietf:params:oauth:grant-type:custom_grant"
        });

        // Assert
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_NoIdentityTokenIsReturnedWhenOfflineAccessScopeIsNotGranted()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.False(context.GenerateIdentityToken);
                    Assert.False(context.IncludeIdentityToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Null(response.IdToken);
    }

    [Theory]
    [InlineData("code id_token")]
    [InlineData("code id_token token")]
    [InlineData("id_token")]
    [InlineData("id_token token")]
    public async Task ProcessSignIn_AnIdentityTokenIsReturnedForImplicitAndHybridFlowRequests(string type)
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

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateIdentityToken);
                    Assert.True(context.IncludeIdentityToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
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
        Assert.NotNull(response.IdToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnIdentityTokenIsReturnedForCodeGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                    Assert.Equal([TokenTypeHints.AuthorizationCode], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AuthorizationCode)
                        .SetPresenters("Fabrikam")
                        .SetScopes(Scopes.OpenId)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateIdentityToken);
                    Assert.True(context.IncludeIdentityToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Code = "SplxlOBeZQQYbYS6WxSbIA",
            GrantType = GrantTypes.AuthorizationCode
        });

        // Assert
        Assert.NotNull(response.IdToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnIdentityTokenIsReturnedForDeviceGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS", context.Token);
                    Assert.Equal([TokenTypeHints.DeviceCode], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity())
                        .SetTokenType(TokenTypeHints.DeviceCode)
                        .SetPresenters("Fabrikam");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetScopes(Scopes.OpenId)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateIdentityToken);
                    Assert.True(context.IncludeIdentityToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            DeviceCode = "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            GrantType = GrantTypes.DeviceCode
        });

        // Assert
        Assert.NotNull(response.IdToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnIdentityTokenIsReturnedForRefreshTokenGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeHints.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.RefreshToken)
                        .SetScopes(Scopes.OpenId)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateIdentityToken);
                    Assert.True(context.IncludeIdentityToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.NotNull(response.IdToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnIdentityTokenIsReturnedForPasswordGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateIdentityToken);
                    Assert.True(context.IncludeIdentityToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.NotNull(response.IdToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnIdentityTokenIsReturnedForClientCredentialsGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateIdentityToken);
                    Assert.True(context.IncludeIdentityToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            ClientSecret = "7Fjfp0ZBr1KtDRbnfVdmIw",
            GrantType = GrantTypes.ClientCredentials,
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.NotNull(response.IdToken);
    }

    [Fact]
    public async Task ProcessSignIn_AnIdentityTokenIsReturnedForCustomGrantRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.AllowCustomFlow("urn:ietf:params:oauth:grant-type:custom_grant");

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateIdentityToken);
                    Assert.True(context.IncludeIdentityToken);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = "urn:ietf:params:oauth:grant-type:custom_grant",
            Scope = Scopes.OpenId
        });

        // Assert
        Assert.NotNull(response.IdToken);
    }

    [Fact]
    public async Task ProcessSignIn_AUserCodeIsReturnedForDeviceAuthorizationRequests()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleAuthorizationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity());

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.True(context.GenerateUserCode);
                    Assert.True(context.IncludeUserCode);

                    return default;
                });

                builder.SetOrder(EvaluateGeneratedTokens.Descriptor.Order + 500);
            });
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/device", new OpenIddictRequest
        {
            ClientId = "Fabrikam"
        });

        // Assert
        Assert.NotNull(response.UserCode);
    }

    [Fact]
    public async Task ProcessSignIn_PrivateClaimsAreAutomaticallyRestored()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeHints.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.RefreshToken)
                        .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                        .SetClaim(Claims.Subject, "Bob le Bricoleur")
                        .SetClaim(Claims.Prefixes.Private + "_private_claim", "value");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.AddEventHandler<ProcessSignInContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal([Scopes.OpenId, Scopes.OfflineAccess], context.Principal!.GetScopes(), StringComparer.Ordinal);
                    Assert.Equal("value", context.Principal!.GetClaim(Claims.Prefixes.Private + "_private_claim"));

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.NotNull(response.IdToken);
        Assert.NotNull(response.RefreshToken);
    }

    [Fact]
    public async Task ProcessSignIn_AuthorizationCodeIsAutomaticallyRedeemed()
    {
        // Arrange
        var token = new OpenIddictToken();

        var manager = CreateTokenManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                .ReturnsAsync(token);

            mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

            mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(TokenTypeHints.AuthorizationCode);

            mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new OpenIddictToken());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("SplxlOBeZQQYbYS6WxSbIA", context.Token);
                    Assert.Equal([TokenTypeHints.AuthorizationCode], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.AuthorizationCode)
                        .SetPresenters("Fabrikam")
                        .SetTokenId("3E228451-1555-46F7-A471-951EFBA23A56")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(CreateApplicationManager(mock =>
            {
                var application = new OpenIddictApplication();

                mock.Setup(manager => manager.FindByClientIdAsync("Fabrikam", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(application);

                mock.Setup(manager => manager.HasClientTypeAsync(application, ClientTypes.Public, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(true);

                mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableDictionary.Create<string, string>()
                        .SetItem(Settings.TokenLifetimes.AccessToken, TimeSpan.FromMinutes(5).ToString("c", CultureInfo.InvariantCulture)));
            }));

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            ClientId = "Fabrikam",
            Code = "SplxlOBeZQQYbYS6WxSbIA",
            GrantType = GrantTypes.AuthorizationCode,
            RedirectUri = "http://www.fabrikam.com/path"
        });

        // Assert
        Mock.Get(manager).Verify(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ProcessSignIn_RefreshTokenIsAutomaticallyRedeemedWhenRollingTokensAreEnabled()
    {
        // Arrange
        var token = new OpenIddictToken();

        var manager = CreateTokenManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                .ReturnsAsync(token);

            mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync("60FFF7EA-F98E-437B-937E-5073CC313103");

            mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(TokenTypeHints.RefreshToken);

            mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);

            mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new OpenIddictToken());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.DisableAuthorizationStorage();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeHints.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.RefreshToken)
                        .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                        .SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.NotNull(response.RefreshToken);

        Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ProcessSignIn_RefreshTokenIsNotRedeemedWhenRollingTokensAreDisabled()
    {
        // Arrange
        var token = new OpenIddictToken();

        var manager = CreateTokenManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()))
                .ReturnsAsync(token);

            mock.Setup(manager => manager.GetTypeAsync(token, It.IsAny<CancellationToken>()))
                .ReturnsAsync(TokenTypeHints.RefreshToken);

            mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Redeemed, It.IsAny<CancellationToken>()))
                .ReturnsAsync(false);

            mock.Setup(manager => manager.HasStatusAsync(token, Statuses.Valid, It.IsAny<CancellationToken>()))
                .ReturnsAsync(true);

            mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new OpenIddictToken());
        });

        await using var server = await CreateServerAsync(options =>
        {
            options.DisableAuthorizationStorage();
            options.DisableRollingRefreshTokens();

            options.AddEventHandler<ValidateTokenContext>(builder =>
            {
                builder.UseInlineHandler(context =>
                {
                    Assert.Equal("8xLOxBtZp8", context.Token);
                    Assert.Equal([TokenTypeHints.RefreshToken], context.ValidTokenTypes);

                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetTokenType(TokenTypeHints.RefreshToken)
                        .SetScopes(Scopes.OpenId, Scopes.OfflineAccess)
                        .SetTokenId("60FFF7EA-F98E-437B-937E-5073CC313103")
                        .SetClaim(Claims.Subject, "Bob le Bricoleur");

                    return default;
                });

                builder.SetOrder(ValidateIdentityModelToken.Descriptor.Order - 500);
            });

            options.Services.AddSingleton(manager);
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.RefreshToken,
            RefreshToken = "8xLOxBtZp8"
        });

        // Assert
        Assert.NotNull(response.RefreshToken);

        Mock.Get(manager).Verify(manager => manager.FindByIdAsync("60FFF7EA-F98E-437B-937E-5073CC313103", It.IsAny<CancellationToken>()), Times.AtLeastOnce());
        Mock.Get(manager).Verify(manager => manager.TryRedeemAsync(token, It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ProcessSignIn_AdHocAuthorizationIsAutomaticallyCreated()
    {
        // Arrange
        var token = new OpenIddictToken();

        var manager = CreateAuthorizationManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new OpenIddictAuthorization());

            mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictAuthorizationDescriptor>(), It.IsAny<CancellationToken>()))
                .ReturnsAsync(new OpenIddictAuthorization());
        });

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

                mock.Setup(manager => manager.GetIdAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableDictionary.Create<string, string>());
            }));

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);
            }));

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
            ResponseType = ResponseTypes.Code,
        });

        // Assert
        Assert.NotNull(response.Code);

        Mock.Get(manager).Verify(manager => manager.CreateAsync(
            It.Is<OpenIddictAuthorizationDescriptor>(descriptor =>
                descriptor.ApplicationId == "3E228451-1555-46F7-A471-951EFBA23A56" &&
                descriptor.CreationDate != null &&
                descriptor.Subject == "Bob le Magnifique" &&
                descriptor.Type == AuthorizationTypes.AdHoc),
            It.IsAny<CancellationToken>()), Times.Once());
    }

    [Fact]
    public async Task ProcessSignIn_AdHocAuthorizationIsNotCreatedWhenAuthorizationStorageIsDisabled()
    {
        // Arrange
        var token = new OpenIddictToken();

        var manager = CreateAuthorizationManager(mock =>
        {
            mock.Setup(manager => manager.FindByIdAsync("1AF06AB2-A0FC-4E3D-86AF-E04DA8C7BE70", It.IsAny<CancellationToken>()))
                .ReturnsAsync(new OpenIddictAuthorization());
        });

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

                mock.Setup(manager => manager.GetIdAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.GetSettingsAsync(application, It.IsAny<CancellationToken>()))
                    .ReturnsAsync(ImmutableDictionary.Create<string, string>());
            }));

            options.Services.AddSingleton(CreateTokenManager(mock =>
            {
                mock.Setup(manager => manager.CreateAsync(It.IsAny<OpenIddictTokenDescriptor>(), It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);

                mock.Setup(manager => manager.GetIdAsync(token, It.IsAny<CancellationToken>()))
                    .ReturnsAsync("3E228451-1555-46F7-A471-951EFBA23A56");

                mock.Setup(manager => manager.FindByIdAsync("3E228451-1555-46F7-A471-951EFBA23A56", It.IsAny<CancellationToken>()))
                    .ReturnsAsync(token);
            }));

            options.Services.AddSingleton(manager);

            options.DisableAuthorizationStorage();

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
        });

        // Assert
        Assert.NotNull(response.Code);

        Mock.Get(manager).Verify(manager => manager.CreateAsync(It.IsAny<OpenIddictAuthorizationDescriptor>(), It.IsAny<CancellationToken>()), Times.Never());
    }

    [Fact]
    public async Task ProcessSignIn_ExpiresInIsReturnedWhenExpirationDateIsKnown()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.NotNull(response.ExpiresIn);
    }

    [Fact]
    public async Task ProcessSignIn_ScopesAreReturnedWhenTheyDifferFromRequestedScopes()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.RegisterScopes(Scopes.Phone, Scopes.Profile);

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetScopes(Scopes.Profile)
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w",
            Scope = "openid phone profile"
        });

        // Assert
        Assert.Equal(Scopes.Profile, response.Scope);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ProcessSignIn_AllowsRejectingRequest(string error, string description, string uri)
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

            options.AddEventHandler<ProcessSignInContext>(builder =>
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
    public async Task ProcessSignIn_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
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
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
        {
            GrantType = GrantTypes.Password,
            Username = "johndoe",
            Password = "A3ddj3w"
        });

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ProcessSignIn_ReturnsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleTokenRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Principal = new ClaimsPrincipal(new ClaimsIdentity("Bearer"))
                        .SetClaim(Claims.Subject, "Bob le Magnifique");

                    return default;
                }));

            options.AddEventHandler<ProcessSignInContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Parameters["boolean_parameter"] = true;
                    context.Parameters["integer_parameter"] = 42;
                    context.Parameters["string_parameter"] = "Bob l'Eponge";
                    context.Parameters["array_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"[""Contoso"",""Fabrikam""]");
                    context.Parameters["object_parameter"] = JsonSerializer.Deserialize<JsonElement>(@"{""parameter"":""value""}");
#if SUPPORTS_JSON_NODES
                    context.Parameters["node_array_parameter"] = new JsonArray("Contoso", "Fabrikam");
                    context.Parameters["node_object_parameter"] = new JsonObject { ["parameter"] = "value" };
#endif
                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/token", new OpenIddictRequest
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
    public async Task ProcessSignOut_UnknownEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options => options.EnableDegradedMode());
        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.PostAsync("/signout", new OpenIddictRequest());
        });

        Assert.Equal(SR.GetResourceString(SR.ID0024), exception.Message);
    }

    [Fact]
    public async Task ProcessSignOut_InvalidEndpointCausesAnException()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();
            options.SetConfigurationEndpointUris("/signout");

            options.AddEventHandler<HandleConfigurationRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SkipRequest();

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act and assert
        var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
        {
            return client.GetAsync("/signout");
        });

        Assert.Equal(SR.GetResourceString(SR.ID0024), exception.Message);
    }

    [Theory]
    [InlineData("custom_error", null, null)]
    [InlineData("custom_error", "custom_description", null)]
    [InlineData("custom_error", "custom_description", "custom_uri")]
    [InlineData(null, "custom_description", null)]
    [InlineData(null, "custom_description", "custom_uri")]
    [InlineData(null, null, "custom_uri")]
    [InlineData(null, null, null)]
    public async Task ProcessSignOut_AllowsRejectingRequest(string error, string description, string uri)
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SignOut();

                    return default;
                }));

            options.AddEventHandler<ProcessSignOutContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Reject(error, description, uri);

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/endsession", new OpenIddictRequest());

        // Assert
        Assert.Equal(error ?? Errors.InvalidRequest, response.Error);
        Assert.Equal(description, response.ErrorDescription);
        Assert.Equal(uri, response.ErrorUri);
    }

    [Fact]
    public async Task ProcessSignOut_AllowsHandlingResponse()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SignOut();

                    return default;
                }));

            options.AddEventHandler<ProcessSignOutContext>(builder =>
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
        var response = await client.PostAsync("/connect/endsession", new OpenIddictRequest());

        // Assert
        Assert.Equal("Bob le Bricoleur", (string?) response["name"]);
    }

    [Fact]
    public async Task ProcessSignOut_ReturnsCustomParameters()
    {
        // Arrange
        await using var server = await CreateServerAsync(options =>
        {
            options.EnableDegradedMode();

            options.AddEventHandler<HandleEndSessionRequestContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.SignOut();

                    return default;
                }));

            options.AddEventHandler<ProcessSignOutContext>(builder =>
                builder.UseInlineHandler(context =>
                {
                    context.Parameters["boolean_parameter"] = true;
                    context.Parameters["integer_parameter"] = 42;
                    context.Parameters["string_parameter"] = "Bob l'Eponge";

                    return default;
                }));
        });

        await using var client = await server.CreateClientAsync();

        // Act
        var response = await client.PostAsync("/connect/endsession", new OpenIddictRequest
        {
            PostLogoutRedirectUri = "http://www.fabrikam.com/path",
            State = "af0ifjsldkj"
        });

        // Assert
        Assert.True((bool) response["boolean_parameter"]);
        Assert.Equal(42, (long) response["integer_parameter"]);
        Assert.Equal("Bob l'Eponge", (string?) response["string_parameter"]);
    }

    protected virtual void ConfigureServices(IServiceCollection services)
    {
        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.SetDefaultApplicationEntity<OpenIddictApplication>()
                       .SetDefaultAuthorizationEntity<OpenIddictAuthorization>()
                       .SetDefaultScopeEntity<OpenIddictScope>()
                       .SetDefaultTokenEntity<OpenIddictToken>();

                options.Services.AddSingleton(CreateApplicationManager())
                                .AddSingleton(CreateAuthorizationManager())
                                .AddSingleton(CreateScopeManager())
                                .AddSingleton(CreateTokenManager());
            })

            .AddServer(options =>
            {
                // Enable the tested endpoints.
                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetConfigurationEndpointUris("/.well-known/openid-configuration")
                       .SetJsonWebKeySetEndpointUris("/.well-known/jwks")
                       .SetDeviceAuthorizationEndpointUris("/connect/device")
                       .SetIntrospectionEndpointUris("/connect/introspect")
                       .SetEndSessionEndpointUris("/connect/endsession")
                       .SetPushedAuthorizationEndpointUris("/connect/par")
                       .SetRevocationEndpointUris("/connect/revoke")
                       .SetTokenEndpointUris("/connect/token")
                       .SetUserInfoEndpointUris("/connect/userinfo")
                       .SetEndUserVerificationEndpointUris("/connect/verification");

                options.AllowAuthorizationCodeFlow()
                       .AllowClientCredentialsFlow()
                       .AllowDeviceAuthorizationFlow()
                       .AllowHybridFlow()
                       .AllowImplicitFlow()
                       .AllowNoneFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                // Accept anonymous clients by default.
                options.AcceptAnonymousClients();

                // Disable permission enforcement by default.
                options.IgnoreEndpointPermissions()
                       .IgnoreGrantTypePermissions()
                       .IgnoreResponseTypePermissions()
                       .IgnoreScopePermissions();

                options.AddSigningCertificate(
                    assembly: typeof(OpenIddictServerIntegrationTests).Assembly,
                    resource: "OpenIddict.Server.IntegrationTests.Certificate.pfx",
                    password: "Owin.Security.OpenIdConnect.Server");

                options.AddEncryptionCertificate(
                    assembly: typeof(OpenIddictServerIntegrationTests).Assembly,
                    resource: "OpenIddict.Server.IntegrationTests.Certificate.pfx",
                    password: "Owin.Security.OpenIdConnect.Server");

                options.AddEventHandler<ValidateAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<ValidateDeviceAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<ValidateEndSessionRequestContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<ValidateEndUserVerificationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<ValidatePushedAuthorizationRequestContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<ProcessAuthenticationContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<ValidateTokenContext>(builder =>
                    builder.UseInlineHandler(context => default));

                options.AddEventHandler<GenerateTokenContext>(builder =>
                    builder.UseInlineHandler(context => default));
            });
    }

    protected abstract ValueTask<OpenIddictServerIntegrationTestServer> CreateServerAsync(
        Action<OpenIddictServerBuilder>? configuration = null);

    protected OpenIddictApplicationManager<OpenIddictApplication> CreateApplicationManager(
        Action<Mock<OpenIddictApplicationManager<OpenIddictApplication>>>? configuration = null)
    {
        var manager = new Mock<OpenIddictApplicationManager<OpenIddictApplication>>(
            Mock.Of<IOpenIddictApplicationCache<OpenIddictApplication>>(),
            OutputHelper.ToLogger<OpenIddictApplicationManager<OpenIddictApplication>>(),
            Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(),
            Mock.Of<IOpenIddictApplicationStoreResolver>());

        configuration?.Invoke(manager);

        return manager.Object;
    }

    protected OpenIddictAuthorizationManager<OpenIddictAuthorization> CreateAuthorizationManager(
        Action<Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>>? configuration = null)
    {
        var manager = new Mock<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(
            Mock.Of<IOpenIddictAuthorizationCache<OpenIddictAuthorization>>(),
            OutputHelper.ToLogger<OpenIddictAuthorizationManager<OpenIddictAuthorization>>(),
            Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(),
            Mock.Of<IOpenIddictAuthorizationStoreResolver>());

        configuration?.Invoke(manager);

        return manager.Object;
    }

    protected OpenIddictScopeManager<OpenIddictScope> CreateScopeManager(
        Action<Mock<OpenIddictScopeManager<OpenIddictScope>>>? configuration = null)
    {
        var manager = new Mock<OpenIddictScopeManager<OpenIddictScope>>(
            Mock.Of<IOpenIddictScopeCache<OpenIddictScope>>(),
            OutputHelper.ToLogger<OpenIddictScopeManager<OpenIddictScope>>(),
            Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(),
            Mock.Of<IOpenIddictScopeStoreResolver>());

        configuration?.Invoke(manager);

        return manager.Object;
    }

    protected OpenIddictTokenManager<OpenIddictToken> CreateTokenManager(
        Action<Mock<OpenIddictTokenManager<OpenIddictToken>>>? configuration = null)
    {
        var manager = new Mock<OpenIddictTokenManager<OpenIddictToken>>(
            Mock.Of<IOpenIddictTokenCache<OpenIddictToken>>(),
            OutputHelper.ToLogger<OpenIddictTokenManager<OpenIddictToken>>(),
            Mock.Of<IOptionsMonitor<OpenIddictCoreOptions>>(),
            Mock.Of<IOpenIddictTokenStoreResolver>());

        configuration?.Invoke(manager);

        return manager.Object;
    }

    public class OpenIddictApplication { }
    public class OpenIddictAuthorization { }
    public class OpenIddictScope { }
    public class OpenIddictToken { }
}

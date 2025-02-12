
/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text.Json;
using Xunit;

namespace OpenIddict.Abstractions.Tests.Primitives;

public class OpenIddictRequestTests
{
    public static IEnumerable<object[]> Properties
    {
        get
        {
            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.AccessToken),
                /* name: */ Parameters.AccessToken,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.AcrValues),
                /* name: */ Parameters.AcrValues,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Assertion),
                /* name: */ Parameters.Assertion,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Audiences),
                /* name: */ Parameters.Audience,
                /* value: */ new OpenIddictParameter(["Fabrikam", "Contoso"])
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Claims),
                /* name: */ Parameters.Claims,
                /* value: */ new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""userinfo"": {}}"))
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.ClaimsLocales),
                /* name: */ Parameters.ClaimsLocales,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.ClientAssertion),
                /* name: */ Parameters.ClientAssertion,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.ClientAssertionType),
                /* name: */ Parameters.ClientAssertionType,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.ClientId),
                /* name: */ Parameters.ClientId,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.ClientSecret),
                /* name: */ Parameters.ClientSecret,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Code),
                /* name: */ Parameters.Code,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.CodeChallenge),
                /* name: */ Parameters.CodeChallenge,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.CodeChallengeMethod),
                /* name: */ Parameters.CodeChallengeMethod,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.CodeVerifier),
                /* name: */ Parameters.CodeVerifier,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.DeviceCode),
                /* name: */ Parameters.DeviceCode,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Display),
                /* name: */ Parameters.Display,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.GrantType),
                /* name: */ Parameters.GrantType,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.IdentityProvider),
                /* name: */ Parameters.IdentityProvider,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.IdToken),
                /* name: */ Parameters.IdToken,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.IdTokenHint),
                /* name: */ Parameters.IdTokenHint,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.LoginHint),
                /* name: */ Parameters.LoginHint,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Nonce),
                /* name: */ Parameters.Nonce,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.MaxAge),
                /* name: */ Parameters.MaxAge,
                /* value: */ new OpenIddictParameter((long?) 42)
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Password),
                /* name: */ Parameters.Password,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.PostLogoutRedirectUri),
                /* name: */ Parameters.PostLogoutRedirectUri,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Prompt),
                /* name: */ Parameters.Prompt,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.RedirectUri),
                /* name: */ Parameters.RedirectUri,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.RefreshToken),
                /* name: */ Parameters.RefreshToken,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Registration),
                /* name: */ Parameters.Registration,
                /* value: */ new OpenIddictParameter(JsonSerializer.Deserialize<JsonElement>(@"{""policy_uri"": ""http://www.fabrikam.com/policy""}"))
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Request),
                /* name: */ Parameters.Request,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.RequestUri),
                /* name: */ Parameters.RequestUri,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Resources),
                /* name: */ Parameters.Resource,
                /* value: */ new OpenIddictParameter(["https://fabrikam.com/", "https://contoso.com/"])
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.ResponseMode),
                /* name: */ Parameters.ResponseMode,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.ResponseType),
                /* name: */ Parameters.ResponseType,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Scope),
                /* name: */ Parameters.Scope,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.State),
                /* name: */ Parameters.State,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Token),
                /* name: */ Parameters.Token,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.TokenTypeHint),
                /* name: */ Parameters.TokenTypeHint,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.UiLocales),
                /* name: */ Parameters.UiLocales,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.UserCode),
                /* name: */ Parameters.UserCode,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };

            yield return new object[]
            {
                /* property: */ nameof(OpenIddictRequest.Username),
                /* name: */ Parameters.Username,
                /* value: */ new OpenIddictParameter("802A3E3E-DCCA-4EFC-89FA-7D82FE8C27E4")
            };
        }
    }

    [Theory]
    [MemberData(nameof(Properties))]
    public void PropertyGetter_ReturnsExpectedParameter(string property, string name, OpenIddictParameter value)
    {
        // Arrange
        var request = new OpenIddictRequest();
        request.SetParameter(name, value);

        // Act and assert
        Assert.Equal(value.Value, typeof(OpenIddictRequest).GetProperty(property)!.GetValue(request));
    }

    [Theory]
    [MemberData(nameof(Properties))]
    public void PropertySetter_AddsExpectedParameter(string property, string name, OpenIddictParameter value)
    {
        // Arrange
        var request = new OpenIddictRequest();

        // Act
        typeof(OpenIddictRequest).GetProperty(property)!.SetValue(request, value.Value);

        // Assert
        Assert.Equal(value, request.GetParameter(name));
    }
}

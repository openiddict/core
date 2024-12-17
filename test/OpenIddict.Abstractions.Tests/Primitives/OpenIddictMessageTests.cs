/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Xunit;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Abstractions.Tests.Primitives;

public class OpenIddictMessageTests
{
    [Fact]
    public void Constructor_ThrowsAnExceptionForInvalidJsonElement()
    {
        // Arrange, act and assert
        var exception = Assert.Throws<ArgumentException>(delegate
        {
            return new OpenIddictMessage(JsonSerializer.Deserialize<JsonElement>("[0,1,2,3]"));
        });

        Assert.Equal("parameters", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0189), exception.Message);
    }

    [Fact]
    public void Constructor_ThrowsAnExceptionForDuplicateParameters()
    {
        // Arrange, act and assert
        var exception = Assert.Throws<ArgumentException>(delegate
        {
            return new OpenIddictMessage(
            [
                new KeyValuePair<string, OpenIddictParameter>("parameter", "Fabrikam"),
                new KeyValuePair<string, OpenIddictParameter>("parameter", "Contoso")
            ]);
        });

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0191), exception.Message);
    }

    [Fact]
    public void Constructor_ImportsParameters()
    {
        // Arrange and act
        var message = new OpenIddictMessage(
        [
            new KeyValuePair<string, OpenIddictParameter>("parameter", 42)
        ]);

        // Assert
        Assert.Equal(42, (long) message.GetParameter("parameter"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void Constructor_IgnoresNullOrEmptyParameterNames(string name)
    {
        // Arrange and act
        var message = new OpenIddictMessage(
        [
            new KeyValuePair<string, OpenIddictParameter>(name, "Fabrikam")
        ]);

        // Assert
        Assert.Equal(0, message.Count);
    }

    [Fact]
    public void Constructor_PreservesEmptyParameters()
    {
        // Arrange and act
        var message = new OpenIddictMessage(
        [
            new KeyValuePair<string, OpenIddictParameter>("null-parameter", (string?) null),
            new KeyValuePair<string, OpenIddictParameter>("empty-parameter", string.Empty)
        ]);

        // Assert
        Assert.Equal(2, message.Count);
    }

    [Fact]
    public void Constructor_CombinesDuplicateParameters()
    {
        // Arrange and act
        var message = new OpenIddictMessage(
        [
            new KeyValuePair<string, string?>("parameter", "Fabrikam"),
            new KeyValuePair<string, string?>("parameter", "Contoso")
        ]);

        // Assert
        Assert.Equal(1, message.Count);
        Assert.Equal(["Fabrikam", "Contoso"], (string[]?) message.GetParameter("parameter"));
    }

    [Fact]
    public void Constructor_SupportsMultiValuedParameters()
    {
        // Arrange and act
        var message = new OpenIddictMessage(
        [
            new KeyValuePair<string, string?[]?>("parameter", ["Fabrikam", "Contoso"])
        ]);

        // Assert
        Assert.Equal(1, message.Count);
        Assert.Equal(["Fabrikam", "Contoso"], (string[]?) message.GetParameter("parameter"));
    }

    [Fact]
    public void Constructor_ExtractsSingleValuedParameters()
    {
        // Arrange and act
        var message = new OpenIddictMessage(
        [
            new KeyValuePair<string, string?[]?>("parameter", ["Fabrikam"])
        ]);

        // Assert
        Assert.Equal(1, message.Count);
        Assert.Equal("Fabrikam", message.GetParameter("parameter")?.Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void AddParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() =>
        {
            message.AddParameter(name, new OpenIddictParameter());
        });

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0190), exception.Message);
    }

    [Fact]
    public void AddParameter_AddsExpectedParameter()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act
        message.AddParameter("parameter", 42);

        // Assert
        Assert.Equal(42, message.GetParameter("parameter"));
    }

    [Fact]
    public void AddParameter_IsCaseSensitive()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act
        message.AddParameter("PARAMETER", 42);

        // Assert
        Assert.Null(message.GetParameter("parameter"));
    }

    [Fact]
    public void AddParameter_PreservesEmptyParameters()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act
        message.AddParameter("string", string.Empty);
        message.AddParameter("array", JsonSerializer.Deserialize<JsonElement>("[]"));
        message.AddParameter("object", JsonSerializer.Deserialize<JsonElement>("{}"));
        message.AddParameter("value", JsonSerializer.Deserialize<JsonElement>(
            @"{""property"":""""}").GetProperty("property").GetString());

#if SUPPORTS_JSON_NODES
        message.AddParameter("node_array", new JsonArray());
        message.AddParameter("node_object", new JsonObject());
        message.AddParameter("node_value", JsonValue.Create(string.Empty));
#endif

        // Assert
        Assert.Empty(((string?) message.GetParameter("string"))!);
        Assert.NotNull((JsonElement?) message.GetParameter("array"));
        Assert.NotNull((JsonElement?) message.GetParameter("object"));
        Assert.NotNull((JsonElement?) message.GetParameter("value"));

#if SUPPORTS_JSON_NODES
        Assert.NotNull((JsonNode?) message.GetParameter("node_array"));
        Assert.NotNull((JsonNode?) message.GetParameter("node_object"));
        Assert.NotNull((JsonNode?) message.GetParameter("node_value"));
#endif
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void GetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => message.GetParameter(name));

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0190), exception.Message);
    }

    [Fact]
    public void GetParameter_ReturnsExpectedParameter()
    {
        // Arrange
        var message = new OpenIddictMessage();

        message.SetParameter("parameter", 42);

        // Act and assert
        Assert.Equal(42, (int) message.GetParameter("parameter"));
    }

    [Fact]
    public void GetParameter_IsCaseSensitive()
    {
        // Arrange
        var message = new OpenIddictMessage();

        message.SetParameter("parameter", 42);

        // Act and assert
        Assert.Null(message.GetParameter("PARAMETER"));
    }

    [Fact]
    public void GetParameter_ReturnsNullForUnsetParameter()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act and assert
        Assert.Null(message.GetParameter("parameter"));
    }

    [Fact]
    public void GetParameters_EnumeratesParameters()
    {
        // Arrange
        var parameters = new Dictionary<string, OpenIddictParameter>
        {
            ["int"] = int.MaxValue,
            ["long"] = long.MaxValue,
            ["string"] = "value"
        };

        var message = new OpenIddictMessage(parameters);

        // Act and assert
        Assert.Equal(parameters, message.GetParameters());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void HasParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => message.HasParameter(name));

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0190), exception.Message);
    }

    [Theory]
    [InlineData("parameter", true)]
    [InlineData("PARAMETER", false)]
    [InlineData("missing_parameter", false)]
    public void HasParameter_ReturnsExpectedResult(string parameter, bool result)
    {
        // Arrange
        var message = new OpenIddictMessage();

        message.SetParameter("parameter", "value");

        // Act and assert
        Assert.Equal(result, message.HasParameter(parameter));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void RemoveParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => message.RemoveParameter(name));

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0190), exception.Message);
    }

    [Fact]
    public void RemoveParameter_RemovesExpectedParameter()
    {
        // Arrange
        var message = new OpenIddictMessage();
        message.AddParameter("parameter", 42);

        // Act
        message.RemoveParameter("parameter");

        // Assert
        Assert.Null(message.GetParameter("parameter"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void SetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act and assert
        var exception = Assert.Throws<ArgumentException>(() => message.SetParameter(name, null));

        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0190), exception.Message);
    }

    [Fact]
    public void SetParameter_AddsExpectedParameter()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act
        message.SetParameter("parameter", 42);

        // Assert
        Assert.Equal(42, message.GetParameter("parameter"));
    }

    [Fact]
    public void SetParameter_IsCaseSensitive()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act
        message.SetParameter("PARAMETER", 42);

        // Assert
        Assert.Null(message.GetParameter("parameter"));
    }

    [Fact]
    public void SetParameter_RemovesNullParameters()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act
        message.SetParameter("null", null);

        // Assert
        Assert.Empty(message.GetParameters());
    }

    [Fact]
    public void SetParameter_RemovesEmptyParameters()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act
        message.SetParameter("string", string.Empty);
        message.SetParameter("array", JsonSerializer.Deserialize<JsonElement>("[]"));
        message.SetParameter("object", JsonSerializer.Deserialize<JsonElement>("{}"));
        message.SetParameter("value", JsonSerializer.Deserialize<JsonElement>(
            @"{""property"":""""}").GetProperty("property").GetString());

#if SUPPORTS_JSON_NODES
        message.SetParameter("node_array", new JsonArray());
        message.SetParameter("node_object", new JsonObject());
        message.SetParameter("node_value", JsonValue.Create(string.Empty));
#endif

        // Assert
        Assert.Empty(message.GetParameters());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void TryGetParameter_ThrowsAnExceptionForNullOrEmptyName(string name)
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act
        var exception = Assert.Throws<ArgumentException>(() => message.TryGetParameter(name, out var parameter));

        // Assert
        Assert.Equal("name", exception.ParamName);
        Assert.StartsWith(SR.GetResourceString(SR.ID0190), exception.Message);
    }

    [Fact]
    public void TryGetParameter_ReturnsTrueAndExpectedParameter()
    {
        // Arrange
        var message = new OpenIddictMessage();
        message.SetParameter("parameter", 42);

        // Act and assert
        Assert.True(message.TryGetParameter("parameter", out var parameter));
        Assert.Equal(42, (long?) parameter.Value);
    }

    [Fact]
    public void TryGetParameter_ReturnsFalseForUnsetParameter()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act and assert
        Assert.False(message.TryGetParameter("parameter", out OpenIddictParameter parameter));
        Assert.Null(parameter.Value);
    }

    [Fact]
    public void ToString_ReturnsJsonRepresentation()
    {
        // Arrange
        var message = JsonSerializer.Deserialize<OpenIddictMessage>($$"""
            {
              "redirect_uris": [
                "https://client.example.org/callback",
                "https://client.example.org/callback2"
              ],
              "client_name": "My Example Client",
              "token_endpoint_auth_method": "client_secret_basic",
              "logo_uri": "https://client.example.org/logo.png",
              "jwks_uri": "https://client.example.org/my_public_keys.jwks",
              "example_extension_parameter": "example_value",
              "_token": "value"
            }
            """)!;

        var options = new JsonSerializerOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true
        };

        // Act and assert
        Assert.Equal(JsonSerializer.Serialize(message, options), message.ToString());
    }

    [Theory]
    [InlineData(Parameters.AccessToken)]
    [InlineData(Parameters.Assertion)]
    [InlineData(Parameters.ClientAssertion)]
    [InlineData(Parameters.ClientSecret)]
    [InlineData(Parameters.Code)]
    [InlineData(Parameters.IdToken)]
    [InlineData(Parameters.IdTokenHint)]
    [InlineData(Parameters.Password)]
    [InlineData(Parameters.RefreshToken)]
    [InlineData(Parameters.Token)]
    [InlineData("custom_token")]
    public void ToString_ExcludesSensitiveParameters(string parameter)
    {
        // Arrange
        var message = new OpenIddictMessage();
        message.AddParameter(parameter, "secret value");

        // Act and assert
        var element = JsonSerializer.Deserialize<JsonElement>(message.ToString());
        Assert.DoesNotContain("secret value", message.ToString());
        Assert.Equal("[redacted]", element.GetProperty(parameter).GetString());
    }

    [Fact]
    public void WriteTo_ThrowsAnExceptionForNullWriter()
    {
        // Arrange
        var message = new OpenIddictMessage();

        // Act and assert
        var exception = Assert.Throws<ArgumentNullException>(() => message.WriteTo(writer: null!));
        Assert.Equal("writer", exception.ParamName);
    }

    [Fact]
    public void WriteTo_WritesUtf8JsonRepresentation()
    {
        // Arrange
        var message = new OpenIddictMessage
        {
            ["redirect_uris"] = new[] { "https://abc.org/callback" },
            ["client_name"] = "My Example Client"
        };

        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream);

        // Act
        message.WriteTo(writer);
        writer.Flush();

        // Assert
        Assert.Equal(@"{""redirect_uris"":[""https://abc.org/callback""],""client_name"":""My Example Client""}",
            Encoding.UTF8.GetString(stream.ToArray()));
    }
}

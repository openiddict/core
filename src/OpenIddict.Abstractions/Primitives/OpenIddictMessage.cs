/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/openiddict/openiddict-core for more information concerning
 * the license and the contributors participating to this project.
 */

using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Primitives;

#if SUPPORTS_JSON_NODES
using System.Text.Json.Nodes;
#endif

namespace OpenIddict.Abstractions;

/// <summary>
/// Represents an abstract OpenIddict message.
/// </summary>
/// <remarks>
/// Security notice: developers instantiating this type are responsible for ensuring that the
/// imported parameters are safe and won't cause the resulting message to grow abnormally,
/// which may result in an excessive memory consumption and a potential denial of service.
/// </remarks>
[DebuggerDisplay("Parameters: {Parameters.Count}")]
[JsonConverter(typeof(OpenIddictConverter))]
public class OpenIddictMessage
{
    /// <summary>
    /// Initializes a new OpenIddict message.
    /// </summary>
    public OpenIddictMessage()
    {
    }

    /// <summary>
    /// Initializes a new OpenIddict message.
    /// </summary>
    /// <param name="parameters">The message parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictMessage(JsonElement parameters)
    {
        if (parameters.ValueKind is not JsonValueKind.Object)
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0189), nameof(parameters));
        }

        foreach (var parameter in parameters.EnumerateObject())
        {
            // Ignore parameters whose name is null or empty.
            if (string.IsNullOrEmpty(parameter.Name))
            {
                continue;
            }

            // While generally discouraged, JSON objects can contain multiple properties with
            // the same name. In this case, the last occurrence replaces the previous ones.
            if (HasParameter(parameter.Name))
            {
                RemoveParameter(parameter.Name);
            }

            AddParameter(parameter.Name, parameter.Value);
        }
    }

#if SUPPORTS_JSON_NODES
    /// <summary>
    /// Initializes a new OpenIddict message.
    /// </summary>
    /// <param name="parameters">The message parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictMessage(JsonObject parameters)
    {
        if (parameters is null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        foreach (var parameter in parameters)
        {
            // Ignore parameters whose name is null or empty.
            if (string.IsNullOrEmpty(parameter.Key))
            {
                continue;
            }

            // While generally discouraged, JSON objects can contain multiple properties with
            // the same name. In this case, the last occurrence replaces the previous ones.
            if (HasParameter(parameter.Key))
            {
                RemoveParameter(parameter.Key);
            }

            AddParameter(parameter.Key, parameter.Value);
        }
    }
#endif

    /// <summary>
    /// Initializes a new OpenIddict message.
    /// </summary>
    /// <param name="parameters">The message parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictMessage(IEnumerable<KeyValuePair<string, OpenIddictParameter>> parameters)
    {
        if (parameters is null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        foreach (var parameter in parameters)
        {
            // Ignore parameters whose name is null or empty.
            if (string.IsNullOrEmpty(parameter.Key))
            {
                continue;
            }

            AddParameter(parameter.Key, parameter.Value);
        }
    }

    /// <summary>
    /// Initializes a new OpenIddict message.
    /// </summary>
    /// <param name="parameters">The message parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictMessage(IEnumerable<KeyValuePair<string, string?>> parameters)
    {
        if (parameters is null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        foreach (var parameter in parameters.GroupBy(parameter => parameter.Key))
        {
            // Ignore parameters whose name is null or empty.
            if (string.IsNullOrEmpty(parameter.Key))
            {
                continue;
            }

            var values = parameter.Select(parameter => parameter.Value).ToArray();

            // Note: the core OAuth 2.0 specification requires that request parameters
            // not be present more than once but derived specifications like the
            // token exchange specification deliberately allow specifying multiple
            // parameters with the same name to represent a multi-valued parameter.
            AddParameter(parameter.Key, values.Length switch
            {
                0 => default,
                1 => values[0],
                _ => values
            });
        }
    }

    /// <summary>
    /// Initializes a new OpenIddict message.
    /// </summary>
    /// <param name="parameters">The message parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictMessage(IEnumerable<KeyValuePair<string, string?[]?>> parameters)
    {
        if (parameters is null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        foreach (var parameter in parameters)
        {
            // Ignore parameters whose name is null or empty.
            if (string.IsNullOrEmpty(parameter.Key))
            {
                continue;
            }

            // Note: the core OAuth 2.0 specification requires that request parameters
            // not be present more than once but derived specifications like the
            // token exchange specification deliberately allow specifying multiple
            // parameters with the same name to represent a multi-valued parameter.
            AddParameter(parameter.Key, parameter.Value?.Length switch
            {
                null or 0 => default,
                1         => parameter.Value[0],
                _         => parameter.Value
            });
        }
    }

    /// <summary>
    /// Initializes a new OpenIddict message.
    /// </summary>
    /// <param name="parameters">The message parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictMessage(IEnumerable<KeyValuePair<string, StringValues>> parameters)
    {
        if (parameters is null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        foreach (var parameter in parameters)
        {
            // Ignore parameters whose name is null or empty.
            if (string.IsNullOrEmpty(parameter.Key))
            {
                continue;
            }

            // Note: the core OAuth 2.0 specification requires that request parameters
            // not be present more than once but derived specifications like the
            // token exchange specification deliberately allow specifying multiple
            // parameters with the same name to represent a multi-valued parameter.
            AddParameter(parameter.Key, parameter.Value.Count switch
            {
                0 => default,
                1 => parameter.Value[0],
                _ => parameter.Value.ToArray()
            });
        }
    }

    /// <summary>
    /// Initializes a new OpenIddict message.
    /// </summary>
    /// <param name="parameters">The message parameters.</param>
    /// <remarks>Parameters with a null or empty key are always ignored.</remarks>
    public OpenIddictMessage(NameValueCollection parameters)
    {
        if (parameters is null)
        {
            throw new ArgumentNullException(nameof(parameters));
        }

        for (var index = 0; index < parameters.AllKeys.Length; index++)
        {
            // Ignore parameters whose name is null or empty.
            var name = parameters.AllKeys[index];
            if (string.IsNullOrEmpty(name))
            {
                continue;
            }

            var values = parameters.GetValues(name);

            // Note: the core OAuth 2.0 specification requires that request parameters
            // not be present more than once but derived specifications like the
            // token exchange specification deliberately allow specifying multiple
            // parameters with the same name to represent a multi-valued parameter.
            AddParameter(name, values?.Length switch
            {
                null or 0 => default,
                1         => values[0],
                _         => values
            });
        }
    }

    /// <summary>
    /// Gets or sets a parameter.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    /// <returns>The parameter value.</returns>
    public OpenIddictParameter? this[string name]
    {
        get => GetParameter(name);
        set => SetParameter(name, value);
    }

    /// <summary>
    /// Gets the number of parameters contained in the current message.
    /// </summary>
    public int Count => Parameters.Count;

    /// <summary>
    /// Gets the dictionary containing the parameters.
    /// </summary>
    protected Dictionary<string, OpenIddictParameter> Parameters { get; }
        = new Dictionary<string, OpenIddictParameter>(StringComparer.Ordinal);

    /// <summary>
    /// Adds a parameter. Note: an exception is thrown if a parameter with the same name was already added.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    /// <param name="value">The parameter value.</param>
    /// <returns>The current instance, which allows chaining calls.</returns>
    public OpenIddictMessage AddParameter(string name, OpenIddictParameter value)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0190), nameof(name));
        }

        if (Parameters.ContainsKey(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0191), nameof(name));
        }

        Parameters.Add(name, value);

        return this;
    }

    /// <summary>
    /// Gets the value corresponding to a given parameter.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    /// <returns>The parameter value, or <see langword="null"/> if it cannot be found.</returns>
    public OpenIddictParameter? GetParameter(string name)
        => TryGetParameter(name, out var parameter) ? parameter : (OpenIddictParameter?) null;

    /// <summary>
    /// Gets all the parameters associated with this instance.
    /// </summary>
    /// <returns>The parameters associated with this instance.</returns>
    public IReadOnlyDictionary<string, OpenIddictParameter> GetParameters()
        => new ReadOnlyDictionary<string, OpenIddictParameter>(Parameters);

    /// <summary>
    /// Determines whether the current message contains the specified parameter.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    /// <returns><see langword="true"/> if the parameter is present, <see langword="false"/> otherwise.</returns>
    public bool HasParameter(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0190), nameof(name));
        }

        return Parameters.ContainsKey(name);
    }

    /// <summary>
    /// Removes a parameter.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    /// <returns>The current instance, which allows chaining calls.</returns>
    public OpenIddictMessage RemoveParameter(string name)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0190), nameof(name));
        }

        Parameters.Remove(name);

        return this;
    }

    /// <summary>
    /// Adds, replaces or removes a parameter.
    /// Note: this method automatically removes empty parameters.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    /// <param name="value">The parameter value.</param>
    /// <returns>The current instance, which allows chaining calls.</returns>
    public OpenIddictMessage SetParameter(string name, OpenIddictParameter? value)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0190), nameof(name));
        }

        // If the parameter value is null or empty, remove the corresponding entry from the collection.
        if (value is null || OpenIddictParameter.IsNullOrEmpty(value.GetValueOrDefault()))
        {
            Parameters.Remove(name);
        }

        else
        {
            Parameters[name] = value.GetValueOrDefault();
        }

        return this;
    }

    /// <summary>
    /// Tries to get the value corresponding to a given parameter.
    /// </summary>
    /// <param name="name">The parameter name.</param>
    /// <param name="value">The parameter value.</param>
    /// <returns><see langword="true"/> if the parameter could be found, <see langword="false"/> otherwise.</returns>
    public bool TryGetParameter(string name, out OpenIddictParameter value)
    {
        if (string.IsNullOrEmpty(name))
        {
            throw new ArgumentException(SR.GetResourceString(SR.ID0190), nameof(name));
        }

        return Parameters.TryGetValue(name, out value);
    }

    /// <summary>
    /// Returns a <see cref="string"/> representation of the current instance that can be used in logs.
    /// Note: sensitive parameters like client secrets are automatically removed for security reasons.
    /// </summary>
    /// <returns>The indented JSON representation corresponding to this message.</returns>
    public override string ToString()
    {
        using var stream = new MemoryStream();
        using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            Indented = true
        });

        writer.WriteStartObject();

        foreach (var parameter in Parameters)
        {
            writer.WritePropertyName(parameter.Key);

            // Remove sensitive parameters from the generated payload.
            switch (parameter.Key)
            {
                case OpenIddictConstants.Parameters.AccessToken:
                case OpenIddictConstants.Parameters.Assertion:
                case OpenIddictConstants.Parameters.ClientAssertion:
                case OpenIddictConstants.Parameters.ClientSecret:
                case OpenIddictConstants.Parameters.Code:
                case OpenIddictConstants.Parameters.IdToken:
                case OpenIddictConstants.Parameters.IdTokenHint:
                case OpenIddictConstants.Parameters.Password:
                case OpenIddictConstants.Parameters.RefreshToken:
                case OpenIddictConstants.Parameters.Token:
                case { Length: > 6 } name when name.EndsWith("_token", StringComparison.OrdinalIgnoreCase):
                    writer.WriteStringValue("[redacted]");
                    continue;
            }

            parameter.Value.WriteTo(writer);
        }

        writer.WriteEndObject();
        writer.Flush();

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    /// <summary>
    /// Writes the message to the specified JSON writer.
    /// </summary>
    /// <param name="writer">The UTF-8 JSON writer.</param>
    public void WriteTo(Utf8JsonWriter writer)
    {
        if (writer is null)
        {
            throw new ArgumentNullException(nameof(writer));
        }

        writer.WriteStartObject();

        foreach (var parameter in Parameters)
        {
            writer.WritePropertyName(parameter.Key);
            parameter.Value.WriteTo(writer);
        }

        writer.WriteEndObject();
    }
}
